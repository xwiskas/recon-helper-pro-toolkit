"""HTTP response header analysis (direct-read).

One request, then a careful reading of what came back. Security headers are
defence in depth: their absence is a *hint* that deserves context, never a
confirmed vulnerability, and this module is written to say exactly that.
"""

from __future__ import annotations

from ...core.errors import NetworkError
from ...core.models import (
    AssetKind,
    Confidence,
    ContactMode,
    Finding,
    Observation,
    PluginResult,
    RunStatus,
    SeverityHint,
)
from ...core.module_base import ModuleBase, ModuleContext
from ...core.scope import validate_target

#: Headers we always record, whether present or not.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
)

#: Headers that commonly leak software and version information.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")


class HttpHeadersModule(ModuleBase):
    id = "headers"
    name = "HTTP header analysis"
    version = "1.0.0"
    category = "web"
    mode = ContactMode.DIRECT_READ
    teaching_key = "headers"
    supported_target_types = ("domain", "host", "url")
    config_schema = {
        "scheme": ("auto", "'auto' tries HTTPS then HTTP; or force 'https'/'http'."),
        "path": ("/", "Path to request."),
    }
    request_budget = 2
    scope_requirement = "warn"

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        config = self.resolved_config(context.params)
        http = context.require_http()

        target = context.target
        if "://" in target:
            urls = [target]
            host = validate_target(target.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0])
        else:
            host = validate_target(target)
            path = str(config["path"]) or "/"
            scheme = str(config["scheme"])
            if scheme == "auto":
                urls = [f"https://{host}{path}", f"http://{host}{path}"]
            else:
                urls = [f"{scheme}://{host}{path}"]

        exchange = None
        requests_made = 0
        for index, url in enumerate(urls):
            context.cancel.raise_if_cancelled()
            context.emit(f"Requesting headers from {url}")
            try:
                exchange = http.get(url, allow_override=context.allow_override)
                requests_made += exchange.requests
                break
            except NetworkError as exc:
                requests_made += 1
                if index == len(urls) - 1:
                    result.status = RunStatus.FAILED
                    result.errors.append(str(exc))
                    result.merge_metrics(requests=requests_made)
                    return result
                result.warnings.append(f"{url} did not respond ({exc}); trying HTTP instead.")

        assert exchange is not None
        result.warnings.extend(exchange.warnings)
        is_https = exchange.final_url.startswith("https://")

        def observe(obs_type: str, value: str, evidence: str, confidence: Confidence) -> None:
            result.observations.append(
                Observation(
                    type=obs_type,
                    normalized_value=value,
                    source_provider=f"HTTP response from {exchange.final_url}",
                    dedup_key=f"{obs_type}:{host}:{value}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence=evidence,
                    confidence=confidence,
                )
            )

        observe(
            "http.status",
            str(exchange.status),
            f"Status line of the response from {exchange.final_url}.",
            Confidence.HIGH,
        )
        observe(
            "http.resolved_address",
            exchange.address,
            f"{host} was resolved once and the request was pinned to this address.",
            Confidence.HIGH,
        )
        if len(exchange.hops) > 1:
            chain = " -> ".join(f"{hop.url} [{hop.status}]" for hop in exchange.hops)
            observe("http.redirect_chain", chain, "Every hop was scope-checked.", Confidence.HIGH)

        present: dict[str, str] = {}
        for name in SECURITY_HEADERS + DISCLOSURE_HEADERS:
            value = exchange.header(name)
            if value:
                present[name] = value
                observe(f"http.header.{name}", value, f"Response header '{name}'.", Confidence.HIGH)

        cookies = exchange.cookies
        for cookie in cookies:
            observe(
                "http.set_cookie_flags",
                _cookie_summary(cookie),
                "Cookie attributes only; the value itself is redacted before storage.",
                Confidence.HIGH,
            )

        result.findings.extend(self._findings(host, present, cookies, is_https, exchange.status))
        result.merge_metrics(
            requests=requests_made,
            headers_present=len(present),
            final_url=exchange.final_url,
        )
        return result

    def _findings(
        self,
        host: str,
        present: dict[str, str],
        cookies: list[str],
        is_https: bool,
        status: int,
    ) -> list[Finding]:
        findings: list[Finding] = []

        def missing(name: str) -> bool:
            return name not in present

        if is_https and missing("strict-transport-security"):
            findings.append(
                Finding(
                    title="No Strict-Transport-Security header",
                    category="headers",
                    interpretation_text=(
                        f"{host} answered over HTTPS but did not send an HSTS header. HSTS tells "
                        "browsers to refuse plain HTTP for this host in future, which closes the "
                        "window where a first request over HTTP could be intercepted. Its absence "
                        "is a hardening gap, not an exploitable flaw on its own - an attacker "
                        "still needs a position on the network path."
                    ),
                    limitations=(
                        "Only this host and path were checked. A site behind a CDN may set HSTS "
                        "on other routes, and HSTS is meaningless on hosts that are HTTP-only "
                        "by design."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.LOW,
                    supporting_dedup_keys=[f"http.status:{host}:{status}"],
                    asset_value=host,
                )
            )

        if missing("content-security-policy"):
            findings.append(
                Finding(
                    title="No Content-Security-Policy header",
                    category="headers",
                    interpretation_text=(
                        f"No CSP header was returned by {host}. CSP restricts where scripts and "
                        "other resources may load from, which limits the damage of a cross-site "
                        "scripting bug. Its absence does not mean the site has XSS - it means "
                        "that if one exists, nothing constrains it."
                    ),
                    limitations=(
                        "CSP can also be delivered in a meta tag, which this header check does "
                        "not see. Severity depends entirely on what the application does."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"http.status:{host}:{status}"],
                    asset_value=host,
                )
            )

        csp = present.get("content-security-policy", "")
        if missing("x-frame-options") and "frame-ancestors" not in csp.lower():
            findings.append(
                Finding(
                    title="No clickjacking protection header",
                    category="headers",
                    interpretation_text=(
                        f"{host} sent neither X-Frame-Options nor a CSP 'frame-ancestors' "
                        "directive, so the page may be embeddable in a frame on another site. "
                        "That matters for pages with state-changing controls, and not at all for "
                        "a static marketing page."
                    ),
                    limitations=(
                        "Whether framing is exploitable depends on what the page lets a user do. "
                        "Confirm by actually attempting to frame it."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"http.status:{host}:{status}"],
                    asset_value=host,
                )
            )

        origin = present.get("access-control-allow-origin", "")
        credentials = present.get("access-control-allow-credentials", "").lower()
        if origin == "*" and credentials == "true":
            findings.append(
                Finding(
                    title="CORS allows any origin together with credentials",
                    category="headers",
                    interpretation_text=(
                        f"{host} returned 'Access-Control-Allow-Origin: *' alongside "
                        "'Access-Control-Allow-Credentials: true'. Browsers reject that exact "
                        "combination, so it usually signals a misconfigured CORS layer rather "
                        "than a working data leak - but a reflected-origin variant of the same "
                        "misconfiguration would be exploitable, so it is worth testing properly."
                    ),
                    limitations=(
                        "Only the default response was inspected. Send an Origin header and see "
                        "whether it is reflected before drawing a conclusion."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.MEDIUM,
                    supporting_dedup_keys=[
                        f"http.header.access-control-allow-origin:{host}:{origin}"
                    ],
                    asset_value=host,
                )
            )
        elif origin == "*":
            findings.append(
                Finding(
                    title="CORS allows any origin",
                    category="headers",
                    interpretation_text=(
                        f"{host} returned 'Access-Control-Allow-Origin: *'. For genuinely public "
                        "data this is correct and intentional. It only becomes a problem when the "
                        "same endpoint also returns something a user is authorized to see."
                    ),
                    limitations="Whether the endpoint returns private data was not tested.",
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        f"http.header.access-control-allow-origin:{host}:{origin}"
                    ],
                    asset_value=host,
                )
            )

        disclosed = {
            name: value for name, value in present.items() if name in DISCLOSURE_HEADERS
        }
        versioned = {
            name: value
            for name, value in disclosed.items()
            if any(character.isdigit() for character in value)
        }
        if versioned:
            listing = "; ".join(f"{name}: {value}" for name, value in versioned.items())
            findings.append(
                Finding(
                    title="Software version disclosed in response headers",
                    category="information-disclosure",
                    interpretation_text=(
                        f"{host} advertises specific software versions ({listing}). This does not "
                        "create a vulnerability, it removes an attacker's guesswork: they can "
                        "look up known issues for that exact build instead of probing. Suppress "
                        "or generalise these headers as hygiene, and keep the software patched "
                        "because that is what actually matters."
                    ),
                    limitations=(
                        "The banner may be inaccurate or deliberately faked, and this module does "
                        "not check any vulnerability database. Do not report a CVE from a banner."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        f"http.header.{name}:{host}:{value}" for name, value in versioned.items()
                    ],
                    asset_value=host,
                )
            )

        for cookie in cookies:
            summary = _cookie_summary(cookie)
            candidates = ("Secure", "HttpOnly", "SameSite") if is_https else ("HttpOnly", "SameSite")
            missing_flags = [
                flag for flag in candidates if flag.lower() not in cookie.lower()
            ]
            if missing_flags:
                findings.append(
                    Finding(
                        title=f"Cookie set without {', '.join(missing_flags)}",
                        category="cookies",
                        interpretation_text=(
                            f"{host} set a cookie ({summary}) missing "
                            f"{', '.join(missing_flags)}. 'Secure' keeps it off plain HTTP, "
                            "'HttpOnly' keeps it away from JavaScript, and 'SameSite' limits "
                            "cross-site sending. How much this matters depends entirely on "
                            "whether the cookie carries a session; a cookie holding a UI "
                            "preference needs none of them."
                        ),
                        limitations=(
                            "The cookie's purpose is unknown - its value is redacted and never "
                            "stored. Check whether it is a session cookie before reporting."
                        ),
                        confidence=Confidence.MEDIUM,
                        severity_hint=SeverityHint.LOW,
                        supporting_dedup_keys=[f"http.set_cookie_flags:{host}:{summary}"],
                        asset_value=host,
                    )
                )
        return findings


def _cookie_summary(set_cookie: str) -> str:
    """Cookie name and flags only - the value never leaves the response."""
    name = set_cookie.split("=", 1)[0].strip()
    attributes = [part.strip() for part in set_cookie.split(";")[1:]]
    flags = [attribute for attribute in attributes if attribute]
    return f"{name}; " + "; ".join(flags) if flags else name
