"""Technology fingerprinting, deliberately "lite" in v1 (PRD 6.2).

A small, readable, bundled signature set beats a large opaque database for a
learning tool: you can see exactly why a technology was suggested. Each match
records the evidence that produced it, and confidence reflects how specific
that evidence is.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

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

#: name -> (header signatures, body signatures, cookie signatures, confidence)
SIGNATURES: dict[str, dict[str, object]] = {
    "nginx": {"headers": {"server": r"nginx"}, "confidence": Confidence.HIGH},
    "Apache httpd": {"headers": {"server": r"apache"}, "confidence": Confidence.HIGH},
    "Microsoft IIS": {"headers": {"server": r"microsoft-iis"}, "confidence": Confidence.HIGH},
    "LiteSpeed": {"headers": {"server": r"litespeed"}, "confidence": Confidence.HIGH},
    "Caddy": {"headers": {"server": r"caddy"}, "confidence": Confidence.HIGH},
    "Cloudflare": {
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
        "confidence": Confidence.HIGH,
    },
    "Varnish": {"headers": {"via": r"varnish", "x-varnish": r".+"}, "confidence": Confidence.MEDIUM},
    "PHP": {
        "headers": {"x-powered-by": r"php"},
        "cookies": [r"^PHPSESSID="],
        "confidence": Confidence.HIGH,
    },
    "ASP.NET": {
        "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"},
        "cookies": [r"^ASP\.NET_SessionId="],
        "confidence": Confidence.HIGH,
    },
    "Express": {"headers": {"x-powered-by": r"express"}, "confidence": Confidence.HIGH},
    "WordPress": {
        "body": [r"/wp-content/", r"/wp-includes/"],
        "meta_generator": r"wordpress",
        "confidence": Confidence.HIGH,
    },
    "Drupal": {
        "headers": {"x-generator": r"drupal", "x-drupal-cache": r".+"},
        "body": [r"/sites/default/files/"],
        "meta_generator": r"drupal",
        "confidence": Confidence.HIGH,
    },
    "Joomla": {"body": [r"/media/jui/"], "meta_generator": r"joomla", "confidence": Confidence.HIGH},
    "Django": {
        "cookies": [r"^csrftoken=", r"^sessionid="],
        "body": [r"csrfmiddlewaretoken"],
        "confidence": Confidence.MEDIUM,
    },
    "Ruby on Rails": {
        "headers": {"x-powered-by": r"phusion|passenger"},
        "body": [r'name="csrf-param"'],
        "confidence": Confidence.MEDIUM,
    },
    "Laravel": {"cookies": [r"^laravel_session="], "confidence": Confidence.HIGH},
    "Next.js": {
        "headers": {"x-powered-by": r"next\.js"},
        "body": [r"/_next/static/", r'id="__NEXT_DATA__"'],
        "confidence": Confidence.HIGH,
    },
    "React": {"body": [r"data-reactroot", r"__REACT_DEVTOOLS"], "confidence": Confidence.LOW},
    "Vue.js": {"body": [r"data-v-[0-9a-f]{8}", r"__VUE__"], "confidence": Confidence.LOW},
    "jQuery": {"body": [r"jquery[.-][0-9]+\.[0-9]+"], "confidence": Confidence.MEDIUM},
    "Shopify": {
        "headers": {"x-shopid": r".+", "powered-by": r"shopify"},
        "body": [r"cdn\.shopify\.com"],
        "confidence": Confidence.HIGH,
    },
    "Wix": {"headers": {"x-wix-request-id": r".+"}, "confidence": Confidence.HIGH},
}

VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){1,3})")


class _HomepageParser(HTMLParser):
    """Just enough HTML to read the title and the generator meta tag."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.generator = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            values = {key.lower(): (value or "") for key, value in attrs}
            if values.get("name", "").lower() == "generator":
                self.generator = values.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 300:
            self.title += data.strip()


class TechFingerprintModule(ModuleBase):
    id = "fingerprint"
    name = "Technology fingerprint (lite)"
    version = "1.0.0"
    category = "web"
    mode = ContactMode.DIRECT_READ
    teaching_key = "fingerprint"
    supported_target_types = ("domain", "host", "url")
    config_schema = {"scheme": ("auto", "'auto' tries HTTPS then HTTP; or force 'https'/'http'.")}
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
            scheme = str(config["scheme"])
            urls = (
                [f"https://{host}/", f"http://{host}/"]
                if scheme == "auto"
                else [f"{scheme}://{host}/"]
            )

        exchange = None
        requests_made = 0
        for index, url in enumerate(urls):
            context.cancel.raise_if_cancelled()
            context.emit(f"Fetching the homepage of {url} to fingerprint it")
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

        assert exchange is not None
        result.warnings.extend(exchange.warnings)

        parser = _HomepageParser()
        try:
            parser.feed(exchange.text)
        except Exception as exc:  # malformed HTML must never abort a run
            result.warnings.append(f"The homepage HTML could not be fully parsed: {exc}")

        if parser.title:
            result.observations.append(
                Observation(
                    type="web.title",
                    normalized_value=parser.title[:200],
                    source_provider=f"HTTP response from {exchange.final_url}",
                    dedup_key=f"web.title:{host}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence="<title> element of the homepage.",
                    confidence=Confidence.HIGH,
                )
            )
        if parser.generator:
            result.observations.append(
                Observation(
                    type="web.generator",
                    normalized_value=parser.generator[:200],
                    source_provider=f"HTTP response from {exchange.final_url}",
                    dedup_key=f"web.generator:{host}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence="<meta name='generator'> element.",
                    confidence=Confidence.HIGH,
                )
            )

        matches = self._match(exchange, parser.generator)
        for name, (evidence, confidence, version) in sorted(matches.items()):
            value = f"{name} {version}".strip()
            result.observations.append(
                Observation(
                    type="web.technology",
                    normalized_value=value,
                    source_provider=f"bundled signature set v{self.version}",
                    dedup_key=f"web.technology:{host}:{name}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence=evidence,
                    confidence=confidence,
                )
            )

        result.findings.extend(self._findings(host, matches))
        result.merge_metrics(
            requests=requests_made,
            technologies=len(matches),
            signatures=len(SIGNATURES),
        )
        if not matches:
            result.warnings.append(
                "No bundled signature matched. The v1 signature set is intentionally small; "
                "absence of a match says nothing about what the site runs."
            )
        return result

    def _match(self, exchange, generator: str) -> dict[str, tuple[str, Confidence, str]]:
        body = exchange.text[:200_000]
        matches: dict[str, tuple[str, Confidence, str]] = {}

        for name, signature in SIGNATURES.items():
            evidence: list[str] = []
            version = ""
            for header, pattern in (signature.get("headers") or {}).items():  # type: ignore[union-attr]
                value = exchange.header(header)
                if value and re.search(str(pattern), value, re.I):
                    evidence.append(f"header '{header}: {value}'")
                    found = VERSION_RE.search(value)
                    if found and not version:
                        version = found.group(1)
            for pattern in signature.get("cookies") or []:  # type: ignore[union-attr]
                for cookie in exchange.cookies:
                    if re.search(str(pattern), cookie, re.I):
                        evidence.append(f"cookie matching {pattern}")
                        break
            for pattern in signature.get("body") or []:  # type: ignore[union-attr]
                if re.search(str(pattern), body, re.I):
                    evidence.append(f"homepage content matching {pattern}")
            generator_pattern = signature.get("meta_generator")
            if generator_pattern and generator and re.search(str(generator_pattern), generator, re.I):
                evidence.append(f"meta generator '{generator}'")
                found = VERSION_RE.search(generator)
                if found and not version:
                    version = found.group(1)

            if evidence:
                confidence = signature.get("confidence", Confidence.LOW)
                if len(evidence) == 1 and confidence is Confidence.HIGH:
                    confidence = Confidence.HIGH
                matches[name] = ("; ".join(evidence), confidence, version)  # type: ignore[arg-type]
        return matches

    def _findings(
        self, host: str, matches: dict[str, tuple[str, Confidence, str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not matches:
            return findings

        listing = ", ".join(
            f"{name} {version}".strip() for name, (_e, _c, version) in sorted(matches.items())
        )
        findings.append(
            Finding(
                title=f"Technology stack suggested by public signals: {listing}",
                category="fingerprint",
                interpretation_text=(
                    f"Headers and homepage content from {host} match {len(matches)} bundled "
                    "signature(s). Knowing the stack shapes what is worth testing next - a "
                    "WordPress site invites plugin enumeration, an ASP.NET site invites "
                    "different checks. None of this is a weakness by itself."
                ),
                limitations=(
                    "Signatures can be spoofed, a CDN can mask the origin, and this v1 set is "
                    "small. Treat every entry as a hypothesis to confirm."
                ),
                confidence=Confidence.MEDIUM,
                severity_hint=SeverityHint.INFO,
                supporting_dedup_keys=[f"web.technology:{host}:{name}" for name in matches],
                asset_value=host,
            )
        )

        versioned = {
            name: version for name, (_e, _c, version) in matches.items() if version
        }
        if versioned:
            findings.append(
                Finding(
                    title="Exact software versions are publicly visible",
                    category="information-disclosure",
                    interpretation_text=(
                        "The response advertises specific versions ("
                        + ", ".join(f"{name} {version}" for name, version in versioned.items())
                        + "). That lets anyone match the host against published advisories "
                        "without probing it. This is a hint to check patch level and to consider "
                        "suppressing version banners - it is not evidence of an unpatched flaw, "
                        "because this tool does not consult any vulnerability database."
                    ),
                    limitations=(
                        "Banners are often stale or deliberately misleading, and backported "
                        "security fixes keep old version numbers. Never report a CVE from a "
                        "banner alone."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        f"web.technology:{host}:{name}" for name in versioned
                    ],
                    asset_value=host,
                )
            )
        return findings
