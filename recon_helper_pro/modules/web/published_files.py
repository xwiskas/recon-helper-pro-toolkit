"""Standard published files: robots.txt, sitemap.xml, security.txt, .well-known.

This is the only ``enumerative`` module in v1, and it stays deliberately narrow:
a fixed list of files that sites publish *on purpose*. It is not a directory
brute-forcer, it does not follow links, and it skips paths robots.txt disallows
unless you explicitly opt in (PRD 6.2, 7.5).
"""

from __future__ import annotations

import re

from ...core.errors import BudgetExceeded, NetworkError
from ...core.models import (
    AssetKind,
    Confidence,
    ContactMode,
    DiscoveredAsset,
    Finding,
    Observation,
    PluginResult,
    RunStatus,
    SeverityHint,
)
from ...core.module_base import ModuleBase, ModuleContext
from ...core.scope import validate_target

#: Files that exist by convention. robots.txt is fetched first, always.
STANDARD_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/ads.txt",
    "/crossdomain.xml",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
)

SENSITIVE_HINTS = (
    "admin",
    "backup",
    "private",
    "internal",
    "staging",
    "test",
    "dev",
    "config",
    "db",
    "sql",
    "old",
    ".git",
    "phpmyadmin",
    "wp-admin",
)

DIRECTORY_LISTING_RE = re.compile(r"<title>\s*Index of /|Directory listing for /", re.I)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def parse_robots(text: str, user_agent: str) -> tuple[list[str], list[str]]:
    """Return ``(disallowed, sitemaps)`` for *user_agent* falling back to ``*``.

    A small, honest parser: robots.txt is a courtesy signal, not a security
    boundary, and we only need it well enough to be polite.
    """
    groups: dict[str, list[str]] = {}
    sitemaps: list[str] = []
    current: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            current = groups.setdefault(value.lower(), [])
        elif field == "disallow" and value:
            current.append(value)
        elif field == "sitemap" and value:
            sitemaps.append(value)
    agent = user_agent.split("/", 1)[0].lower()
    rules = groups.get(agent) or groups.get("*") or []
    return rules, sitemaps


def _is_disallowed(path: str, rules: list[str]) -> bool:
    for rule in rules:
        if rule == "/" or path.startswith(rule):
            return True
    return False


class PublishedFilesModule(ModuleBase):
    id = "published-files"
    name = "Standard published-file discovery"
    version = "1.0.0"
    category = "web"
    mode = ContactMode.ENUMERATIVE
    teaching_key = "published_files"
    supported_target_types = ("domain", "host", "url")
    config_schema = {
        "scheme": ("https", "Scheme to use for the requests."),
        "check_disallowed": (
            False,
            "Also request paths robots.txt disallows. Off by default; robots is a courtesy "
            "signal, and ignoring it is a decision you should make deliberately.",
        ),
        "paths": (list(STANDARD_PATHS), "The fixed list of well-known files to check."),
    }
    request_budget = len(STANDARD_PATHS)
    scope_requirement = "warn"

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        config = self.resolved_config(context.params)
        http = context.require_http()
        host = validate_target(context.target)
        scheme = str(config["scheme"])
        base = f"{scheme}://{host}"
        paths = list(config["paths"]) or list(STANDARD_PATHS)

        requests_made = 0
        robots_text = ""
        rules: list[str] = []
        sitemaps: list[str] = []
        respect_robots = bool(context.settings.get("robots.respect", True))

        # robots.txt first - we need it to know what to skip.
        try:
            context.emit(f"Fetching {base}/robots.txt")
            robots = http.get(f"{base}/robots.txt", allow_override=context.allow_override)
            requests_made += robots.requests
            result.warnings.extend(robots.warnings)
            if robots.status == 200:
                robots_text = robots.text
                rules, sitemaps = parse_robots(robots_text, context.policy.user_agent)
                reference = context.artifact("robots-txt", robots_text)
                result.observations.append(
                    Observation(
                        type="web.robots",
                        normalized_value=f"{len(rules)} Disallow rule(s), {len(sitemaps)} sitemap(s)",
                        source_provider=f"{base}/robots.txt",
                        dedup_key=f"web.robots:{host}",
                        asset_value=host,
                        asset_kind=AssetKind.HOST,
                        raw_value=robots_text[:4000],
                        artifact_ref=reference,
                        evidence="robots.txt as published by the site.",
                        confidence=Confidence.HIGH,
                    )
                )
                for rule in rules:
                    result.observations.append(
                        Observation(
                            type="web.robots_disallow",
                            normalized_value=rule,
                            source_provider=f"{base}/robots.txt",
                            dedup_key=f"web.robots_disallow:{host}:{rule}",
                            asset_value=host,
                            asset_kind=AssetKind.HOST,
                            evidence="Disallow entry in robots.txt.",
                            confidence=Confidence.HIGH,
                        )
                    )
        except (NetworkError, BudgetExceeded) as exc:
            result.status = RunStatus.PARTIAL
            result.errors.append(f"robots.txt could not be read: {exc}")

        skipped: list[str] = []
        for path in paths:
            if path == "/robots.txt":
                continue
            context.cancel.raise_if_cancelled()
            if respect_robots and not config["check_disallowed"] and _is_disallowed(path, rules):
                skipped.append(path)
                result.warnings.append(
                    f"Skipped {path}: robots.txt disallows it. Re-run with "
                    "'--param check_disallowed=true' if you have authorization and a reason."
                )
                continue
            url = f"{base}{path}"
            try:
                context.emit(f"Checking {url}")
                exchange = http.get(url, allow_override=context.allow_override)
                requests_made += exchange.requests
            except BudgetExceeded as exc:
                result.status = RunStatus.PARTIAL
                result.warnings.append(str(exc))
                break
            except NetworkError as exc:
                result.warnings.append(f"{url}: {exc}")
                continue

            result.warnings.extend(exchange.warnings)
            content_type = exchange.header("content-type", "unknown")
            result.observations.append(
                Observation(
                    type="web.published_file",
                    normalized_value=f"{path} -> {exchange.status}",
                    source_provider=url,
                    dedup_key=f"web.published_file:{host}:{path}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence=f"HTTP {exchange.status}, content-type {content_type}, "
                    f"{len(exchange.body)} bytes.",
                    confidence=Confidence.HIGH,
                )
            )

            if exchange.status == 200:
                result.findings.extend(self._file_findings(host, path, exchange))
                if path.endswith("sitemap.xml"):
                    result.discovered_assets.extend(self._sitemap_assets(exchange.text))
                if DIRECTORY_LISTING_RE.search(exchange.text[:8000]):
                    result.findings.append(_directory_listing_finding(host, url))

        for sitemap in sitemaps[:5]:
            result.observations.append(
                Observation(
                    type="web.sitemap_reference",
                    normalized_value=sitemap,
                    source_provider=f"{base}/robots.txt",
                    dedup_key=f"web.sitemap_reference:{host}:{sitemap}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence="Sitemap line in robots.txt. Not fetched by this module.",
                    confidence=Confidence.HIGH,
                )
            )

        result.findings.extend(self._robots_findings(host, rules, robots_text))
        result.merge_metrics(
            requests=requests_made,
            paths_checked=len(paths) - len(skipped),
            paths_skipped=len(skipped),
        )
        return result

    # -- interpretation ---------------------------------------------------
    def _file_findings(self, host: str, path: str, exchange) -> list[Finding]:
        findings: list[Finding] = []
        if path.endswith("security.txt"):
            contact = ""
            for line in exchange.text.splitlines():
                if line.lower().startswith("contact:"):
                    contact = line.split(":", 1)[1].strip()
                    break
            findings.append(
                Finding(
                    title="security.txt is published",
                    category="disclosure-process",
                    interpretation_text=(
                        f"{host} publishes a security.txt"
                        + (f" naming {contact} as the contact" if contact else "")
                        + ". This is good practice and it is the address you should use if you "
                        "find something. Read it before reporting anything."
                    ),
                    limitations="The file may be stale; verify the contact still responds.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"web.published_file:{host}:{path}"],
                    asset_value=host,
                )
            )
        return findings

    def _sitemap_assets(self, text: str) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        for url in SITEMAP_LOC_RE.findall(text)[:50]:
            assets.append(
                DiscoveredAsset(
                    AssetKind.URL, url.strip(), "Listed in sitemap.xml. Recorded, not requested."
                )
            )
        return assets

    def _robots_findings(self, host: str, rules: list[str], robots_text: str) -> list[Finding]:
        findings: list[Finding] = []
        interesting = [
            rule
            for rule in rules
            if any(hint in rule.lower() for hint in SENSITIVE_HINTS)
        ]
        if interesting:
            findings.append(
                Finding(
                    title="robots.txt names paths that sound sensitive",
                    category="information-disclosure",
                    interpretation_text=(
                        f"robots.txt on {host} disallows {', '.join(interesting[:8])}. Listing a "
                        "path in robots.txt hides it from search engines and simultaneously "
                        "advertises it to anyone who reads the file - which is everyone. This is "
                        "a pointer to areas worth understanding, not evidence that any of them "
                        "is exposed. None of these paths was requested by this run."
                    ),
                    limitations=(
                        "A disallowed path may not exist, may require authentication, or may be "
                        "entirely mundane. The name alone means nothing."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        f"web.robots_disallow:{host}:{rule}" for rule in interesting[:8]
                    ],
                    asset_value=host,
                )
            )
        elif not robots_text:
            findings.append(
                Finding(
                    title="No robots.txt published",
                    category="information-disclosure",
                    interpretation_text=(
                        f"{host} does not publish a robots.txt. That is neither good nor bad for "
                        "security - it simply means crawlers are given no guidance."
                    ),
                    limitations="Purely informational.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"web.robots:{host}"],
                    asset_value=host,
                )
            )
        return findings


def _directory_listing_finding(host: str, url: str) -> Finding:
    return Finding(
        title="Directory listing appears to be enabled",
        category="information-disclosure",
        interpretation_text=(
            f"The response from {url} looks like an automatically generated index of files "
            "rather than a page. When directory listing is on, anyone can enumerate the files "
            "in that directory, which sometimes surfaces backups, configuration or source "
            "archives that were never meant to be reachable."
        ),
        limitations=(
            "This is pattern matching on the response body; a page that merely looks like an "
            "index will match. Open the URL and confirm before reporting."
        ),
        confidence=Confidence.MEDIUM,
        severity_hint=SeverityHint.LOW,
        supporting_dedup_keys=[f"web.published_file:{host}"],
        asset_value=host,
    )
