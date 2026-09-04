"""DNS records through a resolver. Third-party: the target is never contacted.

A resolver is a middleman, which is exactly why this is safe to run first - it
tells you where a name points, what mail infrastructure exists, and which name
servers are authoritative, without a single packet reaching the target.
"""

from __future__ import annotations

from typing import Iterable

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
from ...core.scope import normalize_ip, validate_target

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DnsLookupError(Exception):
    """Raised by :func:`resolve_records` for anything other than 'no records'."""


def resolve_records(name: str, rdtype: str, timeout: float = 5.0) -> list[str]:
    """Resolve one record type. Returns ``[]`` when the name simply has none.

    Tests monkeypatch this function, which is why it is a module-level function
    rather than a method.
    """
    import dns.exception
    import dns.rdatatype
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, rdtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        raise DnsLookupError(f"{rdtype} lookup for {name} failed: {exc}") from exc
    return [record.to_text().strip() for record in answer]


def _clean_txt(value: str) -> str:
    """DNS TXT arrives as quoted, possibly split strings."""
    parts = [part.strip('"') for part in value.split('" "')]
    return "".join(parts).strip('"')


class DnsRecordsModule(ModuleBase):
    id = "dns"
    name = "DNS records"
    version = "1.0.0"
    category = "osint"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "dns"
    supported_target_types = ("domain", "host")
    config_schema = {
        "record_types": (list(RECORD_TYPES), "Which record types to ask for."),
        "check_email_policy": (True, "Also look up the _dmarc TXT record."),
    }
    request_budget = 0
    scope_requirement = "none"
    optional_tools = ("dig",)

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        host = validate_target(context.target)
        config = self.resolved_config(context.params)
        types: Iterable[str] = config["record_types"] or RECORD_TYPES

        found: dict[str, list[str]] = {}
        for rdtype in types:
            context.cancel.raise_if_cancelled()
            context.emit(f"Looking up {rdtype} records for {host}")
            try:
                values = resolve_records(host, rdtype)
            except DnsLookupError as exc:
                result.status = RunStatus.PARTIAL
                result.errors.append(str(exc))
                continue
            found[rdtype] = values
            for value in values:
                result.observations.append(
                    Observation(
                        type=f"dns.{rdtype.lower()}",
                        normalized_value=value,
                        source_provider="DNS resolver",
                        dedup_key=f"dns.{rdtype.lower()}:{host}:{value}",
                        asset_value=host,
                        asset_kind=AssetKind.HOST,
                        evidence=f"{rdtype} record returned for {host}.",
                        confidence=Confidence.HIGH,
                    )
                )

        result.discovered_assets.extend(self._assets(found))

        if config["check_email_policy"]:
            context.cancel.raise_if_cancelled()
            try:
                dmarc = [_clean_txt(value) for value in resolve_records(f"_dmarc.{host}", "TXT")]
            except DnsLookupError as exc:
                dmarc = []
                result.warnings.append(str(exc))
            for value in dmarc:
                result.observations.append(
                    Observation(
                        type="dns.dmarc",
                        normalized_value=value,
                        source_provider="DNS resolver",
                        dedup_key=f"dns.dmarc:{host}:{value}",
                        asset_value=host,
                        asset_kind=AssetKind.HOST,
                        evidence=f"TXT record at _dmarc.{host}.",
                        confidence=Confidence.HIGH,
                    )
                )
            result.findings.extend(self._email_findings(host, found.get("TXT", []), dmarc))

        if not any(found.values()):
            result.status = RunStatus.PARTIAL
            result.warnings.append(
                f"No DNS records came back for {host}. Check the spelling, or the name may "
                "only exist inside a private zone."
            )

        result.merge_metrics(requests=0, third_party_requests=0, record_types=len(found))
        return result

    def _assets(self, found: dict[str, list[str]]) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        for value in found.get("A", []) + found.get("AAAA", []):
            if normalize_ip(value) is not None:
                assets.append(
                    DiscoveredAsset(AssetKind.IP, value, "Address the name resolves to.")
                )
        for value in found.get("NS", []):
            assets.append(
                DiscoveredAsset(AssetKind.HOST, value.rstrip("."), "Authoritative name server.")
            )
        for value in found.get("MX", []):
            parts = value.split()
            if parts:
                assets.append(
                    DiscoveredAsset(AssetKind.HOST, parts[-1].rstrip("."), "Mail exchanger.")
                )
        for value in found.get("CNAME", []):
            assets.append(DiscoveredAsset(AssetKind.HOST, value.rstrip("."), "CNAME target."))
        return assets

    def _email_findings(
        self, host: str, txt_records: list[str], dmarc_records: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        spf = [_clean_txt(value) for value in txt_records if "v=spf1" in _clean_txt(value).lower()]

        if not spf:
            findings.append(
                Finding(
                    title="No SPF record published",
                    category="email-policy",
                    interpretation_text=(
                        f"No TXT record starting with 'v=spf1' was found for {host}. SPF tells "
                        "receiving mail servers which hosts may send mail for this domain. Its "
                        "absence makes spoofing easier - but only matters if the domain sends "
                        "or is impersonated in mail. A domain that never sends mail is better "
                        "served by an explicit 'v=spf1 -all' than by nothing."
                    ),
                    limitations=(
                        "This describes mail infrastructure, not the web application, and only "
                        "the apex name was checked."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"dns.txt:{host}"],
                    asset_value=host,
                )
            )
        else:
            record = spf[0]
            if record.strip().endswith("+all") or " +all" in record:
                findings.append(
                    Finding(
                        title="SPF record ends in '+all'",
                        category="email-policy",
                        interpretation_text=(
                            f"The SPF record for {host} is '{record}'. The '+all' mechanism tells "
                            "receivers that any host may send mail as this domain, which defeats "
                            "the point of publishing SPF at all. '-all' (or '~all' while testing) "
                            "is the intended ending."
                        ),
                        limitations=(
                            "Impact depends on whether the domain is used for mail and on DMARC "
                            "policy, which is evaluated separately."
                        ),
                        confidence=Confidence.HIGH,
                        severity_hint=SeverityHint.MEDIUM,
                        supporting_dedup_keys=[f"dns.txt:{host}:{record}"],
                        asset_value=host,
                    )
                )

        if not dmarc_records:
            findings.append(
                Finding(
                    title="No DMARC record published",
                    category="email-policy",
                    interpretation_text=(
                        f"No TXT record was found at _dmarc.{host}. DMARC is what tells receivers "
                        "what to do when SPF and DKIM fail, and where to send reports. Without it "
                        "the domain has no published policy for failed authentication."
                    ),
                    limitations="Mail-infrastructure observation only; subdomains may differ.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"dns.dmarc:{host}"],
                    asset_value=host,
                )
            )
        else:
            record = dmarc_records[0]
            if "p=none" in record.replace(" ", "").lower():
                findings.append(
                    Finding(
                        title="DMARC policy is 'p=none'",
                        category="email-policy",
                        interpretation_text=(
                            f"The DMARC record for {host} is '{record}'. 'p=none' means "
                            "monitor-only: failures are reported but nothing is quarantined or "
                            "rejected. That is the correct first step of a DMARC rollout, so this "
                            "is only a weakness if the rollout has stalled there."
                        ),
                        limitations="Whether this is intentional cannot be told from DNS alone.",
                        confidence=Confidence.HIGH,
                        severity_hint=SeverityHint.INFO,
                        supporting_dedup_keys=[f"dns.dmarc:{host}:{record}"],
                        asset_value=host,
                    )
                )
        return findings
