"""Registration data via RDAP, with the system ``whois`` binary as a bonus.

RDAP is the structured, modern replacement for WHOIS text, it is free and needs
no key, and ``rdap.org`` bootstraps us to the authoritative server for the TLD.
The target is never contacted (PRD 6.1).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...core.errors import NetworkError
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
from ...core.thirdparty import PROVIDERS
from ...core.tools import detect_version, run_tool

EXPIRY_WARNING_DAYS = 45
NEW_DOMAIN_DAYS = 45


def _vcard_field(entity: dict[str, Any] | None, field: str) -> str:
    """Pull one field out of the jCard array RDAP uses for contact data."""
    if not entity:
        return ""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                return " ".join(str(part) for part in value if part)
            return str(value)
    return ""


def _entity_by_role(data: dict[str, Any], role: str) -> dict[str, Any] | None:
    for entity in data.get("entities", []) or []:
        if isinstance(entity, dict) and role in (entity.get("roles") or []):
            return entity
    return None


def _event_date(data: dict[str, Any], action: str) -> str:
    for event in data.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            return str(event.get("eventDate") or "")
    return ""


def _days_until(iso_date: str) -> int | None:
    if not iso_date:
        return None
    text = iso_date.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - datetime.now(timezone.utc)).days


class WhoisRdapModule(ModuleBase):
    id = "whois"
    name = "Registration data (RDAP/WHOIS)"
    version = "1.0.0"
    category = "osint"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "whois"
    supported_target_types = ("domain",)
    config_schema = {
        "use_system_whois": (
            True,
            "Also run the system 'whois' binary when it is installed, for the raw text.",
        )
    }
    request_budget = 0
    scope_requirement = "none"
    optional_tools = ("whois",)

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        domain = validate_target(context.target)
        config = self.resolved_config(context.params)

        context.emit(f"Asking RDAP about {domain} (the target is not contacted)")
        client = context.third_party()
        data: dict[str, Any] | None = None
        try:
            payload = client.get_json(f"{PROVIDERS['rdap']}/domain/{domain}")
            if isinstance(payload, dict):
                data = payload
            else:
                result.warnings.append(
                    "RDAP returned no usable record for this name. Very new domains, some "
                    "country-code TLDs, and rate-limited lookups all look like this."
                )
        except NetworkError as exc:
            result.status = RunStatus.PARTIAL
            result.errors.append(f"RDAP lookup failed: {exc}")
        finally:
            third_party_requests = client.requests_made
            client.close()

        if data:
            result.observations.extend(self._observations(domain, data))
            result.discovered_assets.extend(self._assets(data))
            result.findings.extend(self._findings(domain, data))
        elif result.status is RunStatus.COMPLETED:
            result.status = RunStatus.PARTIAL

        if config["use_system_whois"]:
            tool = run_tool("whois", [], [domain], timeout=20)
            if tool.ok:
                reference = context.artifact("whois-text", context.redactor.text(tool.stdout))
                result.observations.append(
                    Observation(
                        type="whois.raw",
                        normalized_value=f"whois text for {domain} ({len(tool.stdout)} chars)",
                        source_provider=f"system whois ({detect_version('whois') or 'unknown'})",
                        dedup_key=f"whois.raw:{domain}",
                        asset_value=domain,
                        asset_kind=AssetKind.DOMAIN,
                        artifact_ref=reference,
                        evidence="Raw registry text, redacted before storage.",
                        confidence=Confidence.HIGH,
                    )
                )
                result.warnings.append(
                    "System 'whois' output was stored as a redacted artifact."
                )

        result.merge_metrics(requests=0, third_party_requests=third_party_requests)
        return result

    # -- extraction -------------------------------------------------------
    def _observations(self, domain: str, data: dict[str, Any]) -> list[Observation]:
        observations: list[Observation] = []

        def add(obs_type: str, value: str, evidence: str, confidence: Confidence) -> None:
            if not value:
                return
            observations.append(
                Observation(
                    type=obs_type,
                    normalized_value=value,
                    source_provider="RDAP (rdap.org bootstrap)",
                    dedup_key=f"{obs_type}:{domain}:{value}",
                    asset_value=domain,
                    asset_kind=AssetKind.DOMAIN,
                    evidence=evidence,
                    confidence=confidence,
                )
            )

        registrar = _entity_by_role(data, "registrar")
        add(
            "registration.registrar",
            _vcard_field(registrar, "fn"),
            "RDAP entity with role 'registrar'.",
            Confidence.HIGH,
        )
        registrant = _entity_by_role(data, "registrant")
        add(
            "registration.registrant_org",
            _vcard_field(registrant, "org") or _vcard_field(registrant, "fn"),
            "RDAP entity with role 'registrant'. Usually redacted by the registry.",
            Confidence.MEDIUM,
        )
        add("registration.created", _event_date(data, "registration"), "RDAP event 'registration'.", Confidence.HIGH)
        add("registration.expires", _event_date(data, "expiration"), "RDAP event 'expiration'.", Confidence.HIGH)
        add("registration.updated", _event_date(data, "last changed"), "RDAP event 'last changed'.", Confidence.HIGH)

        statuses = [str(item) for item in (data.get("status") or [])]
        if statuses:
            add(
                "registration.status",
                ", ".join(statuses),
                "RDAP 'status' array - registry lock states live here.",
                Confidence.HIGH,
            )

        for nameserver in data.get("nameservers", []) or []:
            if isinstance(nameserver, dict) and nameserver.get("ldhName"):
                add(
                    "registration.nameserver",
                    str(nameserver["ldhName"]).lower(),
                    "RDAP 'nameservers' entry.",
                    Confidence.HIGH,
                )
        return observations

    def _assets(self, data: dict[str, Any]) -> list[DiscoveredAsset]:
        assets: list[DiscoveredAsset] = []
        for nameserver in data.get("nameservers", []) or []:
            if isinstance(nameserver, dict) and nameserver.get("ldhName"):
                assets.append(
                    DiscoveredAsset(
                        kind=AssetKind.HOST,
                        value=str(nameserver["ldhName"]).lower(),
                        note="Authoritative name server named in the registry record.",
                    )
                )
        return assets

    def _findings(self, domain: str, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        expires = _event_date(data, "expiration")
        days_left = _days_until(expires)
        if days_left is not None and days_left <= EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    title=f"Domain registration expires in {days_left} days",
                    category="registration",
                    interpretation_text=(
                        f"The registry says {domain} expires on {expires}, which is "
                        f"{days_left} days away. Expiry is an availability and takeover "
                        "concern rather than a vulnerability: a lapsed domain can be "
                        "re-registered by someone else. Whether this matters depends on "
                        "whether the owner has auto-renew configured, which RDAP does not show."
                    ),
                    limitations=(
                        "Registry dates can lag reality, and auto-renewal is invisible here. "
                        "Confirm with the domain owner before reporting."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.LOW if days_left > 7 else SeverityHint.MEDIUM,
                    supporting_dedup_keys=[f"registration.expires:{domain}:{expires}"],
                    asset_value=domain,
                )
            )

        created = _event_date(data, "registration")
        age = _days_until(created)
        if age is not None and -NEW_DOMAIN_DAYS <= age <= 0:
            findings.append(
                Finding(
                    title=f"Domain was registered {abs(age)} days ago",
                    category="registration",
                    interpretation_text=(
                        "A very recently registered domain is worth noting as context: it is "
                        "common for legitimate new projects and equally common for lookalike "
                        "and phishing domains. This is an observation about age, nothing more."
                    ),
                    limitations="Age alone says nothing about intent or security posture.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"registration.created:{domain}:{created}"],
                    asset_value=domain,
                )
            )

        statuses = " ".join(str(item).lower() for item in (data.get("status") or []))
        if statuses and "transfer prohibited" not in statuses:
            findings.append(
                Finding(
                    title="Registry transfer lock not visible in the RDAP record",
                    category="registration",
                    interpretation_text=(
                        "The RDAP status list does not include a 'clientTransferProhibited' or "
                        "'serverTransferProhibited' state. A transfer lock is a cheap defence "
                        "against domain hijacking. Some registries simply do not publish status "
                        "values, so this is a prompt to check, not a defect."
                    ),
                    limitations=(
                        "Absence in RDAP is not proof the lock is off. Verify in the registrar "
                        "control panel."
                    ),
                    confidence=Confidence.LOW,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"registration.status:{domain}:{', '.join(data.get('status') or [])}"],
                    asset_value=domain,
                )
            )
        return findings
