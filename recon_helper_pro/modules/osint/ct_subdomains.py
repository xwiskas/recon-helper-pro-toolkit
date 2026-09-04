"""Hostname discovery from Certificate Transparency logs (crt.sh, free, keyless).

Every publicly trusted certificate is logged, and certificates name the hosts
they cover - so CT logs are a rich, entirely passive source of subdomains.

Everything found here is *recorded as an asset and never contacted* (PRD 4).
Adding one of these names to your scope is a deliberate decision you make.
"""

from __future__ import annotations

import json
from urllib.parse import quote

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
from ...core.scope import is_hostname, normalize_hostname, validate_target
from ...core.thirdparty import PROVIDERS
from ...core.tools import detect_version, run_tool


class CtSubdomainsModule(ModuleBase):
    id = "subdomains"
    name = "Hostname discovery (Certificate Transparency)"
    version = "1.0.0"
    category = "osint"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "subdomains"
    supported_target_types = ("domain",)
    config_schema = {
        "include_wildcards": (False, "Also record '*.example.com' entries as assets."),
        "max_hostnames": (500, "Stop after this many distinct names."),
        "use_external_tools": (True, "Use subfinder/amass for extra depth when installed."),
    }
    request_budget = 0
    scope_requirement = "none"
    optional_tools = ("subfinder", "amass")

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        domain = validate_target(context.target)
        config = self.resolved_config(context.params)
        limit = int(config["max_hostnames"])

        context.emit(f"Querying Certificate Transparency logs for {domain}")
        url = f"{PROVIDERS['crtsh']}/?q={quote('%.' + domain)}&output=json"
        client = context.third_party()
        entries: list[dict] = []
        try:
            payload = client.get_json(url)
            if isinstance(payload, list):
                entries = [item for item in payload if isinstance(item, dict)]
            else:
                result.status = RunStatus.PARTIAL
                result.warnings.append(
                    "crt.sh did not return usable JSON. It is a free service and rate-limits "
                    "or times out under load; try again in a minute."
                )
        except (NetworkError, json.JSONDecodeError) as exc:
            result.status = RunStatus.PARTIAL
            result.errors.append(f"Certificate Transparency lookup failed: {exc}")
        finally:
            third_party_requests = client.requests_made
            client.close()

        names: dict[str, str] = {}
        sources: dict[str, str] = {}
        wildcards: set[str] = set()
        for entry in entries:
            for raw in str(entry.get("name_value") or "").splitlines():
                candidate = raw.strip().lower().rstrip(".")
                if not candidate:
                    continue
                if candidate.startswith("*."):
                    wildcards.add(candidate)
                    if not config["include_wildcards"]:
                        continue
                    candidate_check = candidate[2:]
                else:
                    candidate_check = candidate
                if not (candidate_check == domain or candidate_check.endswith("." + domain)):
                    continue
                try:
                    normalized = normalize_hostname(candidate_check)
                except Exception:
                    continue
                if not is_hostname(normalized):
                    continue
                key = candidate if candidate.startswith("*.") else normalized
                if key not in names and len(names) < limit:
                    names[key] = str(entry.get("issuer_name") or "").strip()
                    sources[key] = "crt.sh Certificate Transparency search"

        if config["use_external_tools"]:
            names.update(self._external(domain, limit, names, sources, result))

        for name, issuer in sorted(names.items()):
            result.observations.append(
                Observation(
                    type="hostname.discovered",
                    normalized_value=name,
                    source_provider=sources.get(name, "crt.sh Certificate Transparency search"),
                    dedup_key=f"hostname.discovered:{name}",
                    asset_value=domain,
                    asset_kind=AssetKind.DOMAIN,
                    evidence=(
                        f"Named in a logged certificate for {domain}"
                        + (f"; issuer {issuer}" if issuer else "")
                        + "."
                    ),
                    confidence=Confidence.MEDIUM,
                )
            )
            if not name.startswith("*."):
                result.discovered_assets.append(
                    DiscoveredAsset(
                        AssetKind.HOST,
                        name,
                        "Seen in a certificate. Recorded only - not contacted.",
                    )
                )

        if names:
            result.findings.append(
                Finding(
                    title=f"{len(names)} hostname(s) visible in Certificate Transparency",
                    category="attack-surface",
                    interpretation_text=(
                        f"Certificate logs name {len(names)} host(s) under {domain}. This is "
                        "public information by design - CT exists so that mis-issued "
                        "certificates are detectable - but it also means every internal-sounding "
                        "name that ever got a public certificate is discoverable. Names like "
                        "'staging', 'vpn' or 'admin' are worth noting as surface, not as flaws. "
                        "None of these hosts has been contacted; add any you are authorized to "
                        "test with 'rhp scope add'."
                    ),
                    limitations=(
                        "CT only shows names that received a publicly trusted certificate, and "
                        "many of them will no longer resolve. Nothing here proves a host is live."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"hostname.discovered:{name}" for name in list(names)[:10]],
                    asset_value=domain,
                )
            )
        elif result.status is RunStatus.COMPLETED:
            result.warnings.append(
                f"No certificate-transparency entries matched {domain}."
            )

        if wildcards:
            result.warnings.append(
                f"{len(wildcards)} wildcard certificate name(s) seen (e.g. "
                f"{sorted(wildcards)[0]}); wildcards hide the specific hosts behind them."
            )

        result.merge_metrics(
            requests=0, third_party_requests=third_party_requests, hostnames=len(names)
        )
        return result

    def _external(
        self,
        domain: str,
        limit: int,
        existing: dict[str, str],
        sources: dict[str, str],
        result: PluginResult,
    ) -> dict[str, str]:
        """Optional extra depth from subfinder/amass when they happen to exist."""
        extra: dict[str, str] = {}
        for tool, args in (("subfinder", ["-silent", "-d"]), ("amass", ["enum", "-passive", "-d"])):
            outcome = run_tool(tool, args, [domain], timeout=120)
            if not outcome.ok:
                continue
            version = detect_version(tool) or "unknown version"
            for line in outcome.stdout.splitlines():
                candidate = line.strip().lower().rstrip(".")
                if not candidate or candidate in existing or candidate in extra:
                    continue
                if not (candidate == domain or candidate.endswith("." + domain)):
                    continue
                if len(existing) + len(extra) >= limit:
                    break
                extra[candidate] = ""
                sources[candidate] = f"{tool} (optional local tool, {version})"
            result.warnings.append(f"Extra hostnames contributed by {tool} ({version}).")
        return extra
