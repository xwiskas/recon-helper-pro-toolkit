"""Cross-cutting interpretation of everything already collected.

This module sends nothing anywhere. It reads the observations recorded so far
for the engagement and looks for patterns that only appear when you put several
facts side by side. Everything it produces is explicitly a hypothesis: the
point is to teach the reader how findings are assembled from evidence, not to
hand them a vulnerability list.
"""

from __future__ import annotations

from typing import Any

from ...core.models import (
    Confidence,
    ContactMode,
    Finding,
    PluginResult,
    RunStatus,
    SeverityHint,
)
from ...core.module_base import ModuleBase, ModuleContext

INTERNAL_NAME_HINTS = (
    "staging",
    "stage",
    "dev",
    "test",
    "uat",
    "qa",
    "internal",
    "intranet",
    "admin",
    "vpn",
    "jenkins",
    "gitlab",
    "jira",
    "backup",
    "legacy",
    "old",
)

SECURITY_HEADER_TYPES = (
    "http.header.strict-transport-security",
    "http.header.content-security-policy",
    "http.header.x-frame-options",
    "http.header.x-content-type-options",
    "http.header.referrer-policy",
)


class HintsModule(ModuleBase):
    id = "hints"
    name = "Interpreted hints (informational only)"
    version = "1.0.0"
    category = "web"
    mode = ContactMode.THIRD_PARTY  # nothing is contacted; this reads stored data
    teaching_key = "hints"
    supported_target_types = ("domain", "host", "ip", "url")
    config_schema = {}
    request_budget = 0
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        observations = context.prior_observations
        if not observations:
            result.status = RunStatus.PARTIAL
            result.warnings.append(
                "Nothing has been collected for this engagement yet, so there is nothing to "
                "interpret. Run the other modules first (or use 'rhp recon')."
            )
            return result

        target = context.target
        by_type: dict[str, list[dict[str, Any]]] = {}
        for observation in observations:
            by_type.setdefault(str(observation.get("type")), []).append(observation)

        context.emit("Reading stored observations - no requests are sent")
        result.findings.extend(self._hardening(target, by_type))
        result.findings.extend(self._surface(target, by_type))
        result.findings.extend(self._email(target, by_type))

        if not result.findings:
            result.warnings.append(
                "No cross-cutting patterns stood out. That is a normal outcome, not a failure."
            )
        result.merge_metrics(
            requests=0,
            observations_considered=len(observations),
            hints=len(result.findings),
        )
        return result

    # -- patterns ---------------------------------------------------------
    def _hardening(self, target: str, by_type: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        if "http.status" not in by_type:
            return findings

        present = [name for name in SECURITY_HEADER_TYPES if by_type.get(name)]
        missing = [name for name in SECURITY_HEADER_TYPES if not by_type.get(name)]
        disclosed = by_type.get("http.header.server", []) + by_type.get(
            "http.header.x-powered-by", []
        )

        if len(missing) >= 4 and disclosed:
            banners = ", ".join(str(item.get("normalized_value")) for item in disclosed[:3])
            findings.append(
                Finding(
                    title="Response headers suggest little hardening has been applied",
                    category="hypothesis",
                    interpretation_text=(
                        f"{len(missing)} of the {len(SECURITY_HEADER_TYPES)} common security "
                        f"headers are absent, while the server still advertises itself "
                        f"({banners}). Individually each of those is minor. Together they "
                        "suggest a deployment running close to its defaults, which is a "
                        "reasonable hypothesis to carry into the rest of an assessment - and "
                        "nothing more than a hypothesis. A site behind a CDN or a WAF can look "
                        "exactly like this and be well defended."
                    ),
                    limitations=(
                        "Assembled from one response on one path. Do not report a posture "
                        "judgement as a finding; use it to decide what to look at next."
                    ),
                    confidence=Confidence.LOW,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        str(item.get("dedup_key")) for item in disclosed[:3]
                    ],
                    asset_value=target,
                )
            )
        elif len(present) >= 4:
            findings.append(
                Finding(
                    title="Security headers are broadly in place",
                    category="hypothesis",
                    interpretation_text=(
                        f"{len(present)} of the common security headers were returned. Recording "
                        "what is done well matters: it tells the reader of your report that the "
                        "absence of a finding here was checked, not skipped."
                    ),
                    limitations="Presence of a header says nothing about whether its value is sane.",
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[
                        str(by_type[name][0].get("dedup_key")) for name in present
                    ],
                    asset_value=target,
                )
            )
        return findings

    def _surface(self, target: str, by_type: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        names = [
            str(item.get("normalized_value"))
            for item in by_type.get("hostname.discovered", []) + by_type.get("tls.san", [])
        ]
        interesting = sorted(
            {
                name
                for name in names
                if any(hint in name.lower() for hint in INTERNAL_NAME_HINTS)
            }
        )
        if interesting:
            findings.append(
                Finding(
                    title=f"{len(interesting)} discovered hostname(s) sound non-production",
                    category="attack-surface",
                    interpretation_text=(
                        "Names such as "
                        + ", ".join(interesting[:8])
                        + " appear in public certificate data. Non-production environments are "
                        "often less hardened than production and sometimes hold real data, which "
                        "is why they are interesting. None of them has been contacted, and being "
                        "named in a certificate does not mean the host still exists. If any of "
                        "them is in your authorization, add it with 'rhp scope add' and look "
                        "deliberately."
                    ),
                    limitations=(
                        "Inference from naming convention alone. A host called 'test' may be "
                        "production, and a production host may be called anything."
                    ),
                    confidence=Confidence.LOW,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"hostname.discovered:{name}" for name in interesting[:8]],
                    asset_value=target,
                )
            )
        return findings

    def _email(self, target: str, by_type: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        txt_values = [str(item.get("normalized_value", "")).lower() for item in by_type.get("dns.txt", [])]
        has_spf = any("v=spf1" in value for value in txt_values)
        has_dmarc = bool(by_type.get("dns.dmarc"))
        has_mx = bool(by_type.get("dns.mx"))

        if has_mx and not has_spf and not has_dmarc:
            findings.append(
                Finding(
                    title="Domain accepts mail but publishes neither SPF nor DMARC",
                    category="hypothesis",
                    interpretation_text=(
                        f"{target} has MX records, so it is set up to receive mail, yet no SPF "
                        "and no DMARC policy were found. Each absence on its own is common; "
                        "together on a mail-carrying domain they mean receivers have no published "
                        "way to tell genuine mail from spoofed mail. That is a phishing-resistance "
                        "gap rather than a technical vulnerability in any system."
                    ),
                    limitations=(
                        "Only the apex domain was checked, and sending may happen from a "
                        "subdomain with its own records."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.LOW,
                    supporting_dedup_keys=[
                        str(item.get("dedup_key")) for item in by_type.get("dns.mx", [])[:3]
                    ],
                    asset_value=target,
                )
            )
        return findings
