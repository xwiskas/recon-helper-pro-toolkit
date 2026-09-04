"""TLS certificate inspection.

This is the first module in the OSINT group that actually contacts the target:
a TLS handshake is a connection to the host, so the contact mode is
``direct-read``, it is scope-checked, and it counts against the budgets.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

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

WEAK_SIGNATURE_ALGORITHMS = ("md5", "sha1")
EXPIRY_WARNING_DAYS = 21


@dataclass(slots=True)
class CertificateFetch:
    """What one handshake told us."""

    der: bytes | None = None
    verified: bool = False
    verify_error: str = ""
    tls_version: str = ""
    cipher: str = ""
    connections: int = 0
    warnings: list[str] = field(default_factory=list)


def fetch_certificate(
    host: str, address: str, port: int = 443, timeout: float = 10.0
) -> CertificateFetch:
    """Handshake with *address* using *host* for SNI and certificate validation.

    Tests monkeypatch this function. The address is supplied by the caller and
    has already been scope-checked and pinned - this function never resolves.
    """
    fetch = CertificateFetch()

    verifying = ssl.create_default_context()
    try:
        fetch.connections += 1
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with verifying.wrap_socket(raw, server_hostname=host) as tls:
                fetch.der = tls.getpeercert(binary_form=True)
                fetch.verified = True
                fetch.tls_version = tls.version() or ""
                cipher = tls.cipher()
                fetch.cipher = cipher[0] if cipher else ""
        return fetch
    except ssl.SSLError as exc:
        fetch.verify_error = str(exc)
    except OSError as exc:
        raise NetworkError(f"Could not connect to {host} ({address}:{port}): {exc}") from exc

    # The certificate failed validation. Fetch it anyway so we can explain why -
    # reading a certificate is still read-only.
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        fetch.connections += 1
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with unverified.wrap_socket(raw, server_hostname=host) as tls:
                fetch.der = tls.getpeercert(binary_form=True)
                fetch.tls_version = tls.version() or ""
                cipher = tls.cipher()
                fetch.cipher = cipher[0] if cipher else ""
    except (ssl.SSLError, OSError) as exc:
        raise NetworkError(f"TLS handshake with {host} ({address}:{port}) failed: {exc}") from exc
    return fetch


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


class TlsCertificateModule(ModuleBase):
    id = "cert"
    name = "TLS certificate inspection"
    version = "1.0.0"
    category = "osint"
    mode = ContactMode.DIRECT_READ
    teaching_key = "cert"
    supported_target_types = ("domain", "host", "ip")
    config_schema = {"port": (443, "TLS port to connect to.")}
    request_budget = 2
    scope_requirement = "warn"

    def run(self, context: ModuleContext) -> PluginResult:
        from cryptography import x509

        result = PluginResult()
        host = validate_target(context.target)
        port = int(self.resolved_config(context.params)["port"])
        http = context.require_http()

        target = http.prepare(
            f"https://{host}:{port}/", allow_override=context.allow_override, hop_label="Target"
        )
        http.budget.check(target.host)
        http.rate.wait(target.host)
        context.cancel.raise_if_cancelled()
        context.emit(f"TLS handshake with {target.display} on port {port}")

        try:
            fetch = fetch_certificate(host, str(target.address), port, float(context.policy.timeout_s))
        except NetworkError as exc:
            # The attempt still cost a connection; it must count against the budget.
            http.budget.record(target.host)
            result.status = RunStatus.FAILED
            result.errors.append(str(exc))
            result.merge_metrics(requests=1)
            return result

        for _ in range(max(1, fetch.connections)):
            http.budget.record(target.host)

        if not fetch.der:
            result.status = RunStatus.PARTIAL
            result.errors.append("The handshake completed but no certificate was returned.")
            result.merge_metrics(requests=fetch.connections)
            return result

        certificate = x509.load_der_x509_certificate(fetch.der)
        issuer = certificate.issuer.rfc4514_string()
        subject = certificate.subject.rfc4514_string()
        not_before = _aware(certificate.not_valid_before_utc)
        not_after = _aware(certificate.not_valid_after_utc)
        signature = (certificate.signature_hash_algorithm.name
                     if certificate.signature_hash_algorithm else "unknown")

        try:
            san_extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = sorted(set(san_extension.value.get_values_for_type(x509.DNSName)))
        except x509.ExtensionNotFound:
            sans = []

        def observe(obs_type: str, value: str, evidence: str) -> None:
            result.observations.append(
                Observation(
                    type=obs_type,
                    normalized_value=value,
                    source_provider=f"TLS handshake with {host}:{port}",
                    dedup_key=f"{obs_type}:{host}:{value}",
                    asset_value=host,
                    asset_kind=AssetKind.HOST,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                )
            )

        observe("tls.subject", subject, "Certificate subject distinguished name.")
        observe("tls.issuer", issuer, "Certificate issuer distinguished name.")
        observe("tls.not_before", not_before.isoformat(), "Certificate validity start.")
        observe("tls.not_after", not_after.isoformat(), "Certificate validity end.")
        observe("tls.signature_algorithm", signature, "Hash used in the certificate signature.")
        observe("tls.serial", format(certificate.serial_number, "x"), "Certificate serial number.")
        if fetch.tls_version:
            observe("tls.version", fetch.tls_version, "Protocol version negotiated.")
        if fetch.cipher:
            observe("tls.cipher", fetch.cipher, "Cipher suite negotiated.")
        observe(
            "tls.validation",
            "trusted" if fetch.verified else "not trusted",
            fetch.verify_error or "Chain validated against the system trust store.",
        )
        for name in sans:
            observe("tls.san", name, "Subject Alternative Name in the certificate.")
            result.discovered_assets.append(
                DiscoveredAsset(
                    AssetKind.HOST, name.lower().lstrip("*."),
                    "Named in the certificate. Recorded only - not contacted."
                )
            )

        reference = context.artifact("tls-certificate-pem", _to_pem(certificate))
        if reference:
            result.warnings.append("The certificate was stored as an artifact.")

        result.findings.extend(
            self._findings(host, fetch, not_after, not_before, signature, issuer, subject)
        )
        result.merge_metrics(requests=fetch.connections, sans=len(sans))
        return result

    def _findings(
        self,
        host: str,
        fetch: CertificateFetch,
        not_after: datetime,
        not_before: datetime,
        signature: str,
        issuer: str,
        subject: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        if days_left < 0:
            findings.append(
                Finding(
                    title="TLS certificate has expired",
                    category="tls",
                    interpretation_text=(
                        f"The certificate presented by {host} expired on "
                        f"{not_after.date()} ({abs(days_left)} days ago). Browsers will refuse "
                        "the connection with a full-page warning, so this is usually an "
                        "availability incident rather than an attacker's foothold."
                    ),
                    limitations=(
                        "Only the certificate on this host and port was checked; other names on "
                        "the same infrastructure may serve a different certificate."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.MEDIUM,
                    supporting_dedup_keys=[f"tls.not_after:{host}:{not_after.isoformat()}"],
                    asset_value=host,
                )
            )
        elif days_left <= EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    title=f"TLS certificate expires in {days_left} days",
                    category="tls",
                    interpretation_text=(
                        f"The certificate for {host} is valid until {not_after.date()}. Short "
                        "lifetimes are normal (Let's Encrypt issues 90-day certificates), so "
                        "this only matters if renewal is manual."
                    ),
                    limitations="Automated renewal is invisible from the outside.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=[f"tls.not_after:{host}:{not_after.isoformat()}"],
                    asset_value=host,
                )
            )

        if not fetch.verified:
            self_signed = issuer == subject
            findings.append(
                Finding(
                    title=(
                        "TLS certificate is self-signed"
                        if self_signed
                        else "TLS certificate did not validate"
                    ),
                    category="tls",
                    interpretation_text=(
                        f"The chain presented by {host} did not validate against the system "
                        f"trust store. The library reported: {fetch.verify_error or 'no detail'}. "
                        + (
                            "Issuer and subject are identical, so this is a self-signed "
                            "certificate - normal on internal or lab hosts, wrong on a public "
                            "site."
                            if self_signed
                            else "Common causes are a missing intermediate certificate, a name "
                            "mismatch, or an expired chain."
                        )
                    ),
                    limitations=(
                        "A validation failure is a client-side judgement. Confirm what a real "
                        "browser reports before treating it as a defect."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.LOW,
                    supporting_dedup_keys=[f"tls.validation:{host}:not trusted"],
                    asset_value=host,
                )
            )

        if signature.lower() in WEAK_SIGNATURE_ALGORITHMS:
            findings.append(
                Finding(
                    title=f"Certificate signed with {signature.upper()}",
                    category="tls",
                    interpretation_text=(
                        f"The certificate for {host} is signed using {signature.upper()}, which "
                        "is no longer considered collision-resistant. Public CAs stopped issuing "
                        "these years ago, so this usually indicates a private or very old "
                        "certificate."
                    ),
                    limitations=(
                        "Exploiting a weak signature requires a CA that will issue a colliding "
                        "certificate; this is a hygiene finding, not a demonstrated attack."
                    ),
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.MEDIUM,
                    supporting_dedup_keys=[f"tls.signature_algorithm:{host}:{signature}"],
                    asset_value=host,
                )
            )

        if fetch.tls_version and fetch.tls_version in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(
                Finding(
                    title=f"Connection negotiated {fetch.tls_version}",
                    category="tls",
                    interpretation_text=(
                        f"{host} negotiated {fetch.tls_version}. Anything below TLS 1.2 is "
                        "deprecated and disabled by default in current browsers. Note this says "
                        "what *we* negotiated, not the full list of protocols the server accepts."
                    ),
                    limitations=(
                        "A single handshake does not enumerate supported protocol versions; a "
                        "dedicated TLS scanner would be needed for that."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity_hint=SeverityHint.MEDIUM,
                    supporting_dedup_keys=[f"tls.version:{host}:{fetch.tls_version}"],
                    asset_value=host,
                )
            )
        return findings


def _to_pem(certificate: object) -> str:
    from cryptography.hazmat.primitives import serialization

    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]
