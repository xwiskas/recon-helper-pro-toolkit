"""OSINT modules against recorded provider responses - no live services."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from recon_helper_pro.core.models import AssetKind, RunStatus
from recon_helper_pro.modules.osint import dns_records, reverse_dns
from recon_helper_pro.modules.osint.ct_subdomains import CtSubdomainsModule
from recon_helper_pro.modules.osint.dns_records import DnsRecordsModule
from recon_helper_pro.modules.osint.reverse_dns import ReverseDnsModule
from recon_helper_pro.modules.osint.tls_cert import CertificateFetch, TlsCertificateModule
from recon_helper_pro.modules.osint.whois_rdap import WhoisRdapModule

PROVIDER = "https://93.184.216.34"


def _rdap_payload(expires_in_days: int = 400) -> dict:
    expiry = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
    return {
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2005-04-12T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": expiry},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
            }
        ],
        "nameservers": [{"ldhName": "ns1.example.net"}, {"ldhName": "ns2.example.net"}],
    }


@respx.mock
def test_rdap_extracts_registration_data(make_context) -> None:
    respx.get(url__regex=rf"{PROVIDER}/domain/example\.com").mock(
        return_value=httpx.Response(200, json=_rdap_payload())
    )
    context = make_context("example.com", params={"use_system_whois": False})

    result = WhoisRdapModule().run(context)

    assert result.status is RunStatus.COMPLETED
    types = {observation.type for observation in result.observations}
    assert "registration.registrar" in types
    assert "registration.expires" in types
    assert {asset.value for asset in result.discovered_assets} == {
        "ns1.example.net",
        "ns2.example.net",
    }
    for observation in result.observations:
        assert observation.source_provider
        assert observation.collected_at
        assert observation.dedup_key


@respx.mock
def test_rdap_flags_an_imminent_expiry(make_context) -> None:
    respx.get(url__regex=rf"{PROVIDER}/domain/.*").mock(
        return_value=httpx.Response(200, json=_rdap_payload(expires_in_days=10))
    )
    context = make_context("example.com", params={"use_system_whois": False})

    result = WhoisRdapModule().run(context)

    titles = [finding.title for finding in result.findings]
    assert any("expires in" in title for title in titles)


@respx.mock
def test_rdap_missing_record_is_a_partial_run_not_a_crash(make_context) -> None:
    respx.get(url__regex=rf"{PROVIDER}/domain/.*").mock(return_value=httpx.Response(404))
    context = make_context("nonexistent.example", params={"use_system_whois": False})

    result = WhoisRdapModule().run(context)

    assert result.status is RunStatus.PARTIAL
    assert result.observations == []


# -- DNS --------------------------------------------------------------------
FAKE_ZONE = {
    ("example.com", "A"): ["203.0.113.10"],
    ("example.com", "AAAA"): [],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    ("example.com", "TXT"): ['"v=spf1 include:_spf.example.net +all"'],
    ("example.com", "CNAME"): [],
    ("example.com", "SOA"): ["ns1.example.net. hostmaster.example.com. 1 2 3 4 5"],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none; rua=mailto:d@example.com"'],
}


@pytest.fixture
def fake_dns(monkeypatch):
    def resolve(name: str, rdtype: str, timeout: float = 5.0) -> list[str]:
        return list(FAKE_ZONE.get((name, rdtype), []))

    monkeypatch.setattr(dns_records, "resolve_records", resolve)
    return resolve


def test_dns_records_are_recorded_with_provenance(make_context, fake_dns) -> None:
    result = DnsRecordsModule().run(make_context("example.com"))

    assert result.status is RunStatus.COMPLETED
    values = {(o.type, o.normalized_value) for o in result.observations}
    assert ("dns.a", "203.0.113.10") in values
    assert any(kind == "dns.ns" for kind, _ in values)
    assert {asset.value for asset in result.discovered_assets} >= {
        "203.0.113.10",
        "ns1.example.net",
        "mail.example.com",
    }


def test_dns_flags_spf_all_and_dmarc_none(make_context, fake_dns) -> None:
    result = DnsRecordsModule().run(make_context("example.com"))

    titles = " ".join(finding.title for finding in result.findings)
    assert "+all" in titles
    assert "p=none" in titles
    for finding in result.findings:
        assert finding.limitations  # every interpretation states its limits


def test_dns_lookup_failure_is_partial(make_context, monkeypatch) -> None:
    def boom(name: str, rdtype: str, timeout: float = 5.0):
        raise dns_records.DnsLookupError("resolver unreachable")

    monkeypatch.setattr(dns_records, "resolve_records", boom)

    result = DnsRecordsModule().run(make_context("example.com"))

    assert result.status is RunStatus.PARTIAL
    assert result.errors


# -- reverse DNS ------------------------------------------------------------
def test_reverse_dns_and_network_context(make_context, monkeypatch) -> None:
    zone = {
        ("10.113.0.203.in-addr.arpa", "PTR"): ["host.provider.example."],
        ("10.113.0.203.origin.asn.cymru.com", "TXT"): ['"64500 | 203.0.113.0/24 | AU | apnic | 2020-01-01"'],
        ("AS64500.asn.cymru.com", "TXT"): ['"64500 | AU | apnic | 2020-01-01 | EXAMPLE-NET, AU"'],
    }

    def resolve(name: str, rdtype: str, timeout: float = 5.0) -> list[str]:
        return list(zone.get((name, rdtype), []))

    monkeypatch.setattr(reverse_dns.dns_records, "resolve_records", resolve)

    result = ReverseDnsModule().run(make_context("203.0.113.10"))

    values = {(o.type, o.normalized_value) for o in result.observations}
    assert ("dns.ptr", "host.provider.example") in values
    assert ("network.prefix", "203.0.113.0/24") in values
    assert any(o.type == "network.asn" and "EXAMPLE-NET" in o.normalized_value
               for o in result.observations)


# -- certificate transparency ----------------------------------------------
@respx.mock
def test_ct_records_hostnames_as_assets_only(make_context) -> None:
    payload = [
        {"name_value": "www.example.com\nshop.example.com", "issuer_name": "CN=Test CA"},
        {"name_value": "*.example.com", "issuer_name": "CN=Test CA"},
        {"name_value": "unrelated.test", "issuer_name": "CN=Test CA"},
    ]
    respx.get(url__regex=rf"{PROVIDER}/\?q=.*").mock(
        return_value=httpx.Response(200, text=json.dumps(payload))
    )
    context = make_context("example.com", params={"use_external_tools": False})

    result = CtSubdomainsModule().run(context)

    discovered = {asset.value for asset in result.discovered_assets}
    assert discovered == {"www.example.com", "shop.example.com"}
    assert all(asset.kind is AssetKind.HOST for asset in result.discovered_assets)
    assert "unrelated.test" not in discovered
    assert any("wildcard" in warning for warning in result.warnings)
    assert result.metrics["requests"] == 0  # the target is never contacted


# -- TLS certificate --------------------------------------------------------
def _self_signed(host: str, days_valid: int = 200, hash_name: str = "sha256"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    algorithm = hashes.SHA256() if hash_name == "sha256" else hashes.SHA1()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName(f"vpn.{host}")]),
            critical=False,
        )
        .sign(key, algorithm)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_tls_cert_reads_the_certificate_and_flags_self_signed(
    make_context, client_factory, monkeypatch
) -> None:
    der = _self_signed("example.com")

    def fake_fetch(host, address, port=443, timeout=10.0):
        assert address == "203.0.113.10"  # the pinned address, not a fresh lookup
        return CertificateFetch(
            der=der,
            verified=False,
            verify_error="self signed certificate",
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            connections=2,
        )

    from recon_helper_pro.modules.osint import tls_cert

    monkeypatch.setattr(tls_cert, "fetch_certificate", fake_fetch)
    context = make_context("example.com", http=client_factory())

    result = TlsCertificateModule().run(context)

    values = {(o.type, o.normalized_value) for o in result.observations}
    assert ("tls.version", "TLSv1.3") in values
    assert ("tls.validation", "not trusted") in values
    assert ("tls.san", "vpn.example.com") in values
    assert any("self-signed" in finding.title for finding in result.findings)
    assert result.metrics["requests"] == 2
    assert {asset.value for asset in result.discovered_assets} == {
        "example.com",
        "vpn.example.com",
    }


def test_tls_cert_flags_expiry(make_context, client_factory, monkeypatch) -> None:
    der = _self_signed("example.com", days_valid=5)

    from recon_helper_pro.modules.osint import tls_cert

    monkeypatch.setattr(
        tls_cert,
        "fetch_certificate",
        lambda host, address, port=443, timeout=10.0: CertificateFetch(
            der=der, verified=True, tls_version="TLSv1.3", connections=1
        ),
    )

    result = TlsCertificateModule().run(make_context("example.com", http=client_factory()))

    assert any("expires in" in finding.title for finding in result.findings)


def test_tls_cert_refuses_a_blocked_address(make_context, client_factory) -> None:
    from recon_helper_pro.core.errors import ScopeBlocked

    context = make_context("example.com", http=client_factory("169.254.169.254"))

    with pytest.raises(ScopeBlocked):
        TlsCertificateModule().run(context)


def test_reverse_dns_without_addresses_is_partial(make_context, monkeypatch) -> None:
    monkeypatch.setattr(
        reverse_dns.dns_records, "resolve_records", lambda name, rdtype, timeout=5.0: []
    )
    result = ReverseDnsModule().run(make_context("example.com"))
    assert result.status is RunStatus.PARTIAL


def test_normalize_helpers_used_by_revdns() -> None:
    assert reverse_dns._cymru_query_name(ipaddress.ip_address("203.0.113.10")).endswith(
        "origin.asn.cymru.com"
    )
