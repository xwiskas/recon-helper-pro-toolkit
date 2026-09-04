"""End-to-end CLI tests, including the golden path, with no live network."""

from __future__ import annotations

import ipaddress
import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from recon_helper_pro.cli import main as cli
from recon_helper_pro.core import httpclient
from recon_helper_pro.modules.osint import dns_records, tls_cert
from recon_helper_pro.modules.osint.tls_cert import CertificateFetch

TARGET_ADDRESS = "203.0.113.10"
PROVIDER_ADDRESS = "93.184.216.34"
PROVIDER_HOSTS = {"rdap.org", "crt.sh"}

runner = CliRunner()


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """A clean CLI state pointed at a throwaway data directory."""
    cli.STATE.update({"data_dir": None, "verbosity": None, "engine": None})
    monkeypatch.setenv("RHP_DATA_DIR", str(tmp_path / "data"))
    yield tmp_path
    engine = cli.STATE.get("engine")
    if engine is not None:
        engine.close()
    cli.STATE.update({"data_dir": None, "verbosity": None, "engine": None})


@pytest.fixture
def offline(monkeypatch):
    """Pin every hostname and stub out DNS and TLS."""

    def resolver(host: str, port: int) -> list:
        address = PROVIDER_ADDRESS if host in PROVIDER_HOSTS else TARGET_ADDRESS
        return [ipaddress.ip_address(address)]

    monkeypatch.setattr(httpclient, "system_resolver", resolver)

    zone = {
        ("example.com", "A"): ["203.0.113.10"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "NS"): ["ns1.example.net."],
        ("example.com", "TXT"): ['"v=spf1 -all"'],
        ("example.com", "SOA"): ["ns1.example.net. hostmaster.example.com. 1 2 3 4 5"],
        ("10.113.0.203.in-addr.arpa", "PTR"): ["host.provider.example."],
    }
    monkeypatch.setattr(
        dns_records,
        "resolve_records",
        lambda name, rdtype, timeout=5.0: list(zone.get((name, rdtype), [])),
    )
    monkeypatch.setattr(
        tls_cert,
        "fetch_certificate",
        lambda host, address, port=443, timeout=10.0: CertificateFetch(
            der=_certificate(host), verified=True, tls_version="TLSv1.3", connections=1
        ),
    )


def _certificate(host: str) -> bytes:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=200))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def invoke(*args: str):
    return runner.invoke(cli.app, list(args))


def bootstrap() -> None:
    assert invoke("init", "--accept").exit_code == 0
    assert invoke("engagement", "new", "CLI test").exit_code == 0
    assert invoke("scope", "add", "example.com").exit_code == 0


def test_init_records_acceptance_and_is_idempotent(cli_env):
    first = invoke("init", "--accept")
    assert first.exit_code == 0
    assert "Accepted and recorded" in first.stdout

    second = invoke("init")
    assert second.exit_code == 0
    assert "already accepted" in second.stdout


def test_engagement_and_scope_lifecycle(cli_env):
    bootstrap()

    listing = invoke("engagement", "list")
    assert "CLI test" in listing.stdout
    assert "(current)" in listing.stdout

    scope = invoke("scope", "list")
    assert "example.com" in scope.stdout
    assert "169.254.0.0/16" in scope.stdout  # the always-blocked note

    assert invoke("scope", "add", "not a host").exit_code != 0
    assert invoke("scope", "remove", "1").exit_code == 0


def test_running_a_module_requires_acceptance(cli_env):
    result = invoke("run", "dns", "example.com")
    assert result.exit_code != 0


def test_out_of_scope_target_is_refused_without_confirmation(cli_env):
    bootstrap()
    result = runner.invoke(cli.app, ["run", "headers", "elsewhere.test"], input="n\n")
    assert result.exit_code == 4
    assert "Out of scope" in result.stdout


def test_blocked_target_can_never_be_run(cli_env):
    bootstrap()
    result = invoke("run", "cert", "169.254.169.254")
    assert result.exit_code == 3
    assert "link-local" in result.stdout + result.stderr


@respx.mock
def test_golden_path_end_to_end(cli_env, offline):
    """rhp init -> engagement -> scope -> recon -> report, with no live services."""
    respx.route(method="GET", host=PROVIDER_ADDRESS, path="/domain/example.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "ldhName": "example.com",
                "status": ["client transfer prohibited"],
                "events": [{"eventAction": "registration", "eventDate": "2005-04-12T00:00:00Z"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
                "nameservers": [{"ldhName": "ns1.example.net"}],
            },
        )
    )
    respx.route(method="GET", host=PROVIDER_ADDRESS, path="/").mock(
        return_value=httpx.Response(
            200,
            text=json.dumps(
                [{"name_value": "www.example.com\nstaging.example.com", "issuer_name": "CN=CA"}]
            ),
        )
    )

    def target(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin/\n")
        if request.url.path in ("/", "/index.html"):
            return httpx.Response(
                200,
                headers={"server": "nginx/1.18.0"},
                text="<html><title>Example</title></html>",
            )
        return httpx.Response(404)

    respx.route(method="GET", host=TARGET_ADDRESS).mock(side_effect=target)

    bootstrap()
    result = invoke("--verbosity", "normal", "recon", "example.com", "--non-interactive")

    assert result.exit_code == 0, result.stdout
    assert "Recon complete" in result.stdout
    assert "Report written" in result.stdout

    exports = list((cli_env / "data" / "exports").glob("*.md"))
    assert len(exports) == 1
    report = exports[0].read_text(encoding="utf-8")
    assert "## Findings (interpretations, not confirmed vulnerabilities)" in report
    assert "## Observations (raw facts)" in report
    assert "Example Registrar" in report
    assert "staging.example.com" in report

    assets = invoke("assets")
    assert "staging.example.com" in assets.stdout
    findings = invoke("findings")
    assert "severity hint" in findings.stdout.lower()
    runs = invoke("runs")
    assert "completed" in runs.stdout
    activity = invoke("activity")
    assert "Activity - CLI test" in activity.stdout
    # Rich truncates columns to the test terminal width, so check the record itself.
    events = cli.STATE["engine"].db.list_activity(1)
    assert {event["mode"] for event in events} >= {"third-party", "direct-read", "enumerative"}
    assert any(event["request_count"] > 0 for event in events)


def test_define_and_modules_and_version(cli_env):
    bootstrap()
    assert "Autonomous System Number" in invoke("define", "asn").stdout
    assert invoke("define", "not-a-real-term").exit_code != 0
    assert "third-party" in invoke("modules").stdout
    assert "Recon Helper Pro" in invoke("version").stdout


def test_config_set_and_reset(cli_env):
    bootstrap()
    assert invoke("config", "set", "request.delay_ms", "250").exit_code == 0
    assert "250" in invoke("config", "list").stdout
    assert invoke("config", "set", "not.a.setting", "x").exit_code != 0
    assert invoke("config", "reset", "request.delay_ms").exit_code == 0


def test_cancel_and_purge(cli_env):
    bootstrap()
    assert invoke("cancel").exit_code == 0
    purge = invoke("purge", "--artifacts-only", "--yes")
    assert purge.exit_code == 0
    assert "Deleted" in purge.stdout


def test_web_command_launches_the_loopback_dashboard(cli_env, monkeypatch):
    """The command wires through to serve() - it is not started for real here."""
    from recon_helper_pro.web import server as web_server

    captured: dict = {}
    monkeypatch.setattr(
        web_server, "serve", lambda engine, **kwargs: captured.update(kwargs)
    )
    bootstrap()

    result = invoke("web", "--port", "9999", "--no-open")

    assert result.exit_code == 0
    assert captured == {"host": "127.0.0.1", "port": 9999, "open_browser": False}


def test_web_command_refuses_a_non_loopback_bind(cli_env):
    bootstrap()
    result = invoke("web", "--host", "0.0.0.0", "--no-open")
    assert result.exit_code == 2
    assert "loopback-only" in result.stdout + (result.stderr or "")
