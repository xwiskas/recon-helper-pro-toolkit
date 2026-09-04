"""Web modules against mocked responses, including hostile content."""

from __future__ import annotations

import httpx
import respx

from recon_helper_pro.core.models import RunStatus
from recon_helper_pro.modules.web.hints import HintsModule
from recon_helper_pro.modules.web.http_headers import HttpHeadersModule
from recon_helper_pro.modules.web.published_files import PublishedFilesModule, parse_robots
from recon_helper_pro.modules.web.tech_fingerprint import TechFingerprintModule

PINNED_HOST = "203.0.113.10"

BARE_HEADERS = {"server": "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24"}
HARDENED_HEADERS = {
    "server": "nginx",
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


@respx.mock
def test_headers_module_records_and_interprets(make_context, client_factory) -> None:
    respx.route(method="GET", host=PINNED_HOST).mock(
        return_value=httpx.Response(
            200,
            headers=[
                *BARE_HEADERS.items(),
                ("set-cookie", "PHPSESSID=abc123; Path=/"),
            ],
            text="<html><title>Hello</title></html>",
        )
    )

    result = HttpHeadersModule().run(make_context("example.com", http=client_factory()))

    assert result.status is RunStatus.COMPLETED
    types = {observation.type for observation in result.observations}
    assert "http.status" in types
    assert "http.resolved_address" in types
    assert "http.header.server" in types

    titles = " ".join(finding.title for finding in result.findings)
    assert "Strict-Transport-Security" in titles
    assert "Content-Security-Policy" in titles
    assert "version" in titles.lower()
    assert all(finding.limitations for finding in result.findings)
    # No finding is allowed to claim a confirmed vulnerability.
    assert not any("vulnerable" in finding.title.lower() for finding in result.findings)


@respx.mock
def test_hardened_site_produces_no_header_findings(make_context, client_factory) -> None:
    respx.route(method="GET", host=PINNED_HOST).mock(
        return_value=httpx.Response(200, headers=HARDENED_HEADERS, text="ok")
    )

    result = HttpHeadersModule().run(make_context("example.com", http=client_factory()))

    titles = " ".join(finding.title for finding in result.findings)
    assert "Strict-Transport-Security" not in titles
    assert "clickjacking" not in titles


@respx.mock
def test_headers_module_falls_back_from_https_to_http(make_context, client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, headers={"server": "nginx"}, text="ok")

    respx.route(method="GET", host=PINNED_HOST).mock(side_effect=handler)

    result = HttpHeadersModule().run(make_context("example.com", http=client_factory()))

    assert result.status is RunStatus.COMPLETED
    assert any("trying HTTP instead" in warning for warning in result.warnings)


@respx.mock
def test_cors_wildcard_with_credentials_is_flagged(make_context, client_factory) -> None:
    respx.route(method="GET", host=PINNED_HOST).mock(
        return_value=httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
        )
    )

    result = HttpHeadersModule().run(make_context("example.com", http=client_factory()))

    assert any("CORS" in finding.title for finding in result.findings)


# -- fingerprinting ---------------------------------------------------------
@respx.mock
def test_fingerprint_matches_bundled_signatures(make_context, client_factory) -> None:
    html = (
        "<html><head><title>Blog</title>"
        "<meta name='generator' content='WordPress 6.4.2'></head>"
        "<body><link href='/wp-content/themes/x/style.css'></body></html>"
    )
    respx.route(method="GET", host=PINNED_HOST).mock(
        return_value=httpx.Response(200, headers={"server": "nginx/1.18.0"}, text=html)
    )

    result = TechFingerprintModule().run(make_context("example.com", http=client_factory()))

    values = {observation.normalized_value for observation in result.observations}
    assert any(value.startswith("WordPress") for value in values)
    assert "nginx 1.18.0" in values
    assert any(observation.type == "web.title" for observation in result.observations)
    assert all(observation.evidence for observation in result.observations)


@respx.mock
def test_fingerprint_survives_hostile_html(make_context, client_factory) -> None:
    """Target-controlled content must never break the run."""
    html = "<html><title>" + "<script>alert(1)</script>" * 50 + "</title><body>" + "<" * 500
    respx.route(method="GET", host=PINNED_HOST).mock(
        return_value=httpx.Response(200, text=html)
    )

    result = TechFingerprintModule().run(make_context("example.com", http=client_factory()))

    assert result.status is not RunStatus.FAILED


# -- published files --------------------------------------------------------
ROBOTS = """\
User-agent: *
Disallow: /admin/
Disallow: /backup/
Sitemap: https://example.com/sitemap.xml
"""


@respx.mock
def test_published_files_respects_robots_and_records_hints(make_context, client_factory) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS)
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:security@example.com\n")
        return httpx.Response(404)

    respx.route(method="GET", host=PINNED_HOST).mock(side_effect=handler)

    result = PublishedFilesModule().run(make_context("example.com", http=client_factory()))

    assert "/robots.txt" in requested
    assert "/admin/" not in requested  # disallowed paths are never requested
    titles = " ".join(finding.title for finding in result.findings)
    assert "sound sensitive" in titles
    assert "security.txt" in titles
    assert result.metrics["requests"] == len(requested)


@respx.mock
def test_published_files_skips_disallowed_standard_paths(make_context, client_factory) -> None:
    robots = "User-agent: *\nDisallow: /sitemap.xml\n"
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=robots)
        return httpx.Response(404)

    respx.route(method="GET", host=PINNED_HOST).mock(side_effect=handler)

    result = PublishedFilesModule().run(make_context("example.com", http=client_factory()))

    assert "/sitemap.xml" not in requested
    assert any("robots.txt disallows it" in warning for warning in result.warnings)
    assert result.metrics["paths_skipped"] == 1


@respx.mock
def test_directory_listing_is_flagged_as_a_hint(make_context, client_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text="<title>Index of /</title>")
        return httpx.Response(404)

    respx.route(method="GET", host=PINNED_HOST).mock(side_effect=handler)

    result = PublishedFilesModule().run(make_context("example.com", http=client_factory()))

    finding = next(f for f in result.findings if "Directory listing" in f.title)
    assert finding.confidence.value == "medium"
    assert "confirm" in finding.limitations.lower()


def test_parse_robots_handles_comments_and_groups() -> None:
    text = (
        "# comment\n"
        "User-agent: BadBot\nDisallow: /\n\n"
        "User-agent: *\nDisallow: /private/\nSitemap: https://example.com/s.xml\n"
    )
    rules, sitemaps = parse_robots(text, "ReconHelperPro/0.1")
    assert rules == ["/private/"]
    assert sitemaps == ["https://example.com/s.xml"]


# -- hints ------------------------------------------------------------------
def test_hints_interprets_stored_observations(make_context) -> None:
    prior = [
        {"type": "http.status", "normalized_value": "200", "dedup_key": "http.status:example.com:200"},
        {
            "type": "http.header.server",
            "normalized_value": "Apache/2.4.29",
            "dedup_key": "http.header.server:example.com:Apache/2.4.29",
        },
        {
            "type": "hostname.discovered",
            "normalized_value": "staging.example.com",
            "dedup_key": "hostname.discovered:staging.example.com",
        },
        {"type": "dns.mx", "normalized_value": "10 mail.example.com", "dedup_key": "dns.mx:1"},
    ]

    result = HintsModule().run(make_context("example.com", prior_observations=prior))

    titles = " ".join(finding.title for finding in result.findings)
    assert "hardening" in titles
    assert "non-production" in titles
    assert "SPF" in titles
    assert result.metrics["requests"] == 0
    for finding in result.findings:
        assert finding.limitations


def test_hints_with_nothing_collected_is_partial(make_context) -> None:
    result = HintsModule().run(make_context("example.com"))
    assert result.status is RunStatus.PARTIAL
