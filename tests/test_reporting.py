"""The report must keep observations, hints and confirmations distinct."""

from __future__ import annotations

from recon_helper_pro.core.engine import Engine
from recon_helper_pro.core.models import (
    AssetKind,
    Confidence,
    ContactMode,
    DiscoveredAsset,
    Finding,
    Observation,
    PluginResult,
    SeverityHint,
)
from recon_helper_pro.core.module_base import ModuleBase, ModuleContext
from recon_helper_pro.core.registry import Registry
from recon_helper_pro.core.reporting import write_report
from recon_helper_pro.core.scope import parse_scope_entry

import pytest


class ReportingModule(ModuleBase):
    id = "reporter"
    name = "Reporting fixture"
    version = "1.2.3"
    mode = ContactMode.DIRECT_READ
    teaching_key = "headers"
    scope_requirement = "warn"
    request_budget = 2

    def run(self, context: ModuleContext) -> PluginResult:
        return PluginResult(
            observations=[
                Observation(
                    type="http.header.server",
                    normalized_value="nginx/1.18.0",
                    source_provider="HTTP response from https://example.com/",
                    dedup_key="http.header.server:example.com:nginx/1.18.0",
                    asset_value="example.com",
                    asset_kind=AssetKind.HOST,
                    evidence="Response header 'server'.",
                    confidence=Confidence.HIGH,
                )
            ],
            findings=[
                Finding(
                    title="Software version disclosed in response headers",
                    category="information-disclosure",
                    interpretation_text="The banner names an exact build.",
                    limitations="Banners can be faked; no CVE database was consulted.",
                    confidence=Confidence.HIGH,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=["http.header.server:example.com:nginx/1.18.0"],
                    asset_value="example.com",
                )
            ],
            discovered_assets=[DiscoveredAsset(AssetKind.HOST, "vpn.example.com", "from a cert")],
            metrics={"requests": 2},
        )


@pytest.fixture
def reported(tmp_path):
    engine = Engine.open(tmp_path / "data", registry=Registry([ReportingModule()]))
    engine.accept_agreement()
    engagement = engine.db.create_engagement("Report test", "an engagement for the report test")
    engine.add_scope(engagement.id, parse_scope_entry("example.com"))
    engine.run_module(engagement, "reporter", "example.com")
    report = write_report(engine.db, engine.teaching, engagement, engine.paths.exports_dir)
    yield report
    engine.close()


def test_report_is_written_to_exports(reported):
    assert reported.path is not None
    assert reported.path.exists()
    assert reported.path.suffix == ".md"
    assert reported.path.read_text(encoding="utf-8") == reported.markdown


def test_report_contains_every_required_section(reported):
    markdown = reported.markdown
    for heading in (
        "# Recon report - Report test",
        "## Methodology",
        "## Scope and exclusions",
        "## Versions and sources",
        "## Coverage",
        "## Direct-contact accounting",
        "## Assets",
        "## How to read this report",
        "## Findings",
        "## Observations",
        "## Glossary",
    ):
        assert heading in markdown, heading


def test_report_separates_observations_from_interpretations(reported):
    markdown = reported.markdown
    assert "Findings (interpretations, not confirmed vulnerabilities)" in markdown
    assert "Observations (raw facts)" in markdown
    assert "Recon Helper Pro does not confirm vulnerabilities." in markdown
    assert "**Limitations.** Banners can be faked" in markdown


def test_report_states_versions_and_provenance(reported):
    markdown = reported.markdown
    assert "reporter 1.2.3" in markdown
    assert "HTTP response from https://example.com/" in markdown
    assert "**Confidence:** high" in markdown


def test_report_accounts_for_direct_contact(reported):
    markdown = reported.markdown
    assert "2 request(s) were sent directly to targets" in markdown
    assert "| example.com | 2 | completed" in markdown.replace("  ", " ")


def test_report_documents_the_always_blocked_ranges(reported):
    assert "169.254.0.0/16" in reported.markdown
    assert "hard-blocked and were never contacted" in reported.markdown


def test_report_marks_discovered_assets_out_of_scope(reported):
    assert "vpn.example.com" in reported.markdown
    assert "recorded only" in reported.markdown.lower()
