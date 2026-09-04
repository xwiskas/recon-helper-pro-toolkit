"""Engine behaviour: persistence, provenance, partial runs, cancellation."""

from __future__ import annotations

import pytest

from recon_helper_pro.core.engine import Engine
from recon_helper_pro.core.errors import NotAuthorizedError
from recon_helper_pro.core.models import (
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
from recon_helper_pro.core.module_base import ModuleBase, ModuleContext
from recon_helper_pro.core.registry import Registry
from recon_helper_pro.core.scope import parse_scope_entry


class GoodModule(ModuleBase):
    id = "good"
    name = "Good module"
    version = "2.1.0"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "dns"
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        context.emit("working")
        return PluginResult(
            observations=[
                Observation(
                    type="test.fact",
                    normalized_value="a fact",
                    source_provider="unit test",
                    dedup_key="test.fact:example.com",
                    asset_value="example.com",
                    asset_kind=AssetKind.DOMAIN,
                    evidence="made up for the test",
                    confidence=Confidence.HIGH,
                )
            ],
            findings=[
                Finding(
                    title="A hint",
                    category="test",
                    interpretation_text="Something might be true.",
                    limitations="It might not be.",
                    confidence=Confidence.LOW,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=["test.fact:example.com"],
                    asset_value="example.com",
                )
            ],
            discovered_assets=[
                DiscoveredAsset(AssetKind.HOST, "found.example.net", "recorded only")
            ],
            metrics={"requests": 0},
        )


class BrokenModule(ModuleBase):
    id = "broken"
    name = "Broken module"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "dns"
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        raise ValueError("this module is buggy")


class ContactingModule(ModuleBase):
    id = "contacting"
    name = "Contacting module"
    mode = ContactMode.DIRECT_READ
    teaching_key = "headers"
    scope_requirement = "warn"
    request_budget = 1

    def run(self, context: ModuleContext) -> PluginResult:
        return PluginResult(metrics={"requests": 3})


class SlowModule(ModuleBase):
    id = "slow"
    name = "Cancellable module"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "dns"
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        context.cancel.cancel()
        context.cancel.raise_if_cancelled()
        return PluginResult()


@pytest.fixture
def test_engine(tmp_path):
    registry = Registry([GoodModule(), BrokenModule(), ContactingModule(), SlowModule()])
    engine = Engine.open(tmp_path / "data", registry=registry)
    engine.accept_agreement()
    yield engine
    engine.close()


@pytest.fixture
def test_engagement(test_engine):
    engagement = test_engine.db.create_engagement("Engine test")
    test_engine.add_scope(engagement.id, parse_scope_entry("example.com"))
    return engagement


def test_authorization_is_required(tmp_path):
    engine = Engine.open(tmp_path / "unaccepted", registry=Registry([GoodModule()]))
    engagement = engine.db.create_engagement("x")
    with pytest.raises(NotAuthorizedError):
        engine.run_module(engagement, "good", "example.com")
    engine.close()


def test_a_run_persists_everything_with_provenance(test_engine, test_engagement):
    outcome = test_engine.run_module(test_engagement, "good", "example.com")

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.saved_observations == 1
    assert outcome.saved_findings == 1

    stored = test_engine.db.observations_for_engagement(test_engagement.id)
    assert stored[0]["source_provider"] == "unit test"
    assert stored[0]["module"] == "good"
    assert stored[0]["module_version"] == "2.1.0"
    assert stored[0]["collected_at"]
    assert stored[0]["confidence"] == "high"

    runs = test_engine.db.list_runs(test_engagement.id)
    assert runs[0].module_version == "2.1.0"
    assert runs[0].ended_at is not None


def test_discovered_assets_are_recorded_but_not_in_scope(test_engine, test_engagement):
    test_engine.run_module(test_engagement, "good", "example.com")

    assets = {asset.value: asset for asset in test_engine.db.list_assets(test_engagement.id)}
    assert assets["example.com"].in_scope is True
    assert assets["found.example.net"].in_scope is False


def test_adding_scope_updates_the_in_scope_flag(test_engine, test_engagement):
    test_engine.run_module(test_engagement, "good", "example.com")
    test_engine.add_scope(test_engagement.id, parse_scope_entry("found.example.net"))

    assets = {asset.value: asset for asset in test_engine.db.list_assets(test_engagement.id)}
    assert assets["found.example.net"].in_scope is True


def test_a_broken_module_produces_a_failed_run_not_a_crash(test_engine, test_engagement):
    outcome = test_engine.run_module(test_engagement, "broken", "example.com")

    assert outcome.status is RunStatus.FAILED
    assert "buggy" in outcome.result.errors[0]
    run = test_engine.db.list_runs(test_engagement.id)[0]
    assert run.status is RunStatus.FAILED
    assert run.error_summary


def test_activity_log_records_requests_and_overrides(test_engine, test_engagement):
    test_engine.run_module(
        test_engagement,
        "contacting",
        "out-of-scope.test",
        override_confirmed=True,
        override_reason="confirmed in a test",
    )

    events = test_engine.db.list_activity(test_engagement.id)
    assert events[0]["module"] == "contacting"
    assert events[0]["mode"] == "direct-read"
    assert events[0]["request_count"] == 3
    assert events[0]["override_reason"] == "confirmed in a test"


def test_request_totals_accumulate_for_the_ceilings(test_engine, test_engagement):
    for _ in range(3):
        test_engine.run_module(test_engagement, "contacting", "example.com")

    assert test_engine.db.engagement_request_total(test_engagement.id) == 9
    assert test_engine.db.request_counts_by_host(test_engagement.id)["example.com"] == 9


def test_preflight_reports_scope_state(test_engine, test_engagement):
    module = test_engine.registry.require("contacting")

    assert test_engine.preflight(test_engagement.id, module, "example.com").allowed is True

    outside = test_engine.preflight(test_engagement.id, module, "other.test")
    assert outside.allowed is False and outside.needs_override is True

    blocked = test_engine.preflight(test_engagement.id, module, "169.254.169.254")
    assert blocked.blocked is True

    # A module that never contacts the target has no scope question to answer.
    assert test_engine.preflight(test_engagement.id, test_engine.registry.require("good"), "x") is None


def test_cancellation_is_recorded_and_keeps_partial_work(test_engine, test_engagement):
    outcome = test_engine.run_module(test_engagement, "slow", "example.com")

    assert outcome.status is RunStatus.CANCELLED
    assert test_engine.db.list_runs(test_engagement.id)[0].status is RunStatus.CANCELLED


def test_cancel_flag_stops_a_recipe(test_engine, test_engagement):
    test_engine.request_cancel()
    steps = list(
        test_engine.run_recipe(
            test_engagement, "example.com", module_ids=["good", "good"]
        )
    )
    assert steps[0].outcome is None
    assert "Cancelled" in steps[0].skipped_reason
    test_engine.clear_cancel()


def test_recipe_continues_past_a_failure(test_engine, test_engagement):
    steps = list(
        test_engine.run_recipe(
            test_engagement, "example.com", module_ids=["broken", "good"]
        )
    )

    assert [step.module.id for step in steps] == ["broken", "good"]
    assert steps[0].outcome.status is RunStatus.FAILED
    assert steps[1].outcome.status is RunStatus.COMPLETED


def test_recipe_skips_an_out_of_scope_step_when_not_confirmed(test_engine, test_engagement):
    steps = list(
        test_engine.run_recipe(
            test_engagement,
            "not-in-scope.test",
            module_ids=["contacting"],
            confirm=lambda module, decision: False,
        )
    )

    assert steps[0].outcome is None
    assert "No request was sent" in steps[0].skipped_reason
    assert test_engine.db.list_runs(test_engagement.id) == []


def test_recipe_before_step_can_skip(test_engine, test_engagement):
    steps = list(
        test_engine.run_recipe(
            test_engagement,
            "example.com",
            module_ids=["good"],
            before_step=lambda step: False,
        )
    )
    assert steps[0].skipped_reason == "Skipped by the operator."


def test_settings_round_trip(test_engine):
    assert test_engine.settings["request.delay_ms"] == 1000
    test_engine.db.set_setting("request.delay_ms", "250")
    assert test_engine.settings["request.delay_ms"] == 250
    test_engine.db.set_setting("lab.allow_private", "false")
    assert test_engine.settings["lab.allow_private"] is False


def test_lab_mode_off_blocks_private_targets(test_engine, test_engagement):
    module = test_engine.registry.require("contacting")
    assert test_engine.preflight(test_engagement.id, module, "192.168.1.10").blocked is False

    test_engine.db.set_setting("lab.allow_private", "false")
    decision = test_engine.preflight(test_engagement.id, module, "192.168.1.10")
    assert decision.blocked is True
    assert "lab mode is off" in decision.reason


def test_block_enforcement_removes_the_override(test_engine, test_engagement):
    module = test_engine.registry.require("contacting")
    assert test_engine.preflight(test_engagement.id, module, "other.test").needs_override is True

    test_engine.db.set_setting("scope.enforcement", "block")
    decision = test_engine.preflight(test_engagement.id, module, "other.test")
    assert decision.blocked is True
    assert "Overrides are disabled" in decision.reason
