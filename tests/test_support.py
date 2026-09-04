"""Supporting machinery: optional tools, teaching content, artifacts, config."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from recon_helper_pro.core.artifacts import ArtifactStore
from recon_helper_pro.core.config import DEFAULTS, cloud_sync_warning, merged_settings, resolve_paths
from recon_helper_pro.core.errors import ConfigError
from recon_helper_pro.core.registry import RECIPE_ORDER, default_registry
from recon_helper_pro.core.teaching import TeachingLibrary, default_library
from recon_helper_pro.core.tools import run_tool


# -- optional tools ---------------------------------------------------------
def test_run_tool_reports_a_missing_binary_without_raising():
    result = run_tool("definitely-not-installed-rhp", [], ["example.com"])
    assert result.ok is False
    assert "not installed" in result.stderr


@pytest.mark.parametrize("bad", ["-oProxyCommand=x", "example.com; id", "a b"])
def test_run_tool_refuses_injected_targets(bad):
    result = run_tool("whois", [], [bad])
    assert result.ok is False
    assert result.returncode in (2, 127)


# -- teaching ---------------------------------------------------------------
def test_every_module_has_teaching_content():
    library = default_library()
    for module in default_registry().all():
        lesson = library.lesson(module.teaching_key)
        assert lesson.before, f"{module.id} has no 'before' content"
        assert lesson.after, f"{module.id} has no 'after' content"
        assert lesson.next_steps, f"{module.id} has no suggested next steps"


def test_recipe_order_matches_the_registry():
    ids = {module.id for module in default_registry().all()}
    assert set(RECIPE_ORDER) <= ids
    assert [module.id for module in default_registry().recipe()] == list(RECIPE_ORDER)


def test_glossary_lookup_is_forgiving():
    library = default_library()
    assert library.define("hsts") is not None
    assert library.define("HSTS") is not None
    assert library.define("nonexistent-term-xyz") is None
    assert "scope" in library.terms()


def test_missing_teaching_key_degrades_gracefully(tmp_path):
    library = TeachingLibrary(tmp_path)
    lesson = library.lesson("nothing_here")
    assert lesson.is_empty()
    assert lesson.title


# -- artifacts and retention ------------------------------------------------
def test_artifacts_are_content_addressed(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    stored = store.store("robots-txt", "User-agent: *\n")
    assert stored.path.exists()
    assert store.read(stored.path).decode() == "User-agent: *\n"
    assert store.store("robots-txt", "User-agent: *\n").sha256 == stored.sha256


def test_encryption_at_rest_round_trips(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts", encrypt=True, passphrase="correct horse")
    stored = store.store("secret-thing", "sensitive body")
    assert stored.encrypted is True
    assert b"sensitive body" not in stored.path.read_bytes()
    assert store.read(stored.path) == b"sensitive body"


def test_encryption_without_a_passphrase_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("RHP_PASSPHRASE", raising=False)
    with pytest.raises(ConfigError):
        ArtifactStore(tmp_path / "artifacts", encrypt=True)


def test_retention_expiry(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts", retention_days=30)
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert store.is_expired(old, "days:30") is True
    assert store.is_expired(recent, "days:30") is False
    assert store.is_expired(old, "keep") is False


def test_engine_prunes_expired_artifacts(engine, engagement):
    from recon_helper_pro.core.models import ArtifactRecord, ContactMode, Run, RunStatus

    run = engine.db.create_run(
        Run(
            id=None,
            engagement_id=engagement.id,
            module="test",
            module_version="1",
            parameters={},
            mode=ContactMode.THIRD_PARTY,
            status=RunStatus.COMPLETED,
        )
    )
    store = ArtifactStore(engine.paths.artifacts_dir)
    stored = store.store("robots-txt", "old content")
    engine.db.add_artifact(
        ArtifactRecord(
            id=None,
            run_id=run.id,
            type="robots-txt",
            path_or_blob=str(stored.path),
            sha256=stored.sha256,
            created_at=(datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
            retention_policy="days:30",
        )
    )

    assert engine.prune_artifacts(engagement.id) == 1
    assert not stored.path.exists()
    assert engine.db.artifacts_for_engagement(engagement.id) == []


def test_purge_engagement_removes_everything(engine, engagement):
    engine.purge_engagement(engagement.id)
    assert engine.db.get_engagement(engagement.id) is None


# -- config -----------------------------------------------------------------
def test_settings_defaults_and_coercion():
    settings = merged_settings({"request.delay_ms": "50", "encryption.artifacts": "true"})
    assert settings["request.delay_ms"] == 50
    assert settings["encryption.artifacts"] is True
    assert settings["verbosity"] == DEFAULTS["verbosity"]


@pytest.mark.parametrize(
    "path,expected",
    [
        ("C:/Users/x/OneDrive/rhp", True),
        ("C:/Users/x/Dropbox/data", True),
        ("C:/Users/x/AppData/Local/ReconHelperPro", False),
    ],
)
def test_cloud_sync_warning(path, expected):
    assert (cloud_sync_warning(path) is not None) is expected


def test_paths_are_created(tmp_path):
    paths = resolve_paths(tmp_path / "here").ensure()
    assert paths.artifacts_dir.exists()
    assert paths.exports_dir.exists()
    assert paths.db_path.parent.exists()
