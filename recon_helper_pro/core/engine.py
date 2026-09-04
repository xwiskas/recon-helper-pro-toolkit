"""The orchestration layer both interfaces sit on top of (PRD 9.1).

The CLI contains no recon logic and neither will the dashboard: they create an
:class:`Engine`, ask it to run modules, and render what comes back. Everything
that must not be forgotten - authorization, scope, budgets, provenance,
activity logging, partial-run semantics - happens here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from .artifacts import ArtifactStore
from .config import Paths, merged_settings, resolve_paths
from .db import Database
from .errors import (
    BudgetExceeded,
    Cancelled,
    NotAuthorizedError,
    OutOfScope,
    RHPError,
    ScopeBlocked,
)
from .httpclient import SafeHTTPClient
from .models import (
    ActivityEvent,
    ArtifactRecord,
    AssetKind,
    ContactMode,
    Engagement,
    PluginResult,
    Run,
    RunStatus,
    ScopeEntry,
    utcnow,
)
from .module_base import ModuleBase, ModuleContext
from .registry import Registry, default_registry
from .safety import AGREEMENT_VERSION, BudgetTracker, CancelToken, RateLimiter, Redactor, RequestPolicy
from .scope import Scope, ScopeDecision, normalize_hostname, split_url
from .teaching import Lesson, TeachingLibrary, default_library

ProgressSink = Callable[[str], None]


@dataclass(slots=True)
class RunOutcome:
    """Everything an interface needs to render one completed run."""

    run: Run
    result: PluginResult
    module: ModuleBase
    lesson: Lesson
    overridden: bool = False
    saved_observations: int = 0
    saved_findings: int = 0
    recorded_assets: int = 0

    @property
    def status(self) -> RunStatus:
        return self.run.status

    @property
    def requests(self) -> int:
        return self.run.request_count


@dataclass(slots=True)
class RecipeStep:
    """One step of the guided recipe, as it is about to run or after it ran."""

    index: int
    total: int
    module: ModuleBase
    lesson: Lesson
    outcome: RunOutcome | None = None
    skipped_reason: str = ""


@dataclass
class Engine:
    """Owns the database, the settings, and the safety machinery."""

    paths: Paths
    db: Database
    registry: Registry = field(default_factory=default_registry)
    teaching: TeachingLibrary = field(default_factory=default_library)
    redactor: Redactor = field(default_factory=Redactor)
    cancel: CancelToken = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.cancel is None:
            self.cancel = CancelToken(self.paths.cancel_flag)

    # -- construction -----------------------------------------------------
    @classmethod
    def open(
        cls,
        data_dir: str | Path | None = None,
        *,
        registry: Registry | None = None,
        teaching: TeachingLibrary | None = None,
    ) -> "Engine":
        paths = resolve_paths(data_dir).ensure()
        return cls(
            paths=paths,
            db=Database(paths.db_path),
            registry=registry or default_registry(),
            teaching=teaching or default_library(),
        )

    def close(self) -> None:
        self.db.close()

    # -- settings & authorization ----------------------------------------
    @property
    def settings(self) -> dict[str, Any]:
        return merged_settings(self.db.all_settings())

    def policy(self) -> RequestPolicy:
        return RequestPolicy.from_settings(self.settings)

    def is_authorized(self) -> bool:
        return self.db.accepted_version() == AGREEMENT_VERSION

    def accept_agreement(self) -> None:
        self.db.record_acceptance(AGREEMENT_VERSION)

    def require_authorization(self) -> None:
        if not self.is_authorized():
            raise NotAuthorizedError(
                "The authorization and ethics agreement has not been accepted for this version. "
                "Run 'rhp init' first."
            )

    # -- engagements & scope ---------------------------------------------
    def scope_for(self, engagement_id: int) -> Scope:
        return Scope(
            self.db.list_scope_entries(engagement_id),
            allow_private=bool(self.settings.get("lab.allow_private", True)),
        )

    def enforcement(self) -> str:
        """``warn`` (the default) allows a logged override; ``block`` never does."""
        return str(self.settings.get("scope.enforcement", "warn")).lower()

    def add_scope(self, engagement_id: int, entry: ScopeEntry) -> ScopeEntry:
        saved = self.db.add_scope_entry(engagement_id, entry)
        self._refresh_asset_scope(engagement_id)
        return saved

    def remove_scope(self, engagement_id: int, entry_id: int) -> bool:
        removed = self.db.remove_scope_entry(engagement_id, entry_id)
        if removed:
            self._refresh_asset_scope(engagement_id)
        return removed

    @staticmethod
    def _asset_in_scope(scope: Scope, kind: AssetKind, value: str) -> bool:
        """Is this recorded asset covered by the engagement scope?

        Being in scope is what makes an asset *eligible* to be contacted; it is
        never a reason to contact it automatically.
        """
        try:
            if kind is AssetKind.URL:
                scheme, host, port = split_url(value)
                return scope.check_hostname(host, scheme, port).allowed
            return scope.check_hostname(value).allowed
        except RHPError:
            return False

    def _refresh_asset_scope(self, engagement_id: int) -> None:
        scope = self.scope_for(engagement_id)
        in_scope = {
            asset.value
            for asset in self.db.list_assets(engagement_id)
            if self._asset_in_scope(scope, asset.kind, asset.value)
        }
        self.db.set_asset_scope_flags(engagement_id, in_scope)

    def preflight(self, engagement_id: int, module: ModuleBase, target: str) -> ScopeDecision | None:
        """Scope decision to show the user *before* a contacting module runs.

        Returns ``None`` when the module never contacts the target. The address
        is re-checked after resolution and on every redirect regardless of what
        this returns - this is the early, human-facing gate.
        """
        if module.scope_requirement == "none" or not module.mode.contacts_target:
            return None
        scope = self.scope_for(engagement_id)
        if "://" in target:
            scheme, host, port = split_url(target)
            decision = scope.check_hostname(host, scheme, port)
        else:
            decision = scope.check_hostname(target)
        if decision.needs_override and self.enforcement() == "block":
            return ScopeDecision(
                False,
                True,
                f"{decision.reason} Overrides are disabled because "
                "'scope.enforcement' is set to 'block'.",
            )
        return decision

    # -- running ----------------------------------------------------------
    def run_module(
        self,
        engagement: Engagement,
        module_id: str,
        target: str,
        *,
        params: dict[str, Any] | None = None,
        override_confirmed: bool = False,
        override_reason: str = "",
        progress: ProgressSink | None = None,
        cancel: CancelToken | None = None,
    ) -> RunOutcome:
        """Run one module end to end and persist everything it produced."""
        self.require_authorization()
        module = self.registry.require(module_id)
        assert engagement.id is not None
        engagement_id = engagement.id
        params = dict(params or {})
        token = cancel or self.cancel
        settings = self.settings
        policy = RequestPolicy.from_settings(settings)
        if str(settings.get("scope.enforcement", "warn")).lower() == "block":
            override_confirmed = False  # overrides are disabled outright

        run = self.db.create_run(
            Run(
                id=None,
                engagement_id=engagement_id,
                module=module.id,
                module_version=module.version,
                parameters=params,
                mode=module.mode,
                status=RunStatus.RUNNING,
                target=target,
            )
        )
        assert run.id is not None

        store = self._artifact_store(settings)
        artifact_rows: list[ArtifactRecord] = []

        def sink(artifact_type: str, content: bytes | str) -> str:
            stored = store.store(artifact_type, content)
            artifact_rows.append(
                ArtifactRecord(
                    id=None,
                    run_id=run.id or 0,
                    type=artifact_type,
                    path_or_blob=str(stored.path),
                    sha256=stored.sha256,
                    retention_policy=store.retention_policy(),
                )
            )
            return stored.sha256

        warnings_from_client: list[str] = []

        def on_event(kind: str, message: str) -> None:
            warnings_from_client.append(f"[{kind}] {message}")
            if progress:
                progress(message)

        http = None
        if module.mode.contacts_target:
            budget = BudgetTracker(
                policy=policy,
                run_budget=(
                    policy.enumerative_budget
                    if module.mode is ContactMode.ENUMERATIVE
                    else max(1, module.request_budget)
                ),
                prior_per_host=self.db.request_counts_by_host(engagement_id),
                prior_engagement_total=self.db.engagement_request_total(engagement_id),
            )
            http = SafeHTTPClient(
                policy=policy,
                scope=self.scope_for(engagement_id),
                budget=budget,
                redactor=self.redactor,
                rate_limiter=RateLimiter(policy.delay_ms, token),
                cancel=token,
                on_event=on_event,
            )
        else:
            budget = BudgetTracker(policy=policy)

        context = ModuleContext(
            engagement=engagement,
            target=target,
            params=params,
            scope=self.scope_for(engagement_id),
            policy=policy,
            settings=settings,
            redactor=self.redactor,
            http=http,
            cancel=token,
            allow_override=override_confirmed,
            store_artifact=sink,
            prior_observations=(
                self.db.observations_for_engagement(engagement_id) if module.id == "hints" else []
            ),
            progress=progress or (lambda message: None),
        )

        result = PluginResult()
        error_summary = ""
        try:
            result = module.run(context)
        except Cancelled as exc:
            result.status = RunStatus.CANCELLED
            result.warnings.append(str(exc))
        except (ScopeBlocked, OutOfScope) as exc:
            result.status = RunStatus.FAILED
            result.errors.append(str(exc))
            error_summary = str(exc)
        except BudgetExceeded as exc:
            result.status = RunStatus.PARTIAL
            result.warnings.append(str(exc))
        except RHPError as exc:
            result.status = RunStatus.FAILED
            result.errors.append(str(exc))
            error_summary = str(exc)
        except Exception as exc:  # a broken module must not abort the workflow
            result.status = RunStatus.FAILED
            result.errors.append(f"{module.id} failed unexpectedly: {exc}")
            error_summary = f"{type(exc).__name__}: {exc}"
        finally:
            if http is not None:
                http.close()

        result.warnings.extend(warnings_from_client)
        if result.errors and result.status is RunStatus.COMPLETED:
            result.status = RunStatus.PARTIAL
        if not error_summary and result.errors:
            error_summary = result.errors[0]

        requests_made = int(result.metrics.get("requests", budget.run_requests) or 0)
        saved = self._persist(engagement_id, run.id, result, module)

        self.db.finish_run(run.id, result.status, requests_made, error_summary)
        run.status = result.status
        run.request_count = requests_made
        run.ended_at = utcnow()

        for artifact in artifact_rows:
            self.db.add_artifact(artifact)

        host = self._activity_host(target)
        self.db.add_activity(
            ActivityEvent(
                id=None,
                engagement_id=engagement_id,
                module=module.id,
                mode=module.mode,
                target=host,
                request_count=requests_made,
                outcome=result.status.value,
                override_reason=override_reason if override_confirmed else "",
            )
        )
        self._refresh_asset_scope(engagement_id)

        return RunOutcome(
            run=run,
            result=result,
            module=module,
            lesson=self.teaching.lesson(module.teaching_key),
            overridden=override_confirmed,
            saved_observations=saved[0],
            saved_findings=saved[1],
            recorded_assets=saved[2],
        )

    def _activity_host(self, target: str) -> str:
        try:
            if "://" in target:
                return split_url(target)[1]
            return normalize_hostname(target)
        except RHPError:
            return target

    def _persist(
        self, engagement_id: int, run_id: int, result: PluginResult, module: ModuleBase
    ) -> tuple[int, int, int]:
        scope = self.scope_for(engagement_id)
        asset_ids: dict[str, int] = {}

        def asset_id_for(value: str | None, kind: AssetKind) -> int | None:
            if not value:
                return None
            key = f"{kind.value}:{value}"
            if key not in asset_ids:
                asset_ids[key] = self.db.upsert_asset(
                    engagement_id,
                    kind,
                    value,
                    module.id,
                    self._asset_in_scope(scope, kind, value),
                )
            return asset_ids[key]

        observations = 0
        for observation in result.observations:
            self.db.add_observation(
                run_id,
                asset_id_for(observation.asset_value, observation.asset_kind),
                observation,
            )
            observations += 1

        findings = 0
        for finding in result.findings:
            self.db.add_finding(
                engagement_id,
                run_id,
                asset_id_for(finding.asset_value, AssetKind.HOST),
                finding,
            )
            findings += 1

        assets = 0
        for discovered in result.discovered_assets:
            # Recorded only. Nothing here is ever contacted automatically.
            asset_id_for(discovered.value, discovered.kind)
            assets += 1

        return observations, findings, assets

    def _artifact_store(self, settings: dict[str, Any]) -> ArtifactStore:
        return ArtifactStore(
            self.paths.artifacts_dir,
            encrypt=bool(settings.get("encryption.artifacts", False)),
            retention_days=int(settings.get("retention.artifact_days", 30)),
        )

    # -- guided recipe ----------------------------------------------------
    def recipe_modules(self, module_ids: Sequence[str] | None = None) -> list[ModuleBase]:
        if module_ids:
            return [self.registry.require(module_id) for module_id in module_ids]
        return self.registry.recipe()

    def run_recipe(
        self,
        engagement: Engagement,
        target: str,
        *,
        module_ids: Sequence[str] | None = None,
        before_step: Callable[[RecipeStep], bool] | None = None,
        confirm: Callable[[ModuleBase, ScopeDecision], bool] | None = None,
        progress: ProgressSink | None = None,
        params: dict[str, dict[str, Any]] | None = None,
        cancel: CancelToken | None = None,
    ) -> Iterator[RecipeStep]:
        """Walk the guided recon sequence, yielding each step once it has settled.

        ``before_step`` is called with the step *before* it runs, so an interface
        can show the "what and why" panel and ask whether to continue; returning
        ``False`` skips that module. ``confirm`` is called only when the target
        is out of scope, implementing warn-but-allow.

        A module that fails yields a failed outcome and the walk continues - one
        failure never aborts the workflow (PRD 14).
        """
        self.require_authorization()
        assert engagement.id is not None
        modules = self.recipe_modules(module_ids)
        total = len(modules)
        token = cancel or self.cancel

        for index, module in enumerate(modules, start=1):
            lesson = self.teaching.lesson(module.teaching_key)
            step = RecipeStep(index=index, total=total, module=module, lesson=lesson)

            if token.is_cancelled:
                step.skipped_reason = "Cancelled by the user."
                yield step
                return

            if before_step is not None and not before_step(step):
                step.skipped_reason = "Skipped by the operator."
                yield step
                continue

            override = False
            decision = self.preflight(engagement.id, module, target)
            if decision is not None and not decision.allowed:
                if decision.blocked:
                    step.skipped_reason = decision.reason
                    yield step
                    continue
                if confirm is None or not confirm(module, decision):
                    step.skipped_reason = f"{decision.reason} No request was sent."
                    yield step
                    continue
                override = True

            step.outcome = self.run_module(
                engagement,
                module.id,
                target,
                params=(params or {}).get(module.id, {}),
                override_confirmed=override,
                override_reason="confirmed in the guided recipe" if override else "",
                progress=progress,
                cancel=token,
            )
            yield step

    # -- maintenance ------------------------------------------------------
    def prune_artifacts(self, engagement_id: int | None = None) -> int:
        """Delete artifacts past their retention window (PRD 7.6)."""
        store = self._artifact_store(self.settings)
        expired: list[int] = []
        hashes: list[str] = []
        for row in self.db.artifacts_for_engagement(engagement_id):
            if store.is_expired(str(row["created_at"]), str(row["retention_policy"])):
                store.delete(str(row["path_or_blob"]))
                expired.append(int(row["id"]))
                hashes.append(str(row["sha256"]))
        self.db.delete_artifacts(expired, hashes)
        return len(expired)

    def purge_artifacts(self, engagement_id: int | None = None) -> int:
        store = self._artifact_store(self.settings)
        rows = self.db.artifacts_for_engagement(engagement_id)
        for row in rows:
            store.delete(str(row["path_or_blob"]))
        self.db.delete_artifacts(
            [int(row["id"]) for row in rows], [str(row["sha256"]) for row in rows]
        )
        return len(rows)

    def purge_engagement(self, engagement_id: int) -> int:
        removed = self.purge_artifacts(engagement_id)
        self.db.delete_engagement(engagement_id)
        return removed

    def request_cancel(self) -> None:
        """Ask any running workflow (including another process) to stop."""
        self.paths.cancel_flag.write_text(utcnow(), encoding="utf-8")

    def clear_cancel(self) -> None:
        self.cancel.clear_flag()

    # -- small helpers used by the interfaces ------------------------------
    def module_table(self) -> list[dict[str, Any]]:
        from .tools import detect_version

        rows: list[dict[str, Any]] = []
        for module in self.registry.all():
            described = module.describe()
            described["detected_tools"] = {
                tool: detect_version(tool) for tool in module.optional_tools
            }
            rows.append(described)
        return rows

    def state(self) -> dict[str, Any]:
        try:
            return json.loads(self.paths.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def save_state(self, **values: Any) -> None:
        state = self.state()
        state.update(values)
        self.paths.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def current_engagement(self) -> Engagement | None:
        engagement_id = self.state().get("engagement_id")
        if not engagement_id:
            return None
        return self.db.get_engagement(int(engagement_id))
