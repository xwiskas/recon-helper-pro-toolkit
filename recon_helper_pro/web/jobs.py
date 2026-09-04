"""Background jobs for the dashboard.

A recon run takes minutes and must be watchable and cancellable from the
browser, so runs happen on a worker thread and the page polls for progress.

Only one job runs at a time. That is deliberate: it keeps the single-writer
discipline on SQLite simple, and it makes the request budgets meaningful - two
concurrent workflows against the same host would quietly double the load.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core.engine import Engine, RecipeStep
from ..core.errors import RHPError
from ..core.models import Engagement, RunStatus
from ..core.safety import CancelToken

MAX_MESSAGES = 2000


@dataclass
class Job:
    """One background workflow and everything the UI needs to render it."""

    id: str
    kind: str
    target: str
    engagement_id: int
    status: str = "running"  # running | completed | failed | cancelled
    messages: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    cancel: CancelToken = field(default_factory=CancelToken)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def log(self, message: str) -> None:
        with self._lock:
            if len(self.messages) < MAX_MESSAGES:
                self.messages.append(message)

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.results.append(entry)

    def snapshot(self, cursor: int = 0) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "target": self.target,
                "status": self.status,
                "error": self.error,
                "cursor": len(self.messages),
                "messages": self.messages[cursor:],
                "results": list(self.results),
                "finished": self.status != "running",
            }


class JobBusy(RHPError):
    """A job is already running; the dashboard runs one workflow at a time."""


class JobManager:
    """Owns the single worker slot and the job history for this session."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._current: str | None = None
        self._lock = threading.Lock()

    # -- inspection -------------------------------------------------------
    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def current(self) -> Job | None:
        with self._lock:
            return self._jobs.get(self._current) if self._current else None

    def is_busy(self) -> bool:
        job = self.current()
        return job is not None and job.status == "running"

    # -- lifecycle --------------------------------------------------------
    def _start(self, job: Job, work: Callable[[Job], None]) -> Job:
        with self._lock:
            running = self._jobs.get(self._current) if self._current else None
            if running is not None and running.status == "running":
                raise JobBusy(
                    "A run is already in progress. Wait for it to finish, or cancel it first - "
                    "the dashboard deliberately runs one workflow at a time."
                )
            self._jobs[job.id] = job
            self._current = job.id

        def runner() -> None:
            try:
                work(job)
                job.status = "cancelled" if job.cancel.is_cancelled else "completed"
            except RHPError as exc:
                job.status = "failed"
                job.error = str(exc)
                job.log(f"Stopped: {exc}")
            except Exception as exc:  # a bug here must not kill the server
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.log("The run stopped unexpectedly. See the server log for details.")
                traceback.print_exc()

        threading.Thread(target=runner, name=f"rhp-job-{job.id}", daemon=True).start()
        return job

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.status != "running":
            return False
        job.cancel.cancel()
        job.log("Cancellation requested. Work already collected is kept.")
        return True

    # -- the two kinds of work --------------------------------------------
    def start_module(
        self,
        engine: Engine,
        engagement: Engagement,
        module_id: str,
        target: str,
        *,
        params: dict[str, Any] | None = None,
        override: bool = False,
    ) -> Job:
        job = Job(id=uuid.uuid4().hex, kind="module", target=target,
                  engagement_id=int(engagement.id or 0))

        def work(current: Job) -> None:
            module = engine.registry.require(module_id)
            current.log(f"Running {module.name} against {target}")
            outcome = engine.run_module(
                engagement,
                module_id,
                target,
                params=params or {},
                override_confirmed=override,
                override_reason="confirmed in the dashboard" if override else "",
                progress=current.log,
                cancel=current.cancel,
            )
            current.record(_outcome_entry(outcome))
            current.log(f"{module.id}: {outcome.status.value}")

        return self._start(job, work)

    def start_recipe(
        self,
        engine: Engine,
        engagement: Engagement,
        target: str,
        *,
        module_ids: list[str] | None = None,
        override: bool = False,
    ) -> Job:
        job = Job(id=uuid.uuid4().hex, kind="recipe", target=target,
                  engagement_id=int(engagement.id or 0))

        def work(current: Job) -> None:
            def before(step: RecipeStep) -> bool:
                current.log(f"Step {step.index}/{step.total}: {step.module.name}")
                return True

            def confirm(module: Any, decision: Any) -> bool:
                if override:
                    current.log(f"Override confirmed for {module.id}: {decision.reason}")
                    return True
                return False

            for step in engine.run_recipe(
                engagement,
                target,
                module_ids=module_ids,
                before_step=before,
                confirm=confirm,
                progress=current.log,
                cancel=current.cancel,
            ):
                if step.outcome is None:
                    current.record(
                        {
                            "module": step.module.id,
                            "name": step.module.name,
                            "mode": step.module.mode.value,
                            "status": "skipped",
                            "skipped_reason": step.skipped_reason,
                        }
                    )
                    current.log(f"Skipped {step.module.id}: {step.skipped_reason}")
                else:
                    current.record(_outcome_entry(step.outcome))
                    current.log(f"{step.module.id}: {step.outcome.status.value}")

        return self._start(job, work)


def _outcome_entry(outcome: Any) -> dict[str, Any]:
    return {
        "module": outcome.module.id,
        "name": outcome.module.name,
        "mode": outcome.module.mode.value,
        "status": outcome.status.value,
        "observations": outcome.saved_observations,
        "findings": outcome.saved_findings,
        "assets": outcome.recorded_assets,
        "requests": outcome.requests,
        "warnings": list(outcome.result.warnings),
        "errors": list(outcome.result.errors),
        "failed": outcome.status is RunStatus.FAILED,
        "skipped_reason": "",
    }
