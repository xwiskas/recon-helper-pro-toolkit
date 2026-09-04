"""The dashboard's JSON API.

Small on purpose: starting work, watching it, and cancelling it. Everything the
page renders as HTML is rendered server-side by :mod:`server`, so there is no
client-side templating and no place for target-controlled text to become markup.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..core.engine import Engine
from ..core.errors import RHPError, ScopeError
from .jobs import JobBusy, JobManager


class RunRequest(BaseModel):
    module: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    override: bool = False


class RecipeRequest(BaseModel):
    target: str
    modules: list[str] | None = None
    override: bool = False


def build_api(engine: Engine, jobs: JobManager) -> APIRouter:
    router = APIRouter(prefix="/api")

    def _engagement(engagement_id: int):
        engagement = engine.db.get_engagement(engagement_id)
        if engagement is None:
            raise HTTPException(status_code=404, detail="No such engagement.")
        return engagement

    @router.get("/status")
    def status() -> dict[str, Any]:
        current = jobs.current()
        engagement = engine.current_engagement()
        return {
            "authorized": engine.is_authorized(),
            "engagement_id": engagement.id if engagement else None,
            "busy": jobs.is_busy(),
            "job_id": current.id if current else None,
        }

    @router.get("/preflight")
    def preflight(engagement_id: int, module: str, target: str) -> dict[str, Any]:
        """What the scope says about this target, before anything is sent."""
        _engagement(engagement_id)
        try:
            recon_module = engine.registry.require(module)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            decision = engine.preflight(engagement_id, recon_module, target)
        except (ScopeError, RHPError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if decision is None:
            return {
                "contacts_target": False,
                "allowed": True,
                "blocked": False,
                "needs_override": False,
                "reason": "This module never contacts the target.",
            }
        return {
            "contacts_target": True,
            "allowed": decision.allowed,
            "blocked": decision.blocked,
            "needs_override": decision.needs_override,
            "reason": decision.reason,
        }

    @router.post("/engagements/{engagement_id}/run")
    def start_run(engagement_id: int, body: RunRequest) -> dict[str, Any]:
        engagement = _engagement(engagement_id)
        try:
            recon_module = engine.registry.require(body.module)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        _refuse_if_blocked(engine, engagement_id, recon_module, body.target)
        try:
            job = jobs.start_module(
                engine,
                engagement,
                body.module,
                body.target,
                params=body.params,
                override=body.override,
            )
        except JobBusy as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"job_id": job.id}

    @router.post("/engagements/{engagement_id}/recipe")
    def start_recipe(engagement_id: int, body: RecipeRequest) -> dict[str, Any]:
        engagement = _engagement(engagement_id)
        try:
            job = jobs.start_recipe(
                engine,
                engagement,
                body.target,
                module_ids=body.modules,
                override=body.override,
            )
        except (JobBusy, KeyError) as exc:
            status = 409 if isinstance(exc, JobBusy) else 404
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"job_id": job.id}

    @router.get("/jobs/{job_id}")
    def job_status(job_id: str, cursor: int = 0) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="No such job.")
        return job.snapshot(cursor)

    @router.post("/jobs/{job_id}/cancel")
    def cancel_job(job_id: str) -> dict[str, Any]:
        if not jobs.cancel(job_id):
            raise HTTPException(status_code=404, detail="That job is not running.")
        return {"cancelled": True}

    return router


def _refuse_if_blocked(engine: Engine, engagement_id: int, module: Any, target: str) -> None:
    """A hard-blocked destination is refused here as well as in the client.

    Defence in depth: the HTTP client would refuse it anyway, but the dashboard
    should never present a hard block as something a click could get past.
    """
    try:
        decision = engine.preflight(engagement_id, module, target)
    except (ScopeError, RHPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if decision is not None and decision.blocked:
        raise HTTPException(status_code=403, detail=decision.reason)
