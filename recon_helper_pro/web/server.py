"""The loopback dashboard (PRD 12).

Binds to 127.0.0.1 only, renders every page server-side with Jinja autoescaping,
and drives the same :class:`~recon_helper_pro.core.engine.Engine` the CLI uses.
No recon logic lives here.
"""

from __future__ import annotations

import json
import re
import webbrowser
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import APP_NAME, __version__
from ..core.config import cloud_sync_warning
from ..core.engine import Engine
from ..core.errors import RHPError, ScopeError
from ..core.models import Engagement
from ..core.reporting import write_report
from ..core.safety import AGREEMENT_TEXT, AGREEMENT_VERSION
from ..core.scope import parse_scope_entry
from .api import build_api
from .jobs import JobManager
from .security import Session, guard
from .textfmt import shorten, teaching_html

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
STATIC = HERE / "static"

REPORT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.md$")

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def create_app(engine: Engine, session: Session, jobs: JobManager | None = None) -> FastAPI:
    """Build the ASGI app. Exposed separately so tests can drive it directly."""
    jobs = jobs or JobManager()
    app = FastAPI(title=f"{APP_NAME} dashboard", docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES))
    templates.env.autoescape = True
    templates.env.filters["teaching"] = teaching_html
    templates.env.filters["shorten"] = shorten

    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
    app.include_router(build_api(engine, jobs))

    @app.middleware("http")
    async def hardening(request: Request, call_next):  # noqa: ANN001 - starlette signature
        return await guard(request, call_next, session)

    # -- rendering helpers ------------------------------------------------
    def page(request: Request, template: str, **context: Any) -> HTMLResponse:
        engagement = engine.current_engagement()
        base = {
            "app_name": APP_NAME,
            "version": __version__,
            "csrf_token": session.csrf_token,
            "current_engagement": engagement,
            "engagements": engine.db.list_engagements(),
            "busy": jobs.is_busy(),
        }
        base.update(context)
        return templates.TemplateResponse(request=request, name=template, context=base)

    def redirect(path: str) -> RedirectResponse:
        return RedirectResponse(path, status_code=303)

    def require_engagement(engagement_id: int) -> Engagement | None:
        return engine.db.get_engagement(engagement_id)

    # -- authorization gate -----------------------------------------------
    @app.get("/agreement", response_class=HTMLResponse)
    def agreement(request: Request) -> Response:
        return page(
            request,
            "agreement.html",
            agreement_text=AGREEMENT_TEXT,
            agreement_version=AGREEMENT_VERSION,
            authorized=engine.is_authorized(),
        )

    @app.post("/agreement")
    def accept_agreement() -> Response:
        engine.accept_agreement()
        return redirect("/")

    # -- engagements -------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        if not engine.is_authorized():
            return redirect("/agreement")
        rows = []
        for engagement in engine.db.list_engagements():
            assert engagement.id is not None
            rows.append(
                {
                    "engagement": engagement,
                    "scope": len(engine.db.list_scope_entries(engagement.id)),
                    "assets": len(engine.db.list_assets(engagement.id)),
                    "findings": len(engine.db.findings_for_engagement(engagement.id)),
                    "runs": len(engine.db.list_runs(engagement.id, limit=10_000)),
                }
            )
        return page(
            request,
            "index.html",
            rows=rows,
            data_dir=str(engine.paths.data_dir),
            storage_warning=cloud_sync_warning(engine.paths.data_dir),
        )

    @app.post("/engagements")
    def create_engagement(
        name: str = Form(...), description: str = Form(""),
    ) -> Response:
        clean = name.strip()
        if not clean:
            return redirect("/?error=A+name+is+required")
        if engine.db.get_engagement_by_name(clean):
            return redirect("/?error=That+name+is+already+in+use")
        engagement = engine.db.create_engagement(clean, description.strip())
        engine.save_state(engagement_id=engagement.id)
        return redirect(f"/engagements/{engagement.id}")

    @app.post("/engagements/{engagement_id}/select")
    def select_engagement(engagement_id: int) -> Response:
        if require_engagement(engagement_id) is None:
            return redirect("/")
        engine.save_state(engagement_id=engagement_id)
        return redirect(f"/engagements/{engagement_id}")

    @app.get("/engagements/{engagement_id}", response_class=HTMLResponse)
    def engagement_view(request: Request, engagement_id: int, error: str = "") -> Response:
        engagement = require_engagement(engagement_id)
        if engagement is None:
            return redirect("/")
        findings = sorted(
            engine.db.findings_for_engagement(engagement_id),
            key=lambda item: (
                SEVERITY_RANK.get(str(item.get("severity_hint")), 9),
                str(item.get("title")),
            ),
        )
        by_category: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            by_category.setdefault(str(finding.get("category")), []).append(finding)
        return page(
            request,
            "engagement.html",
            engagement=engagement,
            scope_entries=engine.db.list_scope_entries(engagement_id),
            assets=engine.db.list_assets(engagement_id),
            findings_by_category=by_category,
            finding_count=len(findings),
            runs=engine.db.list_runs(engagement_id, limit=50),
            activity=engine.db.list_activity(engagement_id, limit=50),
            error=error,
        )

    @app.post("/engagements/{engagement_id}/scope")
    def add_scope(engagement_id: int, entry: str = Form(...)) -> Response:
        if require_engagement(engagement_id) is None:
            return redirect("/")
        try:
            parsed = parse_scope_entry(entry)
        except ScopeError as exc:
            from urllib.parse import quote

            return redirect(f"/engagements/{engagement_id}?error={quote(str(exc))}")
        engine.add_scope(engagement_id, parsed)
        return redirect(f"/engagements/{engagement_id}")

    @app.post("/engagements/{engagement_id}/scope/{entry_id}/delete")
    def remove_scope(engagement_id: int, entry_id: int) -> Response:
        engine.remove_scope(engagement_id, entry_id)
        return redirect(f"/engagements/{engagement_id}")

    # -- running -----------------------------------------------------------
    @app.get("/engagements/{engagement_id}/run", response_class=HTMLResponse)
    def run_view(request: Request, engagement_id: int, target: str = "") -> Response:
        engagement = require_engagement(engagement_id)
        if engagement is None:
            return redirect("/")
        modules = []
        for module in engine.registry.all():
            lesson = engine.teaching.lesson(module.teaching_key)
            modules.append({"module": module, "lesson": lesson})
        current = jobs.current()
        return page(
            request,
            "run.html",
            engagement=engagement,
            modules=modules,
            recipe=[module.id for module in engine.registry.recipe()],
            scope_entries=engine.db.list_scope_entries(engagement_id),
            target=target,
            active_job=current.id if current and current.status == "running" else "",
        )

    # -- findings ----------------------------------------------------------
    @app.get(
        "/engagements/{engagement_id}/findings/{finding_id}", response_class=HTMLResponse
    )
    def finding_view(request: Request, engagement_id: int, finding_id: int) -> Response:
        engagement = require_engagement(engagement_id)
        if engagement is None:
            return redirect("/")
        findings = engine.db.findings_for_engagement(engagement_id)
        finding = next((item for item in findings if int(item["id"]) == finding_id), None)
        if finding is None:
            return redirect(f"/engagements/{engagement_id}")
        keys = set(json.loads(str(finding.get("supporting_observation_ids") or "[]")))
        supporting = [
            observation
            for observation in engine.db.observations_for_engagement(engagement_id)
            if str(observation.get("dedup_key")) in keys
        ]
        lesson = None
        run = engine.db.get_run(int(finding["run_id"])) if finding.get("run_id") else None
        if run is not None:
            module = engine.registry.get(run.module)
            if module is not None:
                lesson = engine.teaching.lesson(module.teaching_key)
        return page(
            request,
            "finding.html",
            engagement=engagement,
            finding=finding,
            supporting=supporting,
            lesson=lesson,
            run=run,
        )

    # -- reports -----------------------------------------------------------
    @app.get("/engagements/{engagement_id}/reports", response_class=HTMLResponse)
    def reports_view(request: Request, engagement_id: int, preview: str = "") -> Response:
        engagement = require_engagement(engagement_id)
        if engagement is None:
            return redirect("/")
        exports = sorted(
            engine.paths.exports_dir.glob("*.md"), key=lambda path: path.name, reverse=True
        )
        body = ""
        if preview and REPORT_NAME_RE.match(preview):
            path = _safe_export(engine, preview)
            if path is not None:
                body = path.read_text(encoding="utf-8")
        return page(
            request,
            "reports.html",
            engagement=engagement,
            reports=[path.name for path in exports],
            preview_name=preview if body else "",
            preview_body=body,
        )

    @app.post("/engagements/{engagement_id}/reports")
    def generate_report(engagement_id: int) -> Response:
        engagement = require_engagement(engagement_id)
        if engagement is None:
            return redirect("/")
        report = write_report(
            engine.db, engine.teaching, engagement, engine.paths.exports_dir
        )
        name = report.path.name if report.path else ""
        return redirect(f"/engagements/{engagement_id}/reports?preview={name}")

    @app.get("/reports/{name}/download")
    def download_report(name: str) -> Response:
        path = _safe_export(engine, name)
        if path is None:
            return Response("No such report.", status_code=404)
        return FileResponse(
            path,
            media_type="text/markdown",
            filename=path.name,
            headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
        )

    # -- learn -------------------------------------------------------------
    @app.get("/learn", response_class=HTMLResponse)
    def learn(request: Request, term: str = "") -> Response:
        glossary = engine.teaching.glossary()
        lessons = [
            (module, engine.teaching.lesson(module.teaching_key))
            for module in engine.registry.all()
        ]
        return page(
            request,
            "learn.html",
            glossary=sorted(glossary.items()),
            lessons=lessons,
            term=term,
        )

    return app


def _safe_export(engine: Engine, name: str) -> Path | None:
    """Resolve a report filename inside the exports directory, or nothing."""
    if not REPORT_NAME_RE.match(name or ""):
        return None
    exports = engine.paths.exports_dir.resolve()
    candidate = (exports / name).resolve()
    if candidate.parent != exports or not candidate.is_file():
        return None
    return candidate


def serve(
    engine: Engine,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    log_level: str = "warning",
) -> None:  # pragma: no cover - exercised by hand, not in CI
    """Run the dashboard until interrupted."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RHPError(
            f"Refusing to bind to {host!r}. This dashboard is loopback-only by design; "
            "it has no multi-user model and no transport security."
        )

    session = Session(host=host, port=port)
    app = create_app(engine, session)

    # flush=True: the launch URL is the only way in, so it must appear even when
    # stdout is a pipe rather than a terminal.
    print(f"\n{APP_NAME} dashboard {__version__}", flush=True)
    print(f"  Open: {session.url}", flush=True)
    print(
        "  This link contains a session token and is regenerated every launch.",
        flush=True,
    )
    print("  Press Ctrl-C to stop.\n", flush=True)

    if open_browser:
        try:
            webbrowser.open(session.url)
        except Exception:
            pass

    uvicorn.run(app, host=host, port=port, log_level=log_level, access_log=False)
