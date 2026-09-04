"""Dashboard tests: hardening, rendering of hostile strings, and the run flow."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

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
from recon_helper_pro.core.scope import parse_scope_entry
from recon_helper_pro.web.security import CONTENT_SECURITY_POLICY, SESSION_COOKIE, Session
from recon_helper_pro.web.server import create_app

#: A string a target could realistically put in a page title or header.
HOSTILE = "<script>alert('xss')</script>"
HOSTILE_HOST = "evil<img src=x onerror=alert(1)>.example.com"


class WebModule(ModuleBase):
    id = "webtest"
    name = "Dashboard fixture module"
    version = "1.0.0"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "dns"
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        context.emit("collecting")
        return PluginResult(
            observations=[
                Observation(
                    type="web.title",
                    normalized_value=HOSTILE,
                    source_provider="fixture " + HOSTILE,
                    dedup_key="web.title:example.com",
                    asset_value="example.com",
                    asset_kind=AssetKind.HOST,
                    evidence="page title",
                    confidence=Confidence.HIGH,
                )
            ],
            findings=[
                Finding(
                    title="Title contains " + HOSTILE,
                    category="fingerprint",
                    interpretation_text="The page title was " + HOSTILE,
                    limitations="Nothing was executed; this is text.",
                    confidence=Confidence.LOW,
                    severity_hint=SeverityHint.INFO,
                    supporting_dedup_keys=["web.title:example.com"],
                    asset_value="example.com",
                )
            ],
            discovered_assets=[DiscoveredAsset(AssetKind.HOST, HOSTILE_HOST, "hostile name")],
            metrics={"requests": 0},
        )


class ContactingWebModule(ModuleBase):
    id = "contacting"
    name = "Contacting fixture"
    mode = ContactMode.DIRECT_READ
    teaching_key = "headers"
    scope_requirement = "warn"
    request_budget = 1

    def run(self, context: ModuleContext) -> PluginResult:
        return PluginResult(metrics={"requests": 1})


@pytest.fixture
def web(tmp_path):
    engine = Engine.open(
        tmp_path / "data", registry=Registry([WebModule(), ContactingWebModule()])
    )
    engine.accept_agreement()
    engagement = engine.db.create_engagement("Dashboard test", "fixture engagement")
    engine.add_scope(engagement.id, parse_scope_entry("example.com"))
    engine.save_state(engagement_id=engagement.id)
    session = Session(host="127.0.0.1", port=8765)
    app = create_app(engine, session)
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    yield client, session, engine, engagement
    engine.close()


def authenticate(client, session) -> None:
    client.cookies.set(SESSION_COOKIE, session.token)


# -- hardening --------------------------------------------------------------
def test_requests_without_the_session_token_are_refused(web):
    client, _session, _engine, _engagement = web
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 401
    assert "token" in response.text.lower()


def test_the_launch_link_sets_a_session_cookie_and_drops_the_token(web):
    client, session, _engine, _engagement = web
    response = client.get(f"/?token={session.token}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "strict" in cookie.lower()


def test_a_wrong_token_does_not_authenticate(web):
    client, _session, _engine, _engagement = web
    response = client.get("/?token=not-the-token", follow_redirects=False)
    assert response.status_code == 401


def test_a_non_loopback_host_header_is_rejected(web):
    client, session, _engine, _engagement = web
    authenticate(client, session)
    response = client.get("/", headers={"Host": "attacker.example.com"})
    assert response.status_code == 400
    assert "127.0.0.1" in response.text


def test_state_changing_requests_need_the_csrf_token(web):
    client, session, _engine, engagement = web
    authenticate(client, session)

    without = client.post(f"/engagements/{engagement.id}/select", follow_redirects=False)
    assert without.status_code == 403

    with_token = client.post(
        f"/engagements/{engagement.id}/select?csrf={session.csrf_token}",
        follow_redirects=False,
    )
    assert with_token.status_code == 303


def test_same_origin_form_posts_are_accepted(web):
    """A browser sends Origin on form posts; the dashboard's own must pass."""
    client, session, _engine, engagement = web
    authenticate(client, session)
    for origin in sorted(session.origins):
        response = client.post(
            f"/engagements/{engagement.id}/select?csrf={session.csrf_token}",
            headers={"Origin": origin},
            follow_redirects=False,
        )
        assert response.status_code == 303, origin


def test_referrer_policy_keeps_the_origin_header_usable(web):
    """Regression: 'no-referrer' makes browsers send Origin: null, which the
    origin check would then reject on every same-origin form post."""
    client, session, _engine, _engagement = web
    authenticate(client, session)
    policy = client.get("/").headers["referrer-policy"]
    assert policy != "no-referrer"
    assert policy == "same-origin"


def test_an_opaque_origin_is_still_rejected(web):
    client, session, _engine, engagement = web
    authenticate(client, session)
    response = client.post(
        f"/engagements/{engagement.id}/select?csrf={session.csrf_token}",
        headers={"Origin": "null"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_a_foreign_origin_is_rejected(web):
    client, session, _engine, engagement = web
    authenticate(client, session)
    response = client.post(
        f"/engagements/{engagement.id}/select?csrf={session.csrf_token}",
        headers={"Origin": "http://evil.example.com"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert "not this dashboard" in response.text


def test_security_headers_are_present_on_every_response(web):
    client, session, _engine, _engagement = web
    authenticate(client, session)
    response = client.get("/")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "no-store" in response.headers["cache-control"]
    # The CSP must not permit inline script - that is what makes escaping decisive.
    assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_no_cors_headers_are_offered(web):
    client, session, _engine, _engagement = web
    authenticate(client, session)
    response = client.get("/", headers={"Origin": "http://evil.example.com"})
    assert "access-control-allow-origin" not in response.headers


# -- hostile content --------------------------------------------------------
def _hostile_run(engine, engagement):
    engine.run_module(engagement, "webtest", "example.com")


def test_hostile_strings_are_escaped_everywhere(web):
    client, session, engine, engagement = web
    authenticate(client, session)
    _hostile_run(engine, engagement)

    findings = engine.db.findings_for_engagement(engagement.id)
    # Pages that render target-controlled values, and pages that merely exist.
    rendering = [
        f"/engagements/{engagement.id}",
        f"/engagements/{engagement.id}/findings/{findings[0]['id']}",
    ]
    others = [
        f"/engagements/{engagement.id}/run",
        f"/engagements/{engagement.id}/reports",
        "/learn",
        "/",
    ]

    for path in rendering + others:
        response = client.get(path)
        assert response.status_code == 200, path
        body = response.text
        # The payloads must never appear as live markup on any page.
        assert HOSTILE not in body, path
        assert "<script>alert(" not in body, path
        assert "<img src=x" not in body, path

    for path in rendering:
        body = client.get(path).text
        # ... and where they are shown, they are shown escaped.
        assert "&lt;script&gt;" in body or "&lt;img" in body, path


def test_hostile_strings_survive_into_the_report_preview_escaped(web):
    client, session, engine, engagement = web
    authenticate(client, session)
    _hostile_run(engine, engagement)

    generated = client.post(
        f"/engagements/{engagement.id}/reports?csrf={session.csrf_token}",
        follow_redirects=True,
    )
    assert generated.status_code == 200
    # The value is visible as text ...
    assert "&lt;script&gt;" in generated.text
    # ... but never as markup.
    assert "<script>alert(" not in generated.text


def test_report_download_rejects_path_traversal(web):
    client, session, _engine, _engagement = web
    authenticate(client, session)
    for name in ["../rhp.sqlite3", "..%2Frhp.sqlite3", "nope.md", "a/b.md"]:
        response = client.get(f"/reports/{name}/download")
        assert response.status_code == 404


# -- flows ------------------------------------------------------------------
def test_engagement_and_scope_flow(web):
    client, session, engine, _engagement = web
    authenticate(client, session)

    created = client.post(
        f"/engagements?csrf={session.csrf_token}",
        data={"name": "From the dashboard", "description": "made in a test"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    new_id = int(created.headers["location"].rsplit("/", 1)[1])

    added = client.post(
        f"/engagements/{new_id}/scope?csrf={session.csrf_token}",
        data={"entry": "*.example.com"},
        follow_redirects=True,
    )
    assert "*.example.com" in added.text

    entries = engine.db.list_scope_entries(new_id)
    removed = client.post(
        f"/engagements/{new_id}/scope/{entries[0].id}/delete?csrf={session.csrf_token}",
        follow_redirects=True,
    )
    assert removed.status_code == 200
    assert engine.db.list_scope_entries(new_id) == []


def test_invalid_scope_entry_reports_the_reason(web):
    client, session, _engine, engagement = web
    authenticate(client, session)
    response = client.post(
        f"/engagements/{engagement.id}/scope?csrf={session.csrf_token}",
        data={"entry": "not a host"},
        follow_redirects=True,
    )
    assert "not a valid host" in response.text


def test_preflight_reports_scope_state(web):
    client, session, _engine, engagement = web
    authenticate(client, session)

    in_scope = client.get(
        f"/api/preflight?engagement_id={engagement.id}&module=contacting&target=example.com"
    ).json()
    assert in_scope["allowed"] is True

    outside = client.get(
        f"/api/preflight?engagement_id={engagement.id}&module=contacting&target=other.test"
    ).json()
    assert outside["needs_override"] is True

    blocked = client.get(
        f"/api/preflight?engagement_id={engagement.id}&module=contacting&target=169.254.169.254"
    ).json()
    assert blocked["blocked"] is True

    passive = client.get(
        f"/api/preflight?engagement_id={engagement.id}&module=webtest&target=anything.test"
    ).json()
    assert passive["contacts_target"] is False


def test_a_blocked_target_cannot_be_started(web):
    client, session, _engine, engagement = web
    authenticate(client, session)
    response = client.post(
        f"/api/engagements/{engagement.id}/run?csrf={session.csrf_token}",
        json={"module": "contacting", "target": "169.254.169.254"},
    )
    assert response.status_code == 403
    assert "link-local" in response.json()["detail"]


def _wait_for_job(client, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = client.get(f"/api/jobs/{job_id}").json()
        if snapshot["finished"]:
            return snapshot
        time.sleep(0.05)
    raise AssertionError("the job never finished")


def test_running_a_module_from_the_dashboard(web):
    client, session, engine, engagement = web
    authenticate(client, session)

    started = client.post(
        f"/api/engagements/{engagement.id}/run?csrf={session.csrf_token}",
        json={"module": "webtest", "target": "example.com"},
    )
    assert started.status_code == 200
    snapshot = _wait_for_job(client, started.json()["job_id"])

    assert snapshot["status"] == "completed"
    assert snapshot["results"][0]["module"] == "webtest"
    assert snapshot["results"][0]["observations"] == 1
    assert engine.db.list_runs(engagement.id)[0].module == "webtest"


def test_the_guided_recipe_runs_from_the_dashboard(web):
    client, session, engine, engagement = web
    authenticate(client, session)

    started = client.post(
        f"/api/engagements/{engagement.id}/recipe?csrf={session.csrf_token}",
        json={"target": "example.com", "modules": ["webtest", "contacting"]},
    )
    snapshot = _wait_for_job(client, started.json()["job_id"])

    assert snapshot["status"] == "completed"
    assert [entry["module"] for entry in snapshot["results"]] == ["webtest", "contacting"]


def test_an_out_of_scope_step_is_skipped_without_an_override(web):
    client, session, engine, engagement = web
    authenticate(client, session)

    started = client.post(
        f"/api/engagements/{engagement.id}/recipe?csrf={session.csrf_token}",
        json={"target": "other.test", "modules": ["contacting"], "override": False},
    )
    snapshot = _wait_for_job(client, started.json()["job_id"])

    assert snapshot["results"][0]["status"] == "skipped"
    assert "No request was sent" in snapshot["results"][0]["skipped_reason"]
    assert engine.db.list_runs(engagement.id) == []


def test_a_confirmed_override_is_recorded(web):
    client, session, engine, engagement = web
    authenticate(client, session)

    started = client.post(
        f"/api/engagements/{engagement.id}/run?csrf={session.csrf_token}",
        json={"module": "contacting", "target": "other.test", "override": True},
    )
    _wait_for_job(client, started.json()["job_id"])

    events = engine.db.list_activity(engagement.id)
    assert events[0]["override_reason"] == "confirmed in the dashboard"


def test_only_one_job_runs_at_a_time(web):
    client, session, _engine, engagement = web
    authenticate(client, session)

    first = client.post(
        f"/api/engagements/{engagement.id}/recipe?csrf={session.csrf_token}",
        json={"target": "example.com", "modules": ["webtest", "webtest", "webtest"]},
    )
    second = client.post(
        f"/api/engagements/{engagement.id}/run?csrf={session.csrf_token}",
        json={"module": "webtest", "target": "example.com"},
    )
    if second.status_code == 409:
        assert "one workflow at a time" in second.json()["detail"]
    _wait_for_job(client, first.json()["job_id"])


def test_learn_page_renders_teaching_content(web):
    client, session, _engine, _engagement = web
    authenticate(client, session)
    response = client.get("/learn")
    assert response.status_code == 200
    assert "Autonomous System Number" in response.text
    assert "third-party" in response.text


def test_agreement_gate(tmp_path):
    engine = Engine.open(tmp_path / "unaccepted", registry=Registry([WebModule()]))
    session = Session(host="127.0.0.1", port=8765)
    client = TestClient(create_app(engine, session), base_url="http://127.0.0.1:8765")
    client.cookies.set(SESSION_COOKIE, session.token)

    landing = client.get("/", follow_redirects=False)
    assert landing.status_code == 303
    assert landing.headers["location"] == "/agreement"

    assert client.post(f"/agreement?csrf={session.csrf_token}", follow_redirects=False).status_code == 303
    assert engine.is_authorized() is True
    engine.close()
