"""Dashboard hardening (PRD 12).

This dashboard drives a tool that makes network requests, so a page in another
tab must never be able to reach it. Five independent controls, any one of which
would be enough on its own:

1. it binds to the loopback interface only;
2. every request must carry the session cookie, which is set once from a
   random token printed in the terminal;
3. the ``Host`` header must name loopback, so DNS-rebinding a name to
   127.0.0.1 does not get you in;
4. state-changing requests must carry the CSRF token *and* an ``Origin`` that
   matches this server;
5. a restrictive Content-Security-Policy, and Jinja autoescaping, so
   target-controlled strings can never execute.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response

SESSION_COOKIE = "rhp_session"
CSRF_HEADER = "x-csrf-token"
CSRF_QUERY = "csrf"
TOKEN_QUERY = "token"

LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # 'same-origin', deliberately not 'no-referrer': a browser serializes the
    # Origin header as "null" when the referrer policy is no-referrer, which
    # would make every same-origin form post fail the origin check below.
    # 'same-origin' keeps referrers inside this app and sends none anywhere else.
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Cache-Control": "no-store, max-age=0",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Paths reachable without a session: the stylesheet and script of the login
#: page itself. They contain nothing sensitive.
PUBLIC_PREFIXES = ("/static/",)


@dataclass
class Session:
    """The one session this server accepts, created fresh on every launch."""

    host: str
    port: int
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    @property
    def origins(self) -> set[str]:
        return {
            f"http://127.0.0.1:{self.port}",
            f"http://localhost:{self.port}",
            f"http://[::1]:{self.port}",
        }

    @property
    def url(self) -> str:
        display = "127.0.0.1" if self.host in ("0.0.0.0", "::", "") else self.host
        return f"http://{display}:{self.port}/?{TOKEN_QUERY}={self.token}"

    def matches_token(self, candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(candidate or "", self.token)

    def matches_csrf(self, candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(candidate or "", self.csrf_token)


def _host_is_loopback(request: Request, session: Session) -> bool:
    header = request.headers.get("host", "")
    if not header:
        return False
    if header.startswith("["):  # bracketed IPv6, optionally with :port
        name, _, rest = header.partition("]")
        name += "]"
        port = rest[1:] if rest.startswith(":") else ""
    else:
        name, _, port = header.partition(":")
    if name.lower() not in LOOPBACK_HOSTNAMES:
        return False
    return not port or port == str(session.port)


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get(
        "accept", ""
    )


def _deny(request: Request, status: int, message: str) -> Response:
    if _wants_json(request):
        return JSONResponse({"error": message}, status_code=status)
    return PlainTextResponse(message, status_code=status)


async def guard(request: Request, call_next, session: Session) -> Response:
    """The single middleware every request passes through."""
    path = request.url.path

    if not _host_is_loopback(request, session):
        return _deny(
            request,
            400,
            "This dashboard only answers requests addressed to 127.0.0.1. "
            "Open it with the link printed in your terminal.",
        )

    if path.startswith(PUBLIC_PREFIXES):
        response = await call_next(request)
        _apply_security_headers(response)
        return response

    cookie = request.cookies.get(SESSION_COOKIE)
    authenticated = session.matches_token(cookie)

    if not authenticated and request.method == "GET":
        # First visit: the launch URL carries the token. Consume it, set the
        # cookie, and redirect so the token does not linger in browser history.
        if session.matches_token(request.query_params.get(TOKEN_QUERY)):
            remaining = [
                (key, value)
                for key, value in request.query_params.multi_items()
                if key != TOKEN_QUERY
            ]
            query = "&".join(f"{key}={value}" for key, value in remaining)
            target = path + (f"?{query}" if query else "")
            response = RedirectResponse(target, status_code=303)
            _set_session_cookie(response, session)
            _apply_security_headers(response)
            return response

    if not authenticated:
        return _deny(
            request,
            401,
            "Not authorized for this dashboard session. Open the link printed in the "
            "terminal by 'rhp web' - it contains a token that is regenerated every launch.",
        )

    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin")
        if origin is not None and origin not in session.origins:
            allowed = ", ".join(sorted(session.origins))
            return _deny(
                request,
                403,
                f"Rejected a request whose Origin was {origin}, which is not this "
                f"dashboard ({allowed}). If you reached this page any way other than "
                "the link printed by 'rhp web', start again from that link.",
            )
        supplied = request.headers.get(CSRF_HEADER) or request.query_params.get(CSRF_QUERY)
        if not session.matches_csrf(supplied):
            return _deny(request, 403, "Missing or invalid CSRF token.")

    response = await call_next(request)
    _apply_security_headers(response)
    return response


def _set_session_cookie(response: Response, session: Session) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session.token,
        httponly=True,
        samesite="strict",
        path="/",
        max_age=12 * 60 * 60,
    )


def _apply_security_headers(response: Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
