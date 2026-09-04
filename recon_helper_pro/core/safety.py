"""Authorization, redaction, request policy, budgets and cancellation (PRD 7).

Nothing in here is decorative: the redactor runs over everything we persist, the
budget tracker is the automatic kill switch, and the cancel token is what makes
Ctrl-C and ``rhp cancel`` stop in-flight work cleanly.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .errors import BudgetExceeded, Cancelled

AGREEMENT_VERSION = "1.0"

AGREEMENT_TEXT = """\
Recon Helper Pro - authorization and ethics agreement (v1.0)

Recon Helper Pro collects information about systems. Some of what it does
contacts the target directly. By accepting, you confirm all of the following:

 1. You will only point this tool at systems you own, or that you have explicit
    written permission to test (your own lab, an in-scope bug bounty target, a
    CTF, or a client engagement with a signed authorization).
 2. You understand that "read-only" is not the same as "invisible": direct-read
    and enumerative modules appear in the target's logs, attributed to the
    honest User-Agent this tool sends.
 3. You accept that the scope you configure is your declaration of what is
    authorized, and that overriding a scope warning is your decision and is
    recorded in the activity log.
 4. You will not use this tool for exploitation, brute force, denial of service,
    or any activity outside the permission you hold.
 5. Findings produced here are interpretations with confidence levels, not
    confirmed vulnerabilities. You are responsible for verifying anything you
    report onwards.

Unauthorized access to computer systems is a crime in most jurisdictions.
"""


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------
REDACTED = "[REDACTED]"

_HEADER_SECRET_NAMES = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "x-csrf-token",
    "x-xsrf-token",
    "authentication",
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Header lines: "Authorization: Bearer ..." anywhere in stored text.
    (
        re.compile(
            r"(?im)^(\s*(?:" + "|".join(_HEADER_SECRET_NAMES) + r")\s*:\s*)(.+)$"
        ),
        r"\1" + REDACTED,
    ),
    # Bearer / Basic tokens inline.
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # JSON Web Tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"), REDACTED),
    # AWS access key ids and generic long secrets in key=value form.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (
        re.compile(
            r"(?i)\b([a-z0-9_.-]*(?:secret|passwd|password|api[_-]?key|access[_-]?token|"
            r"private[_-]?key|client[_-]?secret)[a-z0-9_.-]*)\s*[=:]\s*[\"']?([^\s\"',;]{6,})"
        ),
        r"\1=" + REDACTED,
    ),
    # PEM private key blocks.
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        REDACTED,
    ),
    # Email addresses (PII; WHOIS output is full of them).
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"), REDACTED),
)


class Redactor:
    """Best-effort removal of secrets and obvious PII (PRD 7.6).

    Best-effort is stated deliberately: the data store is still treated as
    sensitive, because pattern matching will always miss something.
    """

    def text(self, value: str | None) -> str:
        if not value:
            return ""
        result = value
        for pattern, replacement in _PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def bytes(self, value: bytes | None) -> bytes:
        if not value:
            return b""
        return self.text(value.decode("utf-8", errors="replace")).encode("utf-8")

    def headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for name, raw in headers.items():
            lowered = name.lower()
            if lowered == "set-cookie":
                # Keep the cookie name and its attributes - those are what the
                # header analysis reasons about - and drop only the value.
                cleaned[name] = self.set_cookie(raw)
            elif lowered in _HEADER_SECRET_NAMES:
                cleaned[name] = REDACTED
            else:
                cleaned[name] = self.text(raw)
        return cleaned

    def set_cookie(self, raw: str) -> str:
        head, _, attributes = raw.partition(";")
        name, sep, _value = head.partition("=")
        redacted_head = f"{name.strip()}={REDACTED}" if sep else head.strip()
        return f"{redacted_head};{attributes}" if attributes else redacted_head

    def mapping(self, data: Mapping[str, Any]) -> dict[str, Any]:
        return {key: self.text(value) if isinstance(value, str) else value
                for key, value in data.items()}


# --------------------------------------------------------------------------
# Request policy and budgets
# --------------------------------------------------------------------------
@dataclass(slots=True)
class RequestPolicy:
    """The conservative defaults from PRD 7.4, resolved from settings."""

    delay_ms: int = 1000
    max_concurrency: int = 2
    enumerative_budget: int = 100
    timeout_s: int = 10
    max_redirects: int = 5
    max_body_bytes: int = 2 * 1024 * 1024
    user_agent: str = "ReconHelperPro/0.1"
    per_host_requests: int = 500
    per_engagement_requests: int = 2000

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> "RequestPolicy":
        return cls(
            delay_ms=int(settings.get("request.delay_ms", 1000)),
            max_concurrency=int(settings.get("request.max_concurrency", 2)),
            enumerative_budget=int(settings.get("request.enumerative_budget", 100)),
            timeout_s=int(settings.get("request.timeout_s", 10)),
            max_redirects=int(settings.get("request.max_redirects", 5)),
            max_body_bytes=int(settings.get("request.max_body_bytes", 2 * 1024 * 1024)),
            user_agent=str(settings.get("request.user_agent", "ReconHelperPro/0.1")),
            per_host_requests=int(settings.get("limits.per_host_requests", 500)),
            per_engagement_requests=int(settings.get("limits.per_engagement_requests", 2000)),
        )


@dataclass
class BudgetTracker:
    """Counts requests and stops the workflow at the ceilings (PRD 7.4).

    Historical counts come from ``activity_events``; live counts are held here
    so a ceiling is enforced *during* a run, not only between runs.
    """

    policy: RequestPolicy
    run_budget: int | None = None
    prior_per_host: dict[str, int] = field(default_factory=dict)
    prior_engagement_total: int = 0
    run_requests: int = 0
    live_per_host: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def host_total(self, host: str) -> int:
        key = host.lower()
        return self.prior_per_host.get(key, 0) + self.live_per_host.get(key, 0)

    def engagement_total(self) -> int:
        return self.prior_engagement_total + self.run_requests

    def check(self, host: str) -> None:
        """Raise :class:`BudgetExceeded` if one more request would break a limit."""
        with self._lock:
            if self.run_budget is not None and self.run_requests >= self.run_budget:
                raise BudgetExceeded(
                    f"Per-run request budget reached ({self.run_budget} requests). "
                    "Raise it with 'rhp config set request.enumerative_budget <n>' if you "
                    "are sure that is appropriate for this target."
                )
            if self.host_total(host) >= self.policy.per_host_requests:
                raise BudgetExceeded(
                    f"Global per-host ceiling reached for {host} "
                    f"({self.policy.per_host_requests} requests in this engagement). "
                    "This is the kill switch; nothing further will be sent to that host."
                )
            if self.engagement_total() >= self.policy.per_engagement_requests:
                raise BudgetExceeded(
                    f"Global per-engagement ceiling reached "
                    f"({self.policy.per_engagement_requests} requests)."
                )

    def record(self, host: str) -> None:
        with self._lock:
            key = host.lower()
            self.run_requests += 1
            self.live_per_host[key] = self.live_per_host.get(key, 0) + 1


class RateLimiter:
    """Per-host delay between requests, interruptible by cancellation."""

    def __init__(self, delay_ms: int, cancel: "CancelToken | None" = None) -> None:
        self.delay_s = max(0.0, delay_ms / 1000.0)
        self.cancel = cancel
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        key = host.lower()
        with self._lock:
            last = self._last.get(key)
            now = time.monotonic()
            remaining = 0.0 if last is None else (last + self.delay_s) - now
        deadline = time.monotonic() + max(0.0, remaining)
        while time.monotonic() < deadline:
            if self.cancel is not None:
                self.cancel.raise_if_cancelled()
            time.sleep(min(0.1, deadline - time.monotonic()))
        with self._lock:
            self._last[key] = time.monotonic()


class CancelToken:
    """Cooperative cancellation for Ctrl-C, ``rhp cancel`` and the dashboard.

    An in-process :class:`threading.Event` covers Ctrl-C; a flag file in the data
    directory lets a second process (``rhp cancel``) stop a running workflow.
    """

    def __init__(self, flag_path: Path | None = None, poll_interval: float = 0.5) -> None:
        self._event = threading.Event()
        self._flag_path = flag_path
        self._poll_interval = poll_interval
        self._last_poll = 0.0

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        if self._event.is_set():
            return True
        if self._flag_path is not None:
            now = time.monotonic()
            if now - self._last_poll >= self._poll_interval:
                self._last_poll = now
                try:
                    if self._flag_path.exists():
                        self._event.set()
                        return True
                except OSError:
                    return False
        return False

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise Cancelled("Cancelled by the user. Work already collected has been kept.")

    def clear_flag(self) -> None:
        if self._flag_path is not None:
            try:
                self._flag_path.unlink(missing_ok=True)
            except OSError:
                pass
