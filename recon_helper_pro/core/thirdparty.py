"""Client for third-party providers (RDAP, crt.sh) - never the target itself.

These requests do not touch the target, so they are not scope-checked against
the engagement. They are still pinned and address-checked, because a provider
that redirects into private or link-local space would be exactly as dangerous
as a target that did.
"""

from __future__ import annotations

from typing import Any, Mapping

from .httpclient import HttpExchange, SafeHTTPClient
from .safety import BudgetTracker, RateLimiter, Redactor, RequestPolicy
from .scope import IPAddress, Scope, ScopeDecision, is_hard_blocked, is_private_target

#: Providers this build is allowed to talk to. Everything is free and keyless.
PROVIDERS: dict[str, str] = {
    "rdap": "https://rdap.org",
    "crtsh": "https://crt.sh",
}


class PublicInternetScope(Scope):
    """Allows any globally routable address; refuses private and blocked space."""

    def check_hostname(
        self, host: str, scheme: str | None = None, port: int | None = None
    ) -> ScopeDecision:
        decision = super().check_hostname(host, scheme, port)
        if decision.blocked:
            return decision
        return ScopeDecision(True, False, "third-party provider")

    def check_address(
        self, address: IPAddress, scheme: str | None = None, port: int | None = None
    ) -> ScopeDecision:
        blocked = is_hard_blocked(address)
        if blocked:
            return ScopeDecision(False, True, blocked)
        if is_private_target(address):
            return ScopeDecision(
                False,
                True,
                f"{address} is a private address; a public data provider should never "
                "resolve there.",
            )
        return ScopeDecision(True, False, "third-party provider")

    def check_resolved(
        self,
        host: str,
        address: IPAddress,
        scheme: str | None = None,
        port: int | None = None,
    ) -> ScopeDecision:
        return self.check_address(address, scheme, port)


class ThirdPartyClient:
    """Small wrapper that keeps provider traffic separate from target traffic."""

    def __init__(
        self,
        policy: RequestPolicy,
        redactor: Redactor | None = None,
        cancel: object | None = None,
        transport: object | None = None,
        resolver: object | None = None,
        delay_ms: int = 250,
    ) -> None:
        self.policy = policy
        self.budget = BudgetTracker(
            policy=RequestPolicy(
                per_host_requests=10_000,
                per_engagement_requests=10_000,
                max_body_bytes=policy.max_body_bytes,
            )
        )
        self._client = SafeHTTPClient(
            policy=policy,
            scope=PublicInternetScope(),
            budget=self.budget,
            redactor=redactor or Redactor(),
            rate_limiter=RateLimiter(delay_ms, cancel),  # type: ignore[arg-type]
            cancel=cancel,
            resolver=resolver,  # type: ignore[arg-type]
            transport=transport,  # type: ignore[arg-type]
        )

    @property
    def requests_made(self) -> int:
        return self.budget.run_requests

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> HttpExchange:
        return self._client.request("GET", url, headers=headers, max_redirects=5)

    def get_json(self, url: str, headers: Mapping[str, str] | None = None) -> Any:
        import json

        merged = {"Accept": "application/json"}
        if headers:
            merged.update(dict(headers))
        exchange = self.get(url, headers=merged)
        if exchange.status >= 400:
            return None
        text = exchange.text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ThirdPartyClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
