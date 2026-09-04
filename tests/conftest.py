"""Shared fixtures. Nothing in this suite touches a live network service."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Callable

import pytest

from recon_helper_pro.core.engine import Engine
from recon_helper_pro.core.httpclient import SafeHTTPClient
from recon_helper_pro.core.models import Engagement
from recon_helper_pro.core.safety import BudgetTracker, RateLimiter, RequestPolicy
from recon_helper_pro.core.scope import Scope, parse_scope_entry

TEST_ADDRESS = "203.0.113.10"


@pytest.fixture
def policy() -> RequestPolicy:
    """Same shape as the real policy, with the sleep removed."""
    return RequestPolicy(delay_ms=0, timeout_s=5, max_redirects=5, max_body_bytes=64 * 1024)


@pytest.fixture
def fixed_resolver() -> Callable[[str], Callable[[str, int], list]]:
    """Build a resolver that always returns one address, for pinning tests."""

    def build(address: str = TEST_ADDRESS):
        def resolver(host: str, port: int) -> list:
            return [ipaddress.ip_address(address)]

        return resolver

    return build


@pytest.fixture
def scope() -> Scope:
    return Scope([parse_scope_entry("example.com"), parse_scope_entry("*.example.com")])


@pytest.fixture
def client_factory(policy, scope, fixed_resolver):
    """A SafeHTTPClient wired to a deterministic resolver."""

    created: list[SafeHTTPClient] = []

    def build(
        address: str = TEST_ADDRESS,
        *,
        client_scope: Scope | None = None,
        run_budget: int | None = None,
        prior_per_host: dict[str, int] | None = None,
        prior_total: int = 0,
        per_host_limit: int = 500,
        per_engagement_limit: int = 2000,
    ) -> SafeHTTPClient:
        request_policy = RequestPolicy(
            delay_ms=0,
            timeout_s=policy.timeout_s,
            max_redirects=policy.max_redirects,
            max_body_bytes=policy.max_body_bytes,
            per_host_requests=per_host_limit,
            per_engagement_requests=per_engagement_limit,
        )
        budget = BudgetTracker(
            policy=request_policy,
            run_budget=run_budget,
            prior_per_host=dict(prior_per_host or {}),
            prior_engagement_total=prior_total,
        )
        client = SafeHTTPClient(
            policy=request_policy,
            scope=client_scope or scope,
            budget=budget,
            rate_limiter=RateLimiter(0),
            resolver=fixed_resolver(address),
        )
        created.append(client)
        return client

    yield build
    for client in created:
        client.close()


@pytest.fixture
def third_party_factory(policy, fixed_resolver):
    """A ThirdPartyClient whose provider hostnames resolve to a fixed address."""
    from recon_helper_pro.core.thirdparty import ThirdPartyClient

    def build(address: str = "93.184.216.34"):
        def factory() -> ThirdPartyClient:
            return ThirdPartyClient(policy, resolver=fixed_resolver(address), delay_ms=0)

        return factory

    return build


@pytest.fixture
def make_context(policy, scope, third_party_factory):
    """Build a ModuleContext without going through the engine."""
    from recon_helper_pro.core.module_base import ModuleContext

    def build(target: str, **overrides) -> ModuleContext:
        defaults = {
            "engagement": Engagement(id=1, name="Test engagement"),
            "target": target,
            "policy": policy,
            "scope": scope,
            "settings": {"robots.respect": True},
            "third_party_factory": third_party_factory(),
        }
        defaults.update(overrides)
        return ModuleContext(**defaults)

    return build


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    """An engine on a throwaway data directory, with the agreement accepted."""
    instance = Engine.open(tmp_path / "data")
    instance.accept_agreement()
    yield instance
    instance.close()


@pytest.fixture
def engagement(engine: Engine) -> Engagement:
    created = engine.db.create_engagement("Test engagement", "fixture")
    assert created.id is not None
    engine.add_scope(created.id, parse_scope_entry("example.com"))
    return created
