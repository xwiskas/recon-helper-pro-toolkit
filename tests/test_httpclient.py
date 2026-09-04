"""The safety guarantees of the shared HTTP client (PRD 7.3.1, 7.4)."""

from __future__ import annotations

import httpx
import pytest
import respx

from recon_helper_pro.core.errors import BudgetExceeded, OutOfScope, ScopeBlocked
from recon_helper_pro.core.scope import Scope, parse_scope_entry

PINNED = "https://203.0.113.10/"


@respx.mock
def test_request_is_pinned_to_the_validated_address(client_factory) -> None:
    """The connection goes to the address we checked, carrying the real Host."""
    route = respx.get(PINNED).mock(return_value=httpx.Response(200, text="ok"))
    client = client_factory()

    exchange = client.get("https://example.com/")

    assert exchange.status == 200
    assert exchange.address == "203.0.113.10"
    request = route.calls[0].request
    assert request.url.host == "203.0.113.10"
    assert request.headers["Host"] == "example.com"
    assert request.extensions.get("sni_hostname") == "example.com"


@respx.mock
def test_a_name_resolving_into_blocked_space_is_refused(client_factory) -> None:
    """This is the DNS-rebinding case: in-scope name, blocked address."""
    respx.get("https://169.254.169.254/").mock(return_value=httpx.Response(200))
    client = client_factory("169.254.169.254")

    with pytest.raises(ScopeBlocked):
        client.get("https://example.com/")
    assert respx.calls.call_count == 0


@respx.mock
def test_out_of_scope_target_needs_an_explicit_override(client_factory) -> None:
    respx.get(PINNED).mock(return_value=httpx.Response(200))
    client = client_factory()

    with pytest.raises(OutOfScope):
        client.get("https://not-in-scope.test/")
    assert respx.calls.call_count == 0

    exchange = client.get("https://not-in-scope.test/", allow_override=True)
    assert exchange.status == 200


@respx.mock
def test_redirects_are_revalidated_and_stop_at_the_scope_edge(client_factory) -> None:
    route = respx.route(method="GET", host="203.0.113.10").mock(
        return_value=httpx.Response(302, headers={"Location": "https://elsewhere.test/"})
    )
    client = client_factory()

    exchange = client.get("https://example.com/")

    assert exchange.status == 302
    assert exchange.requests == 1
    assert any("Stopped following redirects" in warning for warning in exchange.warnings)
    assert route.call_count == 1  # only the first hop was ever sent


@respx.mock
def test_an_override_never_carries_across_a_redirect(client_factory) -> None:
    respx.get(PINNED).mock(
        return_value=httpx.Response(302, headers={"Location": "https://second.test/"})
    )
    client = client_factory()

    exchange = client.get("https://first.test/", allow_override=True)

    assert exchange.requests == 1
    assert any("second.test" in warning for warning in exchange.warnings)


@respx.mock
def test_in_scope_redirects_are_followed(client_factory) -> None:
    respx.route(method="GET", host="203.0.113.10").mock(
        side_effect=[
            httpx.Response(301, headers={"Location": "https://www.example.com/home"}),
            httpx.Response(200, text="home"),
        ]
    )
    scope = Scope([parse_scope_entry("example.com"), parse_scope_entry("*.example.com")])
    client = client_factory(client_scope=scope)

    exchange = client.get("https://example.com/")

    assert exchange.status == 200
    assert exchange.requests == 2
    assert len(exchange.hops) == 2


@respx.mock
def test_redirect_to_a_blocked_address_is_stopped(client_factory) -> None:
    respx.get(PINNED).mock(
        return_value=httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/"})
    )
    client = client_factory()

    exchange = client.get("https://example.com/")

    assert exchange.requests == 1
    assert any("169.254.169.254" in warning for warning in exchange.warnings)


@respx.mock
def test_body_is_truncated_and_the_truncation_is_reported(client_factory) -> None:
    respx.get(PINNED).mock(return_value=httpx.Response(200, content=b"x" * 200_000))
    client = client_factory()

    exchange = client.get("https://example.com/")

    assert exchange.truncated is True
    assert len(exchange.body) <= 64 * 1024
    assert any("truncated" in warning for warning in exchange.warnings)


@respx.mock
def test_per_run_budget_stops_further_requests(client_factory) -> None:
    respx.get(PINNED).mock(return_value=httpx.Response(200))
    client = client_factory(run_budget=1)

    client.get("https://example.com/")
    with pytest.raises(BudgetExceeded):
        client.get("https://example.com/other")


@respx.mock
def test_per_host_ceiling_acts_as_a_kill_switch(client_factory) -> None:
    respx.get(PINNED).mock(return_value=httpx.Response(200))
    client = client_factory(prior_per_host={"example.com": 500}, per_host_limit=500)

    with pytest.raises(BudgetExceeded) as excinfo:
        client.get("https://example.com/")
    assert "kill switch" in str(excinfo.value)


@respx.mock
def test_per_engagement_ceiling_is_enforced(client_factory) -> None:
    respx.get(PINNED).mock(return_value=httpx.Response(200))
    client = client_factory(prior_total=2000, per_engagement_limit=2000)

    with pytest.raises(BudgetExceeded):
        client.get("https://example.com/")


@respx.mock
def test_cookie_values_are_redacted_but_attributes_survive(client_factory) -> None:
    respx.get(PINNED).mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("set-cookie", "session=supersecretvalue; Path=/; HttpOnly"),
                ("set-cookie", "theme=dark; Path=/"),
                ("authorization", "Bearer abcdefghijklmnop"),
            ],
        )
    )
    client = client_factory()

    exchange = client.get("https://example.com/")

    assert exchange.cookies[0].startswith("session=[REDACTED]")
    assert "HttpOnly" in exchange.cookies[0]
    assert "supersecret" not in "".join(exchange.cookies)
    assert exchange.header("authorization") == "[REDACTED]"


@respx.mock
def test_an_ip_literal_target_is_checked_without_resolution(client_factory) -> None:
    respx.get("https://192.168.1.10/").mock(return_value=httpx.Response(200))
    scope = Scope([parse_scope_entry("192.168.1.0/24")])
    client = client_factory("203.0.113.10", client_scope=scope)

    exchange = client.get("https://192.168.1.10/")

    assert exchange.address == "192.168.1.10"
