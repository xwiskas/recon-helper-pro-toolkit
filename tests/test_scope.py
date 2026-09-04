"""Scope parsing, address normalization and the non-overridable block list."""

from __future__ import annotations

import ipaddress

import pytest

from recon_helper_pro.core.errors import ScopeError, TargetValidationError
from recon_helper_pro.core.models import ScopeEntryType
from recon_helper_pro.core.scope import (
    Scope,
    is_hard_blocked,
    normalize_hostname,
    normalize_ip,
    parse_scope_entry,
    validate_target,
)

METADATA = ipaddress.ip_address("169.254.169.254")


@pytest.mark.parametrize(
    "text",
    [
        "169.254.169.254",
        "2852039166",           # packed decimal
        "0xA9FEA9FE",           # hex
        "0251.0376.0251.0376",  # dotted octal
        "169.0xFE.0251.254",    # mixed bases
        "169.254.43518",        # three-part inet_aton form
        "::ffff:169.254.169.254",   # IPv4-mapped IPv6
        "[::ffff:a9fe:a9fe]",       # bracketed, hex-compressed mapping
        "::169.254.169.254",        # IPv4-compatible IPv6
    ],
)
def test_every_encoding_of_the_metadata_address_normalizes(text: str) -> None:
    assert normalize_ip(text) == METADATA


@pytest.mark.parametrize(
    "text",
    [
        "169.254.169.254",
        "0xA9FEA9FE",
        "169.254.0.1",
        "fe80::1",
        "0.0.0.0",
        "[::]",
        "100.100.100.200",
        "192.0.0.192",
        "fd00:ec2::254",
    ],
)
def test_blocked_addresses_cannot_be_reached(text: str) -> None:
    address = normalize_ip(text)
    assert address is not None
    assert is_hard_blocked(address) is not None


@pytest.mark.parametrize("text", ["127.0.0.1", "10.1.2.3", "192.168.0.5", "203.0.113.10", "fd00::1"])
def test_lab_and_public_addresses_are_allowed(text: str) -> None:
    address = normalize_ip(text)
    assert address is not None
    assert is_hard_blocked(address) is None


def test_blocked_wins_even_when_the_address_is_in_scope() -> None:
    scope = Scope([parse_scope_entry("169.254.0.0/16")])
    decision = scope.check_address(METADATA)
    assert decision.blocked is True
    assert decision.allowed is False


def test_non_addresses_are_not_mistaken_for_addresses() -> None:
    assert normalize_ip("example.com") is None
    assert normalize_ip("999.1.1.1") is None
    assert normalize_ip("") is None


# -- exact host semantics --------------------------------------------------
def test_bare_host_authorizes_only_that_host() -> None:
    scope = Scope([parse_scope_entry("example.com")])
    assert scope.check_hostname("example.com").allowed is True
    assert scope.check_hostname("www.example.com").allowed is False
    assert scope.check_hostname("example.com.evil.test").allowed is False


def test_wildcard_covers_subdomains_but_not_the_apex() -> None:
    scope = Scope([parse_scope_entry("*.example.com")])
    assert scope.check_hostname("api.example.com").allowed is True
    assert scope.check_hostname("deep.api.example.com").allowed is True
    assert scope.check_hostname("example.com").allowed is False


def test_cidr_and_ip_entries() -> None:
    scope = Scope([parse_scope_entry("198.51.100.0/24"), parse_scope_entry("203.0.113.7")])
    assert scope.check_address(ipaddress.ip_address("198.51.100.42")).allowed is True
    assert scope.check_address(ipaddress.ip_address("203.0.113.7")).allowed is True
    assert scope.check_address(ipaddress.ip_address("203.0.113.8")).allowed is False


def test_scheme_and_port_qualifiers() -> None:
    scope = Scope([parse_scope_entry("https://example.com:8443")])
    assert scope.check_hostname("example.com", "https", 8443).allowed is True
    assert scope.check_hostname("example.com", "https", 443).allowed is False
    assert scope.check_hostname("example.com", "http", 8443).allowed is False


def test_idn_hostnames_are_normalized() -> None:
    entry = parse_scope_entry("bücher.example")
    assert entry.value == "xn--bcher-kva.example"
    scope = Scope([entry])
    assert scope.check_hostname("BÜCHER.example").allowed is True


def test_ipv6_scope_entry_round_trips() -> None:
    entry = parse_scope_entry("[2001:db8::1]:8443")
    assert entry.type is ScopeEntryType.IP
    assert entry.port == 8443


def test_check_resolved_blocks_a_rebound_name() -> None:
    """A name that is in scope but resolves into blocked space is refused."""
    scope = Scope([parse_scope_entry("example.com")])
    decision = scope.check_resolved("example.com", METADATA)
    assert decision.blocked is True


def test_trailing_dot_and_case_are_normalized() -> None:
    assert normalize_hostname("EXAMPLE.com.") == "example.com"


@pytest.mark.parametrize(
    "bad",
    ["-oProxyCommand=x", "--version", "example.com; rm -rf /", "example.com`id`", "a b", "$(id)"],
)
def test_validate_target_rejects_argument_injection(bad: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(bad)


def test_validate_target_accepts_normal_input() -> None:
    assert validate_target("Example.COM") == "example.com"
    assert validate_target("203.0.113.10") == "203.0.113.10"


def test_parse_scope_entry_rejects_nonsense() -> None:
    for bad in ["", "ftp://example.com", "not a host", "10.0.0.0/99"]:
        with pytest.raises(ScopeError):
            parse_scope_entry(bad)
