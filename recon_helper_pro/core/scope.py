"""Scope parsing, address normalization, and the hard block list (PRD 7.2, 7.3).

Three rules drive everything in this file:

1. **Never scope-check a raw string.** Any value that could be an address is
   normalized to an :mod:`ipaddress` object first, because ``0xA9FEA9FE``,
   ``2852039166`` and ``0251.0376.0251.0376`` are all ``169.254.169.254``.
2. **Exact-host semantics.** ``example.com`` in scope authorizes *only*
   ``example.com``; subdomains need ``*.example.com`` added deliberately.
3. **Some destinations are never reachable**, whatever the scope says: the whole
   link-local range and the cloud metadata endpoints.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import urlsplit

import idna

from .errors import ScopeError, TargetValidationError
from .models import ScopeEntry, ScopeEntryType

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")

#: Ranges that are hard-blocked and cannot be overridden (PRD 7.3).
HARD_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # Link-local, in full - not just the single metadata address.
    LINK_LOCAL_V4,
    LINK_LOCAL_V6,
    # Cloud metadata services that do not live in link-local space.
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
    ipaddress.ip_network("192.0.0.192/32"),      # Oracle Cloud metadata
    # "This host" / unspecified: 0.0.0.0 and [::] route to local services.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    # Multicast and reserved space is never a legitimate recon destination.
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
)

#: Hostnames that resolve to metadata services on some platforms.
HARD_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$"
)

#: Characters that must never survive into a subprocess argument (PRD 9.4).
_SHELL_UNSAFE_CHARS = frozenset(
    " \t\r\n\v\f;&|<>$`\"'\\(){}[]!*?~^%,"
)


# --------------------------------------------------------------------------
# Address normalization
# --------------------------------------------------------------------------
def _parse_int_part(part: str) -> int | None:
    """Parse one dotted part using inet_aton rules (hex / octal / decimal)."""
    if part == "":
        return None
    lowered = part.lower()
    try:
        if lowered.startswith("0x"):
            return int(lowered[2:], 16) if len(lowered) > 2 else None
        if lowered.startswith("0") and len(lowered) > 1:
            return int(lowered, 8)
        return int(lowered, 10)
    except ValueError:
        return None


def _pack_inet_aton(nums: Sequence[int]) -> int | None:
    """Combine 1-4 numeric parts into a 32-bit address, inet_aton style."""
    count = len(nums)
    if any(n < 0 for n in nums):
        return None
    if count == 1:
        value = nums[0]
        return value if value <= 0xFFFFFFFF else None
    limits = {2: (0xFF, 0xFFFFFF), 3: (0xFF, 0xFF, 0xFFFF), 4: (0xFF, 0xFF, 0xFF, 0xFF)}
    bounds = limits[count]
    if any(n > bound for n, bound in zip(nums, bounds)):
        return None
    if count == 2:
        return (nums[0] << 24) | nums[1]
    if count == 3:
        return (nums[0] << 24) | (nums[1] << 16) | nums[2]
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


def _unwrap_v6(address: IPAddress) -> IPAddress:
    """Reduce tunnelled/mapped IPv6 forms to the IPv4 address they reach."""
    if isinstance(address, ipaddress.IPv6Address):
        for candidate in (address.ipv4_mapped, address.sixtofour):
            if candidate is not None:
                return candidate
        if address.teredo is not None:
            return address.teredo[1]
        # ::a.b.c.d (IPv4-compatible, deprecated but still routable by stacks)
        packed = int(address)
        if packed >> 32 == 0 and packed != 0:
            return ipaddress.IPv4Address(packed & 0xFFFFFFFF)
    return address


def normalize_ip(text: str) -> IPAddress | None:
    """Return the address *text* really denotes, or ``None`` if it is not an IP.

    Handles every representation the C resolver would accept - dotted decimal,
    dotted octal/hex, packed decimal, mixed forms - plus bracketed IPv6, and
    unwraps IPv4-mapped / 6to4 / Teredo IPv6 addresses to the IPv4 address they
    ultimately reach.  This is what makes the block list unbypassable by
    encoding tricks (PRD 7.3.1).
    """
    if text is None:
        return None
    value = str(text).strip()
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    # Strip an IPv6 zone index; we never connect via a scoped interface.
    if "%" in value:
        value = value.split("%", 1)[0]

    address: IPAddress | None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    if address is None and ":" not in value:
        parts = value.split(".")
        if 1 <= len(parts) <= 4 and all(part != "" for part in parts):
            numbers = [_parse_int_part(part) for part in parts]
            if all(number is not None for number in numbers):
                packed = _pack_inet_aton([number for number in numbers if number is not None])
                if packed is not None:
                    address = ipaddress.IPv4Address(packed)

    if address is None:
        return None
    return _unwrap_v6(address)


def is_hard_blocked(address: IPAddress) -> str | None:
    """Return a reason string if *address* may never be contacted."""
    address = _unwrap_v6(address)
    for network in HARD_BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            if network in (LINK_LOCAL_V4, LINK_LOCAL_V6):
                return (
                    f"{address} is in the link-local range {network}, which contains the "
                    "cloud metadata endpoints. This block cannot be overridden."
                )
            return f"{address} is in the always-blocked range {network}."
    return None


def is_private_target(address: IPAddress) -> bool:
    """True for lab-style destinations (RFC1918, loopback, unique-local)."""
    address = _unwrap_v6(address)
    return bool(address.is_private or address.is_loopback)


# --------------------------------------------------------------------------
# Hostname handling
# --------------------------------------------------------------------------
def normalize_hostname(host: str) -> str:
    """Lower-case, strip the trailing dot, and IDNA-encode *host*."""
    value = (host or "").strip().strip(".").lower()
    if not value:
        raise ScopeError("Empty hostname.")
    if value.startswith("[") and value.endswith("]"):
        return value
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        try:
            value = idna.encode(value, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise ScopeError(f"Not a usable international hostname: {host!r} ({exc})") from exc
    return value


def is_hostname(value: str) -> bool:
    """True if *value* is a syntactically valid DNS name (already normalized)."""
    return bool(_HOSTNAME_RE.match(value))


def validate_target(target: str) -> str:
    """Strictly validate a user-supplied target before it can reach a subprocess.

    Rejects leading dashes and anything a shell could reinterpret (PRD 9.4).
    """
    value = (target or "").strip()
    if not value:
        raise TargetValidationError("Empty target.")
    if value.startswith("-"):
        raise TargetValidationError(
            f"Target {value!r} starts with '-', which a command-line tool would read as a flag."
        )
    bad = sorted(set(value) & _SHELL_UNSAFE_CHARS)
    if bad:
        raise TargetValidationError(
            f"Target {value!r} contains characters that are not valid in a host or IP: {bad}."
        )
    if normalize_ip(value) is not None:
        return value
    normalized = normalize_hostname(value)
    if not is_hostname(normalized):
        raise TargetValidationError(f"Target {value!r} is not a valid hostname or IP address.")
    return normalized


# --------------------------------------------------------------------------
# Scope entries
# --------------------------------------------------------------------------
def _parse_port(text: str, original: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise ScopeError(f"Invalid port in scope entry {original!r}.") from exc
    if not 1 <= port <= 65535:
        raise ScopeError(f"Port out of range in scope entry {original!r}.")
    return port


def parse_scope_entry(text: str) -> ScopeEntry:
    """Parse ``https://*.example.com:8443`` style scope input into an entry."""
    raw = (text or "").strip()
    if not raw:
        raise ScopeError("Empty scope entry.")

    scheme: str | None = None
    remainder = raw
    if "://" in remainder:
        scheme, remainder = remainder.split("://", 1)
        scheme = scheme.lower()
        if scheme not in {"http", "https"}:
            raise ScopeError(f"Unsupported scheme {scheme!r}; use http or https.")
    remainder = remainder.split("/", 1)[0] if not _looks_like_cidr(remainder) else remainder

    port: int | None = None
    host_part = remainder
    if host_part.startswith("["):  # bracketed IPv6, optionally with :port
        closing = host_part.find("]")
        if closing == -1:
            raise ScopeError(f"Unbalanced '[' in scope entry {text!r}.")
        after = host_part[closing + 1 :]
        host_part = host_part[1:closing]
        if after.startswith(":"):
            port = _parse_port(after[1:], text)
    elif host_part.count(":") == 1 and "/" not in host_part:
        head, tail = host_part.split(":", 1)
        if tail.isdigit():
            host_part, port = head, _parse_port(tail, text)

    if "/" in host_part:  # CIDR
        try:
            network = ipaddress.ip_network(host_part, strict=False)
        except ValueError as exc:
            raise ScopeError(f"{text!r} is not a valid CIDR range ({exc}).") from exc
        return ScopeEntry(None, None, ScopeEntryType.CIDR, str(network), scheme, port)

    if host_part.startswith("*."):
        base = normalize_hostname(host_part[2:])
        if not is_hostname(base):
            raise ScopeError(f"{text!r} is not a valid wildcard entry.")
        return ScopeEntry(None, None, ScopeEntryType.WILDCARD, f"*.{base}", scheme, port)

    address = normalize_ip(host_part)
    if address is not None:
        return ScopeEntry(None, None, ScopeEntryType.IP, str(address), scheme, port)

    host = normalize_hostname(host_part)
    if not is_hostname(host):
        raise ScopeError(f"{text!r} is not a valid host, wildcard, IP or CIDR entry.")
    return ScopeEntry(None, None, ScopeEntryType.HOST, host, scheme, port)


def _looks_like_cidr(text: str) -> bool:
    head, _, tail = text.partition("/")
    return bool(tail) and tail.isdigit() and (normalize_ip(head) is not None or ":" in head)


@dataclass(slots=True)
class ScopeDecision:
    """Outcome of a scope check.

    ``blocked`` means "never allowed"; ``allowed`` False with ``blocked`` False
    means "outside scope - the user may override with a logged confirmation".
    """

    allowed: bool
    blocked: bool
    reason: str
    matched: str = ""

    @property
    def needs_override(self) -> bool:
        return not self.allowed and not self.blocked


class Scope:
    """The scope of one engagement, plus the non-overridable block list.

    ``allow_private`` is the lab switch (PRD 19): on by default so you can
    practise against your own machines; turning it off makes private, loopback
    and unique-local addresses non-overridably blocked as well.
    """

    def __init__(
        self, entries: Iterable[ScopeEntry] | None = None, allow_private: bool = True
    ) -> None:
        self.entries: list[ScopeEntry] = list(entries or [])
        self.allow_private = allow_private

    def add(self, entry: ScopeEntry) -> None:
        self.entries.append(entry)

    def __len__(self) -> int:
        return len(self.entries)

    # -- matching ---------------------------------------------------------
    @staticmethod
    def _qualifiers_match(entry: ScopeEntry, scheme: str | None, port: int | None) -> bool:
        if entry.scheme and scheme and entry.scheme != scheme.lower():
            return False
        if entry.port:
            return entry.port == port
        return True

    def match_host(
        self, host: str, scheme: str | None = None, port: int | None = None
    ) -> ScopeEntry | None:
        """Return the entry authorizing *host*, honouring exact-host semantics."""
        try:
            normalized = normalize_hostname(host)
        except ScopeError:
            return None
        for entry in self.entries:
            if not self._qualifiers_match(entry, scheme, port):
                continue
            if entry.type is ScopeEntryType.HOST and entry.value == normalized:
                return entry
            if entry.type is ScopeEntryType.WILDCARD:
                base = entry.value[2:]
                if normalized.endswith("." + base):
                    return entry
        return None

    def match_ip(
        self, address: IPAddress, scheme: str | None = None, port: int | None = None
    ) -> ScopeEntry | None:
        address = _unwrap_v6(address)
        for entry in self.entries:
            if not self._qualifiers_match(entry, scheme, port):
                continue
            if entry.type is ScopeEntryType.IP:
                candidate = normalize_ip(entry.value)
                if candidate is not None and candidate == address:
                    return entry
            elif entry.type is ScopeEntryType.CIDR:
                network = ipaddress.ip_network(entry.value, strict=False)
                if address.version == network.version and address in network:
                    return entry
        return None

    # -- decisions --------------------------------------------------------
    def check_hostname(
        self, host: str, scheme: str | None = None, port: int | None = None
    ) -> ScopeDecision:
        """Check a hostname *before* resolution (the cheap first gate)."""
        try:
            normalized = normalize_hostname(host)
        except ScopeError as exc:
            return ScopeDecision(False, True, str(exc))
        if normalized in HARD_BLOCKED_HOSTNAMES:
            return ScopeDecision(
                False,
                True,
                f"{normalized} is a cloud metadata hostname and is always blocked.",
            )
        literal = normalize_ip(normalized)
        if literal is not None:
            return self.check_address(literal, scheme, port)
        entry = self.match_host(normalized, scheme, port)
        if entry is not None:
            return ScopeDecision(True, False, f"in scope via {entry.display()}", entry.display())
        return ScopeDecision(False, False, f"{normalized} is not covered by any scope entry.")

    def check_address(
        self, address: IPAddress, scheme: str | None = None, port: int | None = None
    ) -> ScopeDecision:
        """Check a resolved address. This is the gate that actually protects us."""
        address = _unwrap_v6(address)
        blocked = is_hard_blocked(address)
        if blocked:
            return ScopeDecision(False, True, blocked)
        if not self.allow_private and is_private_target(address):
            return ScopeDecision(
                False,
                True,
                f"{address} is a private or loopback address and lab mode is off "
                "(setting 'lab.allow_private').",
            )
        entry = self.match_ip(address, scheme, port)
        if entry is not None:
            return ScopeDecision(True, False, f"in scope via {entry.display()}", entry.display())
        return ScopeDecision(False, False, f"{address} is not covered by any scope entry.")

    def check_resolved(
        self,
        host: str,
        address: IPAddress,
        scheme: str | None = None,
        port: int | None = None,
    ) -> ScopeDecision:
        """Post-resolution check: the hard block always wins, then either the
        hostname or the resolved address may authorize the request (PRD 7.2)."""
        address = _unwrap_v6(address)
        blocked = is_hard_blocked(address)
        if blocked:
            return ScopeDecision(False, True, blocked)
        if not self.allow_private and is_private_target(address):
            return self.check_address(address, scheme, port)
        host_decision = self.check_hostname(host, scheme, port)
        if host_decision.blocked or host_decision.allowed:
            return host_decision
        return self.check_address(address, scheme, port)


def split_url(url: str) -> tuple[str, str, int]:
    """Return ``(scheme, host, port)`` for *url*, with the default port applied."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    scheme = (parts.scheme or "http").lower()
    try:
        host = parts.hostname or ""
    except ValueError as exc:
        raise ScopeError(f"Could not read a hostname out of {url!r} ({exc}).") from exc
    if not host:
        raise ScopeError(f"Could not read a hostname out of {url!r}.")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ScopeError(f"Invalid port in {url!r} ({exc}).") from exc
    return scheme, host, port
