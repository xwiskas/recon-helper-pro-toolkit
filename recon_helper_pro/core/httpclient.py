"""The one HTTP client every direct-read / enumerative module must use.

It exists so that the safety rules cannot be forgotten by a module author:

* resolve the hostname **once**, validate that address, then connect to that
  exact address with the original ``Host`` header and TLS SNI - which is what
  closes the DNS-rebinding window (PRD 7.3.1);
* re-run the whole procedure on **every** redirect hop, and stop rather than
  follow a redirect out of scope;
* count every request against the per-run, per-host and per-engagement
  ceilings, and pause between requests;
* cap the response body, redact it, and check for cancellation.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .errors import Cancelled, NetworkError, OutOfScope, ScopeBlocked
from .safety import BudgetTracker, RateLimiter, Redactor, RequestPolicy
from .scope import IPAddress, Scope, normalize_hostname, normalize_ip, split_url

#: A resolver maps ``(host, port)`` to the addresses we would connect to.
Resolver = Callable[[str, int], list[IPAddress]]
EventSink = Callable[[str, str], None]

DEFAULT_PORTS = {"http": 80, "https": 443}


def system_resolver(host: str, port: int) -> list[IPAddress]:
    """Resolve *host* through the system resolver, once."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkError(f"Could not resolve {host}: {exc.strerror or exc}") from exc
    addresses: list[IPAddress] = []
    for info in infos:
        raw = info[4][0]
        address = normalize_ip(str(raw))
        if address is not None and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NetworkError(f"Could not resolve {host} to any usable address.")
    return addresses


@dataclass(slots=True)
class PinnedTarget:
    """A destination that has already passed every check."""

    scheme: str
    host: str
    port: int
    address: IPAddress
    overridden: bool = False

    @property
    def host_header(self) -> str:
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def display(self) -> str:
        return f"{self.host} ({self.address})"


@dataclass(slots=True)
class Hop:
    url: str
    address: str
    status: int
    location: str = ""


@dataclass(slots=True)
class HttpExchange:
    """The result of one (possibly redirected) request."""

    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    address: str
    host: str
    requests: int
    elapsed_ms: int
    #: Every Set-Cookie header separately (values redacted, attributes kept).
    cookies: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default


class SafeHTTPClient:
    """Scope-aware, budgeted, pinned HTTP client."""

    def __init__(
        self,
        policy: RequestPolicy,
        scope: Scope,
        budget: BudgetTracker,
        redactor: Redactor | None = None,
        rate_limiter: RateLimiter | None = None,
        cancel: object | None = None,
        resolver: Resolver | None = None,
        transport: httpx.BaseTransport | None = None,
        on_event: EventSink | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.policy = policy
        self.scope = scope
        self.budget = budget
        self.redactor = redactor or Redactor()
        self.rate = rate_limiter or RateLimiter(policy.delay_ms, cancel)  # type: ignore[arg-type]
        self.cancel = cancel
        self.resolver = resolver or system_resolver
        self.on_event = on_event
        self._client = httpx.Client(
            timeout=httpx.Timeout(policy.timeout_s),
            follow_redirects=False,
            verify=verify_tls,
            transport=transport,
            headers={"User-Agent": policy.user_agent, "Accept-Encoding": "identity"},
        )

    # -- lifecycle --------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SafeHTTPClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- helpers ----------------------------------------------------------
    def _emit(self, kind: str, message: str) -> None:
        if self.on_event is not None:
            self.on_event(kind, message)

    def _check_cancel(self) -> None:
        if self.cancel is not None and getattr(self.cancel, "is_cancelled", False):
            raise Cancelled("Cancelled by the user. Work already collected has been kept.")

    def prepare(
        self, url: str, *, allow_override: bool = False, hop_label: str = "target"
    ) -> PinnedTarget:
        """Validate *url* and pin it to a single resolved address.

        This is the only place a hostname is turned into an address, and the
        address it returns is the address we connect to - nothing re-resolves
        afterwards.
        """
        scheme, raw_host, port = split_url(url)
        host = normalize_hostname(raw_host)

        pre = self.scope.check_hostname(host, scheme, port)
        if pre.blocked:
            raise ScopeBlocked(
                f"Refusing to contact {host}: {pre.reason}", target=host, reason=pre.reason
            )

        literal = normalize_ip(host)
        if literal is not None:
            address = literal
        else:
            addresses = self.resolver(host, port)
            address = addresses[0]

        decision = self.scope.check_resolved(host, address, scheme, port)
        if decision.blocked:
            raise ScopeBlocked(
                f"Refusing to contact {host} ({address}): {decision.reason}",
                target=host,
                reason=decision.reason,
            )
        overridden = False
        if not decision.allowed:
            if not allow_override:
                raise OutOfScope(
                    f"{hop_label} {host} ({address}) is out of scope: {decision.reason}",
                    target=host,
                    reason=decision.reason,
                )
            overridden = True
            self._emit(
                "override",
                f"Contacting out-of-scope {host} ({address}) because you confirmed the override.",
            )
        return PinnedTarget(scheme, host, port, address, overridden)

    def _pinned_url(self, target: PinnedTarget, url: str) -> str:
        parts = urlsplit(url if "://" in url else f"{target.scheme}://{url}")
        literal = f"[{target.address}]" if target.address.version == 6 else str(target.address)
        netloc = f"{literal}:{target.port}"
        path = parts.path or "/"
        return urlunsplit((target.scheme, netloc, path, parts.query, ""))

    # -- the request ------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        allow_override: bool = False,
        max_redirects: int | None = None,
    ) -> HttpExchange:
        started = time.monotonic()
        limit = self.policy.max_redirects if max_redirects is None else max_redirects
        current = url if "://" in url else f"http://{url}"
        hops: list[Hop] = []
        warnings: list[str] = []
        requests_made = 0

        for hop_index in range(limit + 1):
            self._check_cancel()
            try:
                # One resolution per hop, and the address it returns is the one
                # we connect to. A redirect never inherits the initial override.
                target = self.prepare(
                    current,
                    allow_override=allow_override and hop_index == 0,
                    hop_label="Redirect to" if hop_index else "Target",
                )
            except (OutOfScope, ScopeBlocked) as exc:
                if hop_index == 0:
                    raise
                warnings.append(
                    f"Stopped following redirects: {exc}. The redirect target was not "
                    "contacted and this was recorded as an out-of-scope event."
                )
                self._emit("out-of-scope", str(exc))
                break
            self.budget.check(target.host)
            self.rate.wait(target.host)
            self._check_cancel()

            status, response_headers, cookies, body, truncated = self._send(
                method, current, target, headers
            )
            self.budget.record(target.host)
            requests_made += 1

            location = ""
            for key, value in response_headers.items():
                if key.lower() == "location":
                    location = value
                    break
            hops.append(Hop(current, str(target.address), status, location))

            if 300 <= status < 400 and location:
                if hop_index >= limit:
                    warnings.append(
                        f"Stopped after {limit} redirects (the configured maximum)."
                    )
                    break
                current = urljoin(current, location)
                continue

            break

        elapsed = int((time.monotonic() - started) * 1000)
        if truncated:
            warnings.append(
                f"Response body was longer than {self.policy.max_body_bytes} bytes and was "
                "truncated before storage."
            )
        return HttpExchange(
            url=url,
            final_url=current,
            status=status,
            headers=response_headers,
            body=body,
            truncated=truncated,
            address=str(target.address),
            host=target.host,
            requests=requests_made,
            elapsed_ms=elapsed,
            cookies=cookies,
            hops=hops,
            warnings=warnings,
        )

    def get(self, url: str, **kwargs: object) -> HttpExchange:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def head(self, url: str, **kwargs: object) -> HttpExchange:
        return self.request("HEAD", url, **kwargs)  # type: ignore[arg-type]

    # -- transport --------------------------------------------------------
    def _send(
        self,
        method: str,
        url: str,
        target: PinnedTarget,
        extra_headers: Mapping[str, str] | None,
    ) -> tuple[int, dict[str, str], list[str], bytes, bool]:
        pinned = self._pinned_url(target, url)
        headers: dict[str, str] = {"Host": target.host_header}
        if extra_headers:
            headers.update(dict(extra_headers))
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}

        request = self._client.build_request(
            method, pinned, headers=headers, extensions=extensions
        )
        try:
            response = self._client.send(request, stream=True)
        except httpx.HTTPError as exc:
            raise NetworkError(f"Request to {target.display} failed: {exc}") from exc

        truncated = False
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_bytes():
                self._check_cancel()
                chunks.append(chunk)
                size += len(chunk)
                if size >= self.policy.max_body_bytes:
                    truncated = True
                    break
            raw_headers = dict(response.headers)
            raw_cookies = list(response.headers.get_list("set-cookie"))
            status = response.status_code
        except httpx.HTTPError as exc:
            raise NetworkError(f"Reading the response from {target.display} failed: {exc}") from exc
        finally:
            response.close()

        body = b"".join(chunks)[: self.policy.max_body_bytes]
        cookies = [self.redactor.set_cookie(cookie) for cookie in raw_cookies]
        return (
            status,
            self.redactor.headers(raw_headers),
            cookies,
            self.redactor.bytes(body),
            truncated,
        )
