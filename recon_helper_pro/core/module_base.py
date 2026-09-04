"""The module contract every recon capability implements (PRD 9.2).

A module declares what it is, how much it touches the target, what it costs in
requests, and which teaching content explains it. It never talks to the network
except through the client on its context, and it never decides on its own that
something is a vulnerability - it emits observations, and findings that are
explicitly framed as interpretations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .httpclient import SafeHTTPClient
from .models import ContactMode, Engagement, PluginResult
from .safety import CancelToken, Redactor, RequestPolicy
from .scope import Scope
from .thirdparty import ThirdPartyClient


class ArtifactSink(Protocol):
    """Stores a raw (already redacted) artifact and returns its reference."""

    def __call__(self, artifact_type: str, content: bytes | str) -> str: ...


@dataclass(slots=True)
class ModuleContext:
    """Everything a module is allowed to touch."""

    engagement: Engagement
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    scope: Scope = field(default_factory=Scope)
    policy: RequestPolicy = field(default_factory=RequestPolicy)
    settings: Mapping[str, Any] = field(default_factory=dict)
    redactor: Redactor = field(default_factory=Redactor)
    http: SafeHTTPClient | None = None
    cancel: CancelToken = field(default_factory=CancelToken)
    allow_override: bool = False
    store_artifact: ArtifactSink | None = None
    #: Observations already recorded for this engagement, for modules that
    #: interpret earlier results rather than collecting new ones.
    prior_observations: list[dict[str, Any]] = field(default_factory=list)
    #: Overridable factory for the provider client, so tests can pin resolution.
    third_party_factory: Callable[[], ThirdPartyClient] | None = None
    progress: Callable[[str], None] = lambda message: None

    def emit(self, message: str) -> None:
        """Report progress to whichever interface is driving the run."""
        self.progress(message)

    def third_party(self) -> ThirdPartyClient:
        """Client for public data providers - never for the target."""
        if self.third_party_factory is not None:
            return self.third_party_factory()
        return ThirdPartyClient(self.policy, redactor=self.redactor, cancel=self.cancel)

    def require_http(self) -> SafeHTTPClient:
        if self.http is None:
            raise RuntimeError("This module needs an HTTP client but none was provided.")
        return self.http

    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)

    def artifact(self, artifact_type: str, content: bytes | str) -> str | None:
        if self.store_artifact is None:
            return None
        return self.store_artifact(artifact_type, content)


class ModuleBase(ABC):
    """Base class for every bundled recon module."""

    #: Stable identifier used on the command line and in the database.
    id: str = ""
    name: str = ""
    version: str = "0.1.0"
    category: str = "general"
    mode: ContactMode = ContactMode.THIRD_PARTY
    #: Key into ``teaching_content/`` - prose never lives in module code.
    teaching_key: str = ""
    supported_target_types: tuple[str, ...] = ("domain", "host")
    #: Declared configuration, as ``name -> (default, description)``.
    config_schema: dict[str, tuple[Any, str]] = {}
    request_budget: int = 0
    timeout: int = 10
    redirect_policy: str = "follow-in-scope"
    retry_policy: str = "none"
    #: ``required`` means the run is refused out of scope; ``warn`` allows an
    #: explicit, logged override; ``none`` means the target is never contacted.
    scope_requirement: str = "none"
    optional_tools: tuple[str, ...] = ()
    pure_python_fallback: bool = True
    output_schema_version: int = 1

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "mode": self.mode.value,
            "teaching_key": self.teaching_key,
            "request_budget": self.request_budget,
            "scope_requirement": self.scope_requirement,
            "optional_tools": list(self.optional_tools),
            "supported_target_types": list(self.supported_target_types),
            "output_schema_version": self.output_schema_version,
        }

    def resolved_config(self, params: Mapping[str, Any]) -> dict[str, Any]:
        config = {key: default for key, (default, _desc) in self.config_schema.items()}
        for key, value in params.items():
            if key in config:
                config[key] = value
        return config

    @abstractmethod
    def run(self, context: ModuleContext) -> PluginResult:
        """Do the work. Must honour ``context.cancel`` and never raise for an
        expected failure - return a ``partial``/``failed`` result instead."""
