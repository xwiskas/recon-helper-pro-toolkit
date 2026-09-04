"""Domain objects: engagements, scope, assets, runs, observations, findings.

The distinction that matters throughout the product (PRD 8):

* an **observation** is a raw fact we collected, with provenance;
* a **finding** is an *interpretation* of one or more observations, always
  carrying confidence and limitations, and never presented as a confirmed
  vulnerability.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence


def utcnow() -> str:
    """ISO-8601 UTC timestamp used for every ``*_at`` column."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ContactMode(str, enum.Enum):
    """How much a module touches the target (PRD 5)."""

    THIRD_PARTY = "third-party"
    DIRECT_READ = "direct-read"
    ENUMERATIVE = "enumerative"

    @property
    def contacts_target(self) -> bool:
        return self is not ContactMode.THIRD_PARTY


class RunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SeverityHint(str, enum.Enum):
    """Deliberately a *hint*: context-aware, never auto-derived from one header."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScopeEntryType(str, enum.Enum):
    HOST = "host"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"


class AssetKind(str, enum.Enum):
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    URL = "url"


@dataclass(slots=True)
class Engagement:
    id: int | None
    name: str
    description: str = ""
    notes: str = ""
    created_at: str = field(default_factory=utcnow)


@dataclass(slots=True)
class ScopeEntry:
    id: int | None
    engagement_id: int | None
    type: ScopeEntryType
    value: str
    scheme: str | None = None
    port: int | None = None
    created_at: str = field(default_factory=utcnow)

    def display(self) -> str:
        prefix = f"{self.scheme}://" if self.scheme else ""
        suffix = f":{self.port}" if self.port else ""
        return f"{prefix}{self.value}{suffix}"


@dataclass(slots=True)
class Asset:
    id: int | None
    engagement_id: int
    kind: AssetKind
    value: str
    discovered_by: str
    first_seen: str = field(default_factory=utcnow)
    in_scope: bool = False


@dataclass(slots=True)
class Run:
    id: int | None
    engagement_id: int
    module: str
    module_version: str
    parameters: dict[str, Any]
    mode: ContactMode
    status: RunStatus
    target: str = ""
    started_at: str = field(default_factory=utcnow)
    ended_at: str | None = None
    request_count: int = 0
    error_summary: str = ""


@dataclass(slots=True)
class Observation:
    """A raw fact with provenance. ``asset_value`` is resolved to an id on save."""

    type: str
    normalized_value: str
    source_provider: str
    dedup_key: str
    asset_value: str | None = None
    asset_kind: AssetKind = AssetKind.HOST
    raw_value: str | None = None
    artifact_ref: str | None = None
    evidence: str = ""
    confidence: Confidence = Confidence.HIGH
    collected_at: str = field(default_factory=utcnow)
    id: int | None = None
    run_id: int | None = None


@dataclass(slots=True)
class Finding:
    """An interpretation of observations - a hint, not a confirmed vulnerability."""

    title: str
    category: str
    interpretation_text: str
    limitations: str
    confidence: Confidence = Confidence.MEDIUM
    severity_hint: SeverityHint = SeverityHint.INFO
    supporting_dedup_keys: Sequence[str] = field(default_factory=tuple)
    asset_value: str | None = None
    created_at: str = field(default_factory=utcnow)
    id: int | None = None
    engagement_id: int | None = None


@dataclass(slots=True)
class DiscoveredAsset:
    """A host/IP/URL a module found. Recorded only - never auto-contacted (PRD 4)."""

    kind: AssetKind
    value: str
    note: str = ""


@dataclass(slots=True)
class ArtifactRecord:
    id: int | None
    run_id: int
    type: str
    path_or_blob: str
    sha256: str
    retention_policy: str = "days:30"
    created_at: str = field(default_factory=utcnow)


@dataclass(slots=True)
class ActivityEvent:
    id: int | None
    engagement_id: int | None
    module: str
    mode: ContactMode
    target: str
    request_count: int
    outcome: str
    override_reason: str = ""
    timestamp: str = field(default_factory=utcnow)


@dataclass(slots=True)
class PluginResult:
    """What every module returns (PRD 9.2)."""

    status: RunStatus = RunStatus.COMPLETED
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovered_assets: list[DiscoveredAsset] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def merge_metrics(self, **kwargs: Any) -> None:
        self.metrics.update(kwargs)
