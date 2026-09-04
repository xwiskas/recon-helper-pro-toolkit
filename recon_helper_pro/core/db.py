"""SQLite access layer in WAL mode (PRD 8, 14).

WAL lets the CLI and the (phase 2) dashboard read concurrently. Writes are
funnelled through :meth:`Database.write` which takes an in-process lock and an
``IMMEDIATE`` transaction, so concurrent writers serialize rather than corrupt.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from .models import (
    ActivityEvent,
    ArtifactRecord,
    Asset,
    AssetKind,
    ContactMode,
    Engagement,
    Finding,
    Observation,
    Run,
    RunStatus,
    ScopeEntry,
    ScopeEntryType,
    utcnow,
)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    -- scheme/port are stored as '' / 0 rather than NULL so that the UNIQUE
    -- constraint actually deduplicates (SQLite treats NULLs as distinct).
    scheme TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE (engagement_id, type, value, scheme, port)
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    discovered_by TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    in_scope INTEGER NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, kind, value)
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    module_version TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '{}',
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    ended_at TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    raw_value TEXT,
    artifact_ref TEXT,
    source_provider TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'high',
    dedup_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    interpretation_text TEXT NOT NULL,
    supporting_observation_ids TEXT NOT NULL DEFAULT '[]',
    confidence TEXT NOT NULL DEFAULT 'medium',
    limitations TEXT NOT NULL DEFAULT '',
    severity_hint TEXT NOT NULL DEFAULT 'info',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    path_or_blob TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retention_policy TEXT NOT NULL DEFAULT 'days:30'
);

CREATE TABLE IF NOT EXISTS activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    mode TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    request_count INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL,
    outcome TEXT NOT NULL,
    override_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS policy_acceptances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agreement_version TEXT NOT NULL,
    accepted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_obs_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_obs_dedup ON observations(dedup_key);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_events_engagement ON activity_events(engagement_id);
"""


class Database:
    """Thin, explicit SQLite wrapper - no ORM, no hidden magic."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        cur = self._conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    def _migrate(self) -> None:
        with self.write() as cur:
            cur.executescript(SCHEMA)
            cur.execute(
                "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- primitives -------------------------------------------------------
    @contextmanager
    def write(self) -> Iterator[sqlite3.Cursor]:
        """Serialized write transaction (single-writer discipline, PRD 14)."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            try:
                return cur.fetchall()
            finally:
                cur.close()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- settings ---------------------------------------------------------
    def all_settings(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.query("SELECT key, value FROM settings")}

    def set_setting(self, key: str, value: Any) -> None:
        stored = "true" if value is True else "false" if value is False else str(value)
        with self.write() as cur:
            cur.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, stored),
            )

    def delete_setting(self, key: str) -> None:
        with self.write() as cur:
            cur.execute("DELETE FROM settings WHERE key = ?", (key,))

    # -- authorization ----------------------------------------------------
    def accepted_version(self) -> str | None:
        row = self.query_one(
            "SELECT agreement_version FROM policy_acceptances ORDER BY id DESC LIMIT 1"
        )
        return row["agreement_version"] if row else None

    def record_acceptance(self, version: str) -> None:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO policy_acceptances(agreement_version, accepted_at) VALUES(?, ?)",
                (version, utcnow()),
            )

    # -- engagements ------------------------------------------------------
    def create_engagement(self, name: str, description: str = "") -> Engagement:
        engagement = Engagement(None, name=name, description=description)
        with self.write() as cur:
            cur.execute(
                "INSERT INTO engagements(name, description, notes, created_at) VALUES(?,?,?,?)",
                (engagement.name, engagement.description, engagement.notes, engagement.created_at),
            )
            engagement.id = int(cur.lastrowid or 0)
        return engagement

    def list_engagements(self) -> list[Engagement]:
        return [_engagement(row) for row in self.query(
            "SELECT * FROM engagements ORDER BY id"
        )]

    def get_engagement(self, engagement_id: int) -> Engagement | None:
        row = self.query_one("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        return _engagement(row) if row else None

    def get_engagement_by_name(self, name: str) -> Engagement | None:
        row = self.query_one("SELECT * FROM engagements WHERE name = ?", (name,))
        return _engagement(row) if row else None

    def delete_engagement(self, engagement_id: int) -> None:
        with self.write() as cur:
            cur.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))

    # -- scope ------------------------------------------------------------
    def add_scope_entry(self, engagement_id: int, entry: ScopeEntry) -> ScopeEntry:
        entry.engagement_id = engagement_id
        with self.write() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO scope_entries"
                "(engagement_id, type, value, scheme, port, created_at) VALUES(?,?,?,?,?,?)",
                (
                    engagement_id,
                    entry.type.value,
                    entry.value,
                    entry.scheme or "",
                    entry.port or 0,
                    entry.created_at,
                ),
            )
        row = self.query_one(
            "SELECT id FROM scope_entries WHERE engagement_id=? AND type=? AND value=? "
            "AND scheme=? AND port=?",
            (engagement_id, entry.type.value, entry.value, entry.scheme or "", entry.port or 0),
        )
        entry.id = int(row["id"]) if row else None
        return entry

    def list_scope_entries(self, engagement_id: int) -> list[ScopeEntry]:
        rows = self.query(
            "SELECT * FROM scope_entries WHERE engagement_id = ? ORDER BY id", (engagement_id,)
        )
        return [_scope_entry(row) for row in rows]

    def remove_scope_entry(self, engagement_id: int, entry_id: int) -> bool:
        with self.write() as cur:
            cur.execute(
                "DELETE FROM scope_entries WHERE id = ? AND engagement_id = ?",
                (entry_id, engagement_id),
            )
            return cur.rowcount > 0

    # -- assets -----------------------------------------------------------
    def upsert_asset(
        self,
        engagement_id: int,
        kind: AssetKind,
        value: str,
        discovered_by: str,
        in_scope: bool,
    ) -> int:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO assets(engagement_id, kind, value, discovered_by, first_seen, "
                "in_scope) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(engagement_id, kind, value) DO UPDATE SET in_scope=excluded.in_scope",
                (engagement_id, kind.value, value, discovered_by, utcnow(), int(in_scope)),
            )
            row = cur.execute(
                "SELECT id FROM assets WHERE engagement_id=? AND kind=? AND value=?",
                (engagement_id, kind.value, value),
            ).fetchone()
            return int(row["id"])

    def list_assets(self, engagement_id: int) -> list[Asset]:
        rows = self.query(
            "SELECT * FROM assets WHERE engagement_id = ? ORDER BY kind, value", (engagement_id,)
        )
        return [_asset(row) for row in rows]

    def set_asset_scope_flags(self, engagement_id: int, in_scope_values: set[str]) -> None:
        with self.write() as cur:
            for row in cur.execute(
                "SELECT id, value FROM assets WHERE engagement_id = ?", (engagement_id,)
            ).fetchall():
                cur.execute(
                    "UPDATE assets SET in_scope = ? WHERE id = ?",
                    (int(row["value"] in in_scope_values), row["id"]),
                )

    # -- runs -------------------------------------------------------------
    def create_run(self, run: Run) -> Run:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO runs(engagement_id, module, module_version, parameters, mode, "
                "status, target, started_at, request_count, error_summary) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    run.engagement_id,
                    run.module,
                    run.module_version,
                    json.dumps(run.parameters, sort_keys=True),
                    run.mode.value,
                    run.status.value,
                    run.target,
                    run.started_at,
                    run.request_count,
                    run.error_summary,
                ),
            )
            run.id = int(cur.lastrowid or 0)
        return run

    def finish_run(
        self, run_id: int, status: RunStatus, request_count: int, error_summary: str = ""
    ) -> None:
        with self.write() as cur:
            cur.execute(
                "UPDATE runs SET status=?, ended_at=?, request_count=?, error_summary=? "
                "WHERE id=?",
                (status.value, utcnow(), request_count, error_summary, run_id),
            )

    def update_run_status(self, run_id: int, status: RunStatus) -> None:
        with self.write() as cur:
            cur.execute("UPDATE runs SET status=? WHERE id=?", (status.value, run_id))

    def list_runs(self, engagement_id: int, limit: int = 100) -> list[Run]:
        rows = self.query(
            "SELECT * FROM runs WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
            (engagement_id, limit),
        )
        return [_run(row) for row in rows]

    def get_run(self, run_id: int) -> Run | None:
        row = self.query_one("SELECT * FROM runs WHERE id = ?", (run_id,))
        return _run(row) if row else None

    def running_runs(self) -> list[Run]:
        rows = self.query("SELECT * FROM runs WHERE status IN ('queued','running') ORDER BY id")
        return [_run(row) for row in rows]

    # -- observations & findings -----------------------------------------
    def add_observation(self, run_id: int, asset_id: int | None, obs: Observation) -> int:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO observations(run_id, asset_id, type, normalized_value, raw_value, "
                "artifact_ref, source_provider, collected_at, evidence, confidence, dedup_key) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    asset_id,
                    obs.type,
                    obs.normalized_value,
                    obs.raw_value,
                    obs.artifact_ref,
                    obs.source_provider,
                    obs.collected_at,
                    obs.evidence,
                    obs.confidence.value,
                    obs.dedup_key,
                ),
            )
            return int(cur.lastrowid or 0)

    def add_finding(
        self, engagement_id: int, run_id: int | None, asset_id: int | None, finding: Finding
    ) -> int:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO findings(engagement_id, run_id, asset_id, title, category, "
                "interpretation_text, supporting_observation_ids, confidence, limitations, "
                "severity_hint, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    engagement_id,
                    run_id,
                    asset_id,
                    finding.title,
                    finding.category,
                    finding.interpretation_text,
                    json.dumps(list(finding.supporting_dedup_keys)),
                    finding.confidence.value,
                    finding.limitations,
                    finding.severity_hint.value,
                    finding.created_at,
                ),
            )
            return int(cur.lastrowid or 0)

    def observations_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT o.*, a.value AS asset_value, r.module AS module, r.module_version "
            "AS module_version FROM observations o "
            "JOIN runs r ON r.id = o.run_id "
            "LEFT JOIN assets a ON a.id = o.asset_id "
            "WHERE r.engagement_id = ? ORDER BY o.id",
            (engagement_id,),
        )
        return [dict(row) for row in rows]

    def findings_for_engagement(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT f.*, a.value AS asset_value FROM findings f "
            "LEFT JOIN assets a ON a.id = f.asset_id "
            "WHERE f.engagement_id = ? ORDER BY f.id",
            (engagement_id,),
        )
        return [dict(row) for row in rows]

    # -- artifacts --------------------------------------------------------
    def add_artifact(self, artifact: ArtifactRecord) -> int:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO artifacts(run_id, type, path_or_blob, sha256, created_at, "
                "retention_policy) VALUES(?,?,?,?,?,?)",
                (
                    artifact.run_id,
                    artifact.type,
                    artifact.path_or_blob,
                    artifact.sha256,
                    artifact.created_at,
                    artifact.retention_policy,
                ),
            )
            return int(cur.lastrowid or 0)

    def artifacts_for_engagement(self, engagement_id: int | None = None) -> list[dict[str, Any]]:
        if engagement_id is None:
            rows = self.query("SELECT * FROM artifacts ORDER BY id")
        else:
            rows = self.query(
                "SELECT ar.* FROM artifacts ar JOIN runs r ON r.id = ar.run_id "
                "WHERE r.engagement_id = ? ORDER BY ar.id",
                (engagement_id,),
            )
        return [dict(row) for row in rows]

    def delete_artifacts(self, artifact_ids: Sequence[int], sha256s: Sequence[str] = ()) -> None:
        """Delete artifact rows and detach any observation that referenced them.

        Observations reference artifacts by content hash, which is what
        ``sha256s`` carries.
        """
        if not artifact_ids:
            return
        placeholders = ",".join("?" for _ in artifact_ids)
        with self.write() as cur:
            cur.execute(f"DELETE FROM artifacts WHERE id IN ({placeholders})", tuple(artifact_ids))
            if sha256s:
                hash_placeholders = ",".join("?" for _ in sha256s)
                cur.execute(
                    "UPDATE observations SET artifact_ref = NULL WHERE artifact_ref IN "
                    f"({hash_placeholders})",
                    tuple(sha256s),
                )

    # -- activity ---------------------------------------------------------
    def add_activity(self, event: ActivityEvent) -> int:
        with self.write() as cur:
            cur.execute(
                "INSERT INTO activity_events(engagement_id, module, mode, target, request_count, "
                "timestamp, outcome, override_reason) VALUES(?,?,?,?,?,?,?,?)",
                (
                    event.engagement_id,
                    event.module,
                    event.mode.value,
                    event.target,
                    event.request_count,
                    event.timestamp,
                    event.outcome,
                    event.override_reason,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_activity(self, engagement_id: int, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM activity_events WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
            (engagement_id, limit),
        )
        return [dict(row) for row in rows]

    def request_counts_by_host(self, engagement_id: int) -> dict[str, int]:
        """Historical per-host request totals, used to enforce the ceilings."""
        rows = self.query(
            "SELECT target, SUM(request_count) AS total FROM activity_events "
            "WHERE engagement_id = ? GROUP BY target",
            (engagement_id,),
        )
        return {str(row["target"]).lower(): int(row["total"] or 0) for row in rows if row["target"]}

    def engagement_request_total(self, engagement_id: int) -> int:
        row = self.query_one(
            "SELECT SUM(request_count) AS total FROM activity_events WHERE engagement_id = ?",
            (engagement_id,),
        )
        return int(row["total"] or 0) if row else 0


# --------------------------------------------------------------------------
# Row -> dataclass helpers
# --------------------------------------------------------------------------
def _engagement(row: sqlite3.Row) -> Engagement:
    return Engagement(
        id=int(row["id"]),
        name=row["name"],
        description=row["description"],
        notes=row["notes"],
        created_at=row["created_at"],
    )


def _scope_entry(row: sqlite3.Row) -> ScopeEntry:
    return ScopeEntry(
        id=int(row["id"]),
        engagement_id=int(row["engagement_id"]),
        type=ScopeEntryType(row["type"]),
        value=row["value"],
        scheme=row["scheme"] or None,
        port=int(row["port"]) or None,
        created_at=row["created_at"],
    )


def _asset(row: sqlite3.Row) -> Asset:
    return Asset(
        id=int(row["id"]),
        engagement_id=int(row["engagement_id"]),
        kind=AssetKind(row["kind"]),
        value=row["value"],
        discovered_by=row["discovered_by"],
        first_seen=row["first_seen"],
        in_scope=bool(row["in_scope"]),
    )


def _run(row: sqlite3.Row) -> Run:
    return Run(
        id=int(row["id"]),
        engagement_id=int(row["engagement_id"]),
        module=row["module"],
        module_version=row["module_version"],
        parameters=json.loads(row["parameters"] or "{}"),
        mode=ContactMode(row["mode"]),
        status=RunStatus(row["status"]),
        target=row["target"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        request_count=int(row["request_count"]),
        error_summary=row["error_summary"],
    )
