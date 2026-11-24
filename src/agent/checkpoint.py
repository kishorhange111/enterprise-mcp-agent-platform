"""Durable checkpointing and step-level state persistence for agent graphs."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field

from src.core.models import TaskStatus, ToolCallResult, utc_now


class StepRecord(BaseModel):
    """Immutable audit record of a single executed graph node."""

    step_index: int
    node_name: str
    status: str
    latency_ms: float = 0.0
    output_summary: Any = None
    error: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)


class AgentState(BaseModel):
    """Serializable state carried across DAG nodes and persisted at checkpoints."""

    task_id: str
    tenant_id: str
    principal_id: str
    correlation_id: str
    prompt: str
    current_node: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    step_count: int = 0
    memory: dict[str, Any] = Field(default_factory=dict)
    step_history: list[StepRecord] = Field(default_factory=list)
    tool_results: list[ToolCallResult] = Field(default_factory=list)
    final_output: Any = None
    error: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


class CheckpointStore(Protocol):
    """Storage interface for saving and restoring agent execution checkpoints."""

    def save(self, state: AgentState) -> int:
        """Persist a snapshot of AgentState and return its checkpoint version."""
        ...

    def load_latest(self, task_id: str) -> AgentState | None:
        """Load the most recent AgentState checkpoint for a task."""
        ...

    def list_history(self, task_id: str) -> list[AgentState]:
        """Return all persisted checkpoints for a task in chronological order."""
        ...


class InMemoryCheckpointStore:
    """Fast in-memory checkpoint store for unit tests and ephemeral runs."""

    def __init__(self) -> None:
        self._store: dict[str, list[str]] = {}

    def save(self, state: AgentState) -> int:
        snapshots = self._store.setdefault(state.task_id, [])
        snapshots.append(state.model_dump_json())
        return len(snapshots)

    def load_latest(self, task_id: str) -> AgentState | None:
        snapshots = self._store.get(task_id)
        if not snapshots:
            return None
        return AgentState.model_validate_json(snapshots[-1])

    def list_history(self, task_id: str) -> list[AgentState]:
        return [AgentState.model_validate_json(s) for s in self._store.get(task_id, [])]


class SQLiteCheckpointStore:
    """Durable SQLite-backed checkpoint store enabling crash recovery and HITL resume."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON agent_checkpoints (task_id, version)"
        )
        self._conn.commit()

    def save(self, state: AgentState) -> int:
        cur = self._conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM agent_checkpoints WHERE task_id = ?",
            (state.task_id,),
        )
        next_version = int(cur.fetchone()[0]) + 1
        self._conn.execute(
            """
            INSERT INTO agent_checkpoints (task_id, tenant_id, version, state_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                state.task_id,
                state.tenant_id,
                next_version,
                state.model_dump_json(),
                utc_now().isoformat(),
            ),
        )
        self._conn.commit()
        return next_version

    def load_latest(self, task_id: str) -> AgentState | None:
        cur = self._conn.execute(
            """
            SELECT state_json FROM agent_checkpoints
            WHERE task_id = ? ORDER BY version DESC LIMIT 1
            """,
            (task_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return AgentState.model_validate(json.loads(row[0]))

    def list_history(self, task_id: str) -> list[AgentState]:
        cur = self._conn.execute(
            """
            SELECT state_json FROM agent_checkpoints
            WHERE task_id = ? ORDER BY version ASC
            """,
            (task_id,),
        )
        return [AgentState.model_validate(json.loads(row[0])) for row in cur.fetchall()]
