"""Tamper-evident hash-chained audit trail and compliance logger (SOC2/ISO-27001)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Callable

from pydantic import BaseModel, Field

from src.core.models import Principal, ToolCallRequest, ToolCallResult, new_id, utc_now

GENESIS_HASH = "0" * 64


class AuditEvent(BaseModel):
    """Immutable, hash-chained compliance audit event."""

    event_id: str = Field(default_factory=lambda: new_id("aud"))
    sequence: int
    timestamp: datetime = Field(default_factory=utc_now)
    tenant_id: str
    principal_id: str
    action: str
    resource: str
    outcome: str
    correlation_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    event_hash: str


class AuditTrail:
    """Append-only cryptographic hash-chained audit ledger with integrity verification."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @staticmethod
    def _compute_hash(payload: dict[str, Any], prev_hash: str) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        digest_input = f"{prev_hash}:{canonical}".encode("utf-8")
        return hashlib.sha256(digest_input).hexdigest()

    def record(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        action: str,
        resource: str,
        outcome: str,
        correlation_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append a new tamper-evident audit event to the ledger."""
        seq = len(self._events) + 1
        prev_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        ts = utc_now()
        event_id = new_id("aud")
        meta = dict(metadata or {})

        hash_payload = {
            "event_id": event_id,
            "sequence": seq,
            "timestamp": ts.isoformat(),
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "metadata": meta,
        }
        event_hash = self._compute_hash(hash_payload, prev_hash)
        event = AuditEvent(
            event_id=event_id,
            sequence=seq,
            timestamp=ts,
            tenant_id=tenant_id,
            principal_id=principal_id,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata=meta,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )
        self._events.append(event)
        return event

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Recompute the full SHA-256 chain; returns (valid, first_broken_sequence)."""
        expected_prev = GENESIS_HASH
        for idx, ev in enumerate(self._events, start=1):
            if ev.sequence != idx or ev.prev_hash != expected_prev:
                return False, idx
            payload = {
                "event_id": ev.event_id,
                "sequence": ev.sequence,
                "timestamp": ev.timestamp.isoformat(),
                "tenant_id": ev.tenant_id,
                "principal_id": ev.principal_id,
                "action": ev.action,
                "resource": ev.resource,
                "outcome": ev.outcome,
                "correlation_id": ev.correlation_id,
                "metadata": ev.metadata,
            }
            recomputed = self._compute_hash(payload, ev.prev_hash)
            if recomputed != ev.event_hash:
                return False, idx
            expected_prev = ev.event_hash
        return True, None

    def query(
        self,
        *,
        tenant_id: str,
        principal_id: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
    ) -> list[AuditEvent]:
        """Query audit events strictly scoped to a tenant."""
        return [
            ev
            for ev in self._events
            if ev.tenant_id == tenant_id
            and (principal_id is None or ev.principal_id == principal_id)
            and (action is None or ev.action == action)
            and (outcome is None or ev.outcome == outcome)
        ]

    def export_jsonl(self, tenant_id: str) -> str:
        """Export tenant-scoped audit events as newline-delimited JSON."""
        events = self.query(tenant_id=tenant_id)
        return "\n".join(ev.model_dump_json() for ev in events)

    def make_mcp_hook(self) -> Callable[[ToolCallRequest, ToolCallResult, Principal], None]:
        """Return an MCPServer post-execution hook that logs every tool call."""

        def _hook(req: ToolCallRequest, res: ToolCallResult, principal: Principal) -> None:
            self.record(
                tenant_id=principal.tenant_id,
                principal_id=principal.user_id,
                action="mcp.tool.invoke",
                resource=req.tool_name,
                outcome="success" if res.success else "denied_or_error",
                correlation_id=req.correlation_id,
                metadata={
                    "call_id": req.call_id,
                    "latency_ms": res.latency_ms,
                    "redacted": res.redacted,
                    "error": res.error,
                },
            )

        return _hook
