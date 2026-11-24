"""Enterprise REST/Ticketing MCP connector with idempotency keys & tenant isolation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.core.models import RiskLevel, new_id, utc_now
from src.core.tenant import TenantContext, TenantIsolationError, assert_tenant_isolation
from src.mcp.registry import ToolRegistry, ToolSpec
from src.security.rbac import Permission


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused with a different request payload."""


class TicketNotFoundError(KeyError):
    """Raised when a ticket does not exist."""


class InvalidTicketTransitionError(ValueError):
    """Raised when a ticket status transition is not allowed."""


_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"in_progress", "resolved", "closed"}),
    "in_progress": frozenset({"open", "resolved", "closed"}),
    "resolved": frozenset({"closed", "open"}),
    "closed": frozenset({"open"}),
}


@dataclass
class Ticket:
    """Enterprise support/incident ticket record."""

    ticket_id: str
    tenant_id: str
    title: str
    description: str
    priority: str
    status: str = "open"
    created_by: str = ""
    assignee: str | None = None
    idempotency_key: str | None = None
    tags: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "tenant_id": self.tenant_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "status": self.status,
            "created_by": self.created_by,
            "assignee": self.assignee,
            "tags": list(self.tags),
            "comments": list(self.comments),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class TicketingConnector:
    """Multi-tenant ticketing connector (Jira/ServiceNow/Zendesk pattern) with idempotency."""

    CONNECTOR_NAME = "ticketing"

    def __init__(self) -> None:
        self._tickets: dict[str, Ticket] = {}
        # Maps (tenant_id, idempotency_key) -> (payload_fingerprint, ticket_id)
        self._idempotency_index: dict[tuple[str, str], tuple[str, str]] = {}

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def create_ticket(
        self,
        ctx: TenantContext,
        *,
        title: str,
        description: str,
        priority: str = "P3",
        idempotency_key: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a ticket safely with optional idempotency-key deduplication."""
        payload = {
            "title": title,
            "description": description,
            "priority": priority,
            "tags": sorted(tags or []),
        }
        fingerprint = self._fingerprint(payload)

        if idempotency_key:
            key = (ctx.tenant_id, idempotency_key)
            existing = self._idempotency_index.get(key)
            if existing is not None:
                prev_hash, prev_ticket_id = existing
                if prev_hash != fingerprint:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' was already used with a "
                        "different ticket payload"
                    )
                return {
                    "ticket": self._tickets[prev_ticket_id].to_dict(),
                    "idempotent_replay": True,
                }

        ticket = Ticket(
            ticket_id=new_id("TCK"),
            tenant_id=ctx.tenant_id,
            title=title,
            description=description,
            priority=priority,
            created_by=ctx.principal.user_id,
            idempotency_key=idempotency_key,
            tags=list(tags or []),
        )
        self._tickets[ticket.ticket_id] = ticket
        if idempotency_key:
            self._idempotency_index[(ctx.tenant_id, idempotency_key)] = (
                fingerprint,
                ticket.ticket_id,
            )

        return {"ticket": ticket.to_dict(), "idempotent_replay": False}

    def get_ticket(self, ctx: TenantContext, ticket_id: str) -> dict[str, Any]:
        """Fetch a single ticket while enforcing strict tenant isolation."""
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFoundError(f"Ticket '{ticket_id}' not found")
        if ticket.tenant_id != ctx.tenant_id:
            raise TenantIsolationError(f"Cross-tenant ticket access denied for '{ticket_id}'")
        assert_tenant_isolation(ticket.tenant_id)
        return {"ticket": ticket.to_dict()}

    def list_tickets(
        self,
        ctx: TenantContext,
        *,
        status: str | None = None,
        priority: str | None = None,
    ) -> dict[str, Any]:
        """List tickets belonging to the active tenant with optional filters."""
        matched = [
            t.to_dict()
            for t in self._tickets.values()
            if t.tenant_id == ctx.tenant_id
            and (status is None or t.status == status)
            and (priority is None or t.priority == priority)
        ]
        return {"tenant_id": ctx.tenant_id, "count": len(matched), "tickets": matched}

    def transition_ticket(
        self,
        ctx: TenantContext,
        *,
        ticket_id: str,
        new_status: str,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Transition a ticket across valid lifecycle states."""
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFoundError(f"Ticket '{ticket_id}' not found")
        if ticket.tenant_id != ctx.tenant_id:
            raise TenantIsolationError(f"Cross-tenant ticket mutation denied for '{ticket_id}'")

        allowed = _ALLOWED_TRANSITIONS.get(ticket.status, frozenset())
        if new_status not in allowed:
            raise InvalidTicketTransitionError(
                f"Cannot transition ticket '{ticket_id}' from '{ticket.status}' to '{new_status}'"
            )

        ticket.status = new_status
        ticket.updated_at = utc_now()
        if comment:
            ticket.comments.append(comment)
        return {"ticket": ticket.to_dict()}

    def register_tools(self, registry: ToolRegistry) -> None:
        """Register ticketing MCP tools onto a ToolRegistry."""
        registry.register(
            ToolSpec(
                name="tickets.create",
                description="Create an enterprise support/incident ticket with idempotency support.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.TICKET_WRITE,
                risk_level=RiskLevel.MEDIUM,
                requires_hitl=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "minLength": 1, "maxLength": 200},
                        "description": {"type": "string", "minLength": 1},
                        "priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
                        "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
                        "tags": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["title", "description"],
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.create_ticket(
                    ctx,
                    title=args["title"],
                    description=args["description"],
                    priority=args.get("priority", "P3"),
                    idempotency_key=args.get("idempotency_key"),
                    tags=args.get("tags"),
                ),
                tags=("ticketing", "write", "idempotent"),
            )
        )
        registry.register(
            ToolSpec(
                name="tickets.list",
                description="List support tickets scoped to the active tenant.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.TICKET_READ,
                risk_level=RiskLevel.LOW,
                input_schema={
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["open", "in_progress", "resolved", "closed"],
                        },
                        "priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
                    },
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.list_tickets(
                    ctx, status=args.get("status"), priority=args.get("priority")
                ),
                tags=("ticketing", "read"),
            )
        )
        registry.register(
            ToolSpec(
                name="tickets.transition",
                description="Transition a ticket's workflow status with optional comment.",
                connector=self.CONNECTOR_NAME,
                required_permission=Permission.TICKET_WRITE,
                risk_level=RiskLevel.MEDIUM,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ticket_id": {"type": "string", "minLength": 1},
                        "new_status": {
                            "type": "string",
                            "enum": ["open", "in_progress", "resolved", "closed"],
                        },
                        "comment": {"type": "string"},
                    },
                    "required": ["ticket_id", "new_status"],
                    "additionalProperties": False,
                },
                handler=lambda args, ctx: self.transition_ticket(
                    ctx,
                    ticket_id=args["ticket_id"],
                    new_status=args["new_status"],
                    comment=args.get("comment"),
                ),
                tags=("ticketing", "write"),
            )
        )
