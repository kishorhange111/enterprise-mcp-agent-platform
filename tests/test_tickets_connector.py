"""Unit tests for the REST/Ticketing MCP connector with idempotency keys."""

from __future__ import annotations

import pytest

from src.core import Principal, Role, TenantIsolationError, tenant_scope
from src.mcp import MCPServer, ToolRegistry
from src.mcp.connectors.tickets import (
    IdempotencyConflictError,
    InvalidTicketTransitionError,
    TicketingConnector,
)


def test_ticketing_idempotency_replay_and_conflict() -> None:
    connector = TicketingConnector()
    op = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))

    with tenant_scope(op) as ctx:
        first = connector.create_ticket(
            ctx,
            title="ETL pipeline lag",
            description="Kafka consumer lag > 15m",
            priority="P1",
            idempotency_key="idem-etl-001",
            tags=["data", "sla"],
        )
        assert first["idempotent_replay"] is False
        ticket_id = first["ticket"]["ticket_id"]

        # Exact replay returns the same ticket without duplicating
        replay = connector.create_ticket(
            ctx,
            title="ETL pipeline lag",
            description="Kafka consumer lag > 15m",
            priority="P1",
            idempotency_key="idem-etl-001",
            tags=["sla", "data"],
        )
        assert replay["idempotent_replay"] is True
        assert replay["ticket"]["ticket_id"] == ticket_id
        assert connector.list_tickets(ctx)["count"] == 1

        # Reusing the same idempotency key with a different payload must conflict
        with pytest.raises(IdempotencyConflictError):
            connector.create_ticket(
                ctx,
                title="Different incident",
                description="Mutated body",
                priority="P2",
                idempotency_key="idem-etl-001",
            )


def test_ticketing_tenant_isolation_and_transitions() -> None:
    connector = TicketingConnector()
    acme_op = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))
    globex_op = Principal(user_id="op2", tenant_id="globex", roles=(Role.OPERATOR,))

    with tenant_scope(acme_op) as ctx:
        created = connector.create_ticket(
            ctx, title="SSO error", description="SAML assertion expired", priority="P2"
        )
        tid = created["ticket"]["ticket_id"]
        moved = connector.transition_ticket(
            ctx, ticket_id=tid, new_status="in_progress", comment="Investigating"
        )
        assert moved["ticket"]["status"] == "in_progress"
        assert moved["ticket"]["comments"] == ["Investigating"]

        with pytest.raises(InvalidTicketTransitionError):
            connector.transition_ticket(ctx, ticket_id=tid, new_status="in_progress")

    with tenant_scope(globex_op) as other_ctx:
        assert connector.list_tickets(other_ctx)["count"] == 0
        with pytest.raises(TenantIsolationError):
            connector.get_ticket(other_ctx, tid)


def test_ticketing_connector_mcp_integration() -> None:
    registry = ToolRegistry()
    connector = TicketingConnector()
    connector.register_tools(registry)
    server = MCPServer(registry=registry)

    op = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))
    resp = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "tickets.create",
                "arguments": {
                    "title": "API 502 spike",
                    "description": "Reported by ops@acme.com",
                    "priority": "P1",
                    "idempotency_key": "k-502",
                },
            },
        },
        op,
    )
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"]["ticket"]["priority"] == "P1"
    assert "[REDACTED_EMAIL]" in resp["result"]["content"]["ticket"]["description"]
