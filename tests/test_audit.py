"""Unit tests for the hash-chained immutable audit trail and MCP hook."""

from __future__ import annotations

import json

from src.core import Principal, Role
from src.mcp import MCPServer, ToolRegistry, ToolSpec
from src.observability import AuditTrail
from src.security import Permission


def test_audit_trail_hash_chain_and_tamper_detection() -> None:
    trail = AuditTrail()
    e1 = trail.record(
        tenant_id="acme",
        principal_id="u1",
        action="sql.query",
        resource="orders",
        outcome="success",
        correlation_id="c1",
    )
    e2 = trail.record(
        tenant_id="acme",
        principal_id="u1",
        action="tickets.create",
        resource="TCK-1",
        outcome="success",
        correlation_id="c1",
    )
    assert e2.prev_hash == e1.event_hash
    assert trail.verify_integrity() == (True, None)

    # Export JSONL scoped to tenant
    lines = trail.export_jsonl("acme").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["action"] == "sql.query"

    # Simulate tampering with record #1
    trail._events[0].outcome = "tampered"
    valid, broken_seq = trail.verify_integrity()
    assert valid is False
    assert broken_seq == 1


def test_audit_trail_mcp_hook_records_allowed_and_denied_calls() -> None:
    trail = AuditTrail()
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="admin.rotate_keys",
            description="Rotate tenant keys",
            connector="admin",
            required_permission=Permission.ADMIN_CONFIG,
            input_schema={"type": "object", "properties": {}},
            handler=lambda args, ctx: {"rotated": True},
        )
    )
    server = MCPServer(registry=registry)
    server.add_post_hook(trail.make_mcp_hook())

    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    admin = Principal(user_id="adm1", tenant_id="acme", roles=(Role.ADMIN,))

    server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "admin.rotate_keys", "arguments": {}},
        },
        viewer,
    )
    server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "admin.rotate_keys", "arguments": {}},
        },
        admin,
    )

    events = trail.query(tenant_id="acme", action="mcp.tool.invoke")
    assert [e.outcome for e in events] == ["denied_or_error", "success"]
    assert trail.verify_integrity() == (True, None)
