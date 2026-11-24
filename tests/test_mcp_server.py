"""Unit tests for MCP server core and tool registry protocol."""

from __future__ import annotations

from src.core import Principal, RiskLevel, Role, TenantProfile, TenantQuota, TenantRegistry
from src.mcp import MCPServer, ToolRegistry, ToolSpec
from src.security import Permission


def _build_server() -> MCPServer:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="crm.lookup",
            description="Look up customer contact",
            connector="crm",
            required_permission=Permission.DOC_READ,
            risk_level=RiskLevel.LOW,
            input_schema={
                "type": "object",
                "properties": {"account_id": {"type": "string"}},
                "required": ["account_id"],
                "additionalProperties": False,
            },
            handler=lambda args, ctx: {
                "tenant": ctx.tenant_id,
                "account_id": args["account_id"],
                "contact": "ceo@acme.com",
            },
        )
    )
    registry.register(
        ToolSpec(
            name="ticket.create",
            description="Create a support ticket",
            connector="ticketing",
            required_permission=Permission.TICKET_WRITE,
            risk_level=RiskLevel.MEDIUM,
            input_schema={
                "type": "object",
                "properties": {"title": {"type": "string"}},
                "required": ["title"],
            },
            handler=lambda args, ctx: {"ticket_id": "TCK-1", "title": args["title"]},
        )
    )
    tenants = TenantRegistry()
    tenants.register(
        TenantProfile(
            tenant_id="acme",
            name="Acme Corp",
            quota=TenantQuota(allowed_connectors=("crm", "ticketing")),
        )
    )
    tenants.register(
        TenantProfile(
            tenant_id="starter-co",
            name="Starter Co",
            tier="starter",
            quota=TenantQuota(allowed_connectors=("crm",)),
        )
    )
    return MCPServer(registry=registry, tenant_registry=tenants)


def test_mcp_initialize_and_rbac_filtered_tools_list() -> None:
    server = _build_server()
    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    operator = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))

    init_resp = server.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, viewer)
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"

    viewer_tools = server.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, viewer)
    assert [t["name"] for t in viewer_tools["result"]["tools"]] == ["crm.lookup"]

    op_tools = server.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, operator)
    assert [t["name"] for t in op_tools["result"]["tools"]] == ["crm.lookup", "ticket.create"]


def test_mcp_tools_call_redacts_pii_and_validates_schema() -> None:
    server = _build_server()
    seen_hooks: list[str] = []
    server.add_post_hook(lambda req, res, p: seen_hooks.append(f"{req.tool_name}:{res.success}"))

    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    resp = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "crm.lookup", "arguments": {"account_id": "ACC-9"}},
        },
        viewer,
    )
    assert resp["result"]["isError"] is False
    assert resp["result"]["meta"]["redacted"] is True
    assert resp["result"]["content"]["contact"] == "[REDACTED_EMAIL]"
    assert seen_hooks == ["crm.lookup:True"]

    bad_schema = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "crm.lookup", "arguments": {"wrong_field": 123}},
        },
        viewer,
    )
    assert bad_schema["result"]["isError"] is True
    assert "Invalid arguments" in bad_schema["result"]["content"]["error"]


def test_mcp_denies_unauthorized_role_and_disallowed_connector() -> None:
    server = _build_server()
    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    denied_role = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {"name": "ticket.create", "arguments": {"title": "Outage"}},
        },
        viewer,
    )
    assert denied_role["result"]["isError"] is True
    assert "lacks permission" in denied_role["result"]["content"]["error"]

    starter_op = Principal(user_id="op2", tenant_id="starter-co", roles=(Role.OPERATOR,))
    denied_conn = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {"name": "ticket.create", "arguments": {"title": "Outage"}},
        },
        starter_op,
    )
    assert denied_conn["result"]["isError"] is True
    assert "not enabled for tenant" in denied_conn["result"]["content"]["error"]

    unknown = server.handle_rpc({"jsonrpc": "2.0", "id": 22, "method": "nope/method"}, viewer)
    assert unknown["error"]["code"] == -32601
