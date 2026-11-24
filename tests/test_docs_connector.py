"""Unit tests for the ACL-enforced document store / knowledge base MCP connector."""

from __future__ import annotations

import pytest

from src.core import Principal, Role, tenant_scope
from src.mcp import MCPServer, ToolRegistry
from src.mcp.connectors.docs import Document, KnowledgeBaseConnector


def _build_kb() -> KnowledgeBaseConnector:
    kb = KnowledgeBaseConnector()
    kb.ingest(
        Document(
            doc_id="DOC-1",
            tenant_id="acme",
            title="Kafka Consumer Lag Runbook",
            content="Check consumer group lag and rebalance partition assignment.",
            classification="internal",
            tags=("runbook", "kafka"),
            source_uri="wiki://runbooks/kafka-lag",
        )
    )
    kb.ingest(
        Document(
            doc_id="DOC-2",
            tenant_id="acme",
            title="Executive M&A Kafka Integration",
            content="Confidential acquisition details for Kafka telemetry vendor.",
            classification="confidential",
            allowed_groups=("exec-team",),
            tags=("strategy",),
        )
    )
    kb.ingest(
        Document(
            doc_id="DOC-3",
            tenant_id="globex",
            title="Globex Kafka Architecture",
            content="Globex private Kafka broker setup.",
            classification="public",
            tags=("kafka",),
        )
    )
    return kb


def test_kb_search_enforces_tenant_classification_and_group_acls() -> None:
    kb = _build_kb()
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))
    exec_op = Principal(
        user_id="op1",
        tenant_id="acme",
        roles=(Role.OPERATOR,),
        attributes={"groups": ["exec-team"]},
    )
    non_exec_op = Principal(
        user_id="op2",
        tenant_id="acme",
        roles=(Role.OPERATOR,),
        attributes={"groups": ["support"]},
    )

    with tenant_scope(analyst) as ctx:
        res = kb.search(ctx, query="kafka lag")
        assert [r["doc_id"] for r in res["results"]] == ["DOC-1"]

    with tenant_scope(non_exec_op) as ctx:
        res = kb.search(ctx, query="kafka")
        assert [r["doc_id"] for r in res["results"]] == ["DOC-1"]

    with tenant_scope(exec_op) as ctx:
        res = kb.search(ctx, query="kafka")
        assert {r["doc_id"] for r in res["results"]} == {"DOC-1", "DOC-2"}


def test_kb_get_document_denies_cross_tenant_and_unauthorized_groups() -> None:
    kb = _build_kb()
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))

    with tenant_scope(analyst) as ctx:
        doc = kb.get_document(ctx, "DOC-1")
        assert doc["title"] == "Kafka Consumer Lag Runbook"

        with pytest.raises(PermissionError):
            kb.get_document(ctx, "DOC-2")
        with pytest.raises(PermissionError):
            kb.get_document(ctx, "DOC-3")


def test_kb_mcp_server_registration() -> None:
    kb = _build_kb()
    registry = ToolRegistry()
    kb.register_tools(registry)
    server = MCPServer(registry=registry)

    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))
    resp = server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "docs.search", "arguments": {"query": "kafka", "tag": "runbook"}},
        },
        analyst,
    )
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"]["results"][0]["doc_id"] == "DOC-1"
