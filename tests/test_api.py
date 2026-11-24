"""Integration tests for the HTTP API, MCP RPC endpoint, SSE streaming, HITL, and metrics."""

from __future__ import annotations

from starlette.testclient import TestClient

from src.api import create_app
from src.core import Principal, RiskLevel, Role


def test_healthz_mcp_rpc_and_metrics_endpoints() -> None:
    app = create_app()
    client = TestClient(app)

    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    rpc_resp = client.post(
        "/mcp/rpc",
        headers={"X-Tenant-Id": "acme", "X-User-Id": "a1", "X-Roles": "analyst"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "docs.search", "arguments": {"query": "SLA escalation"}},
        },
    )
    assert rpc_resp.status_code == 200
    body = rpc_resp.json()
    assert body["result"]["isError"] is False
    assert body["result"]["content"]["results"][0]["doc_id"] == "DOC-SLA-01"

    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    assert "mcp_tool_calls_total" in metrics_resp.text


def test_agent_run_and_sse_streaming_endpoints() -> None:
    app = create_app()
    client = TestClient(app)
    headers = {"X-Tenant-Id": "acme", "X-User-Id": "a1", "X-Roles": "analyst"}

    run_resp = client.post("/v1/agents/run", headers=headers, json={"prompt": "SLA escalation"})
    assert run_resp.status_code == 200
    data = run_resp.json()
    assert data["status"] == "completed"
    assert "DOC-SLA-01" in data["final_output"]["citations"]

    stream_resp = client.post(
        "/v1/agents/stream", headers=headers, json={"prompt": "SLA escalation"}
    )
    assert stream_resp.status_code == 200
    assert "text/event-stream" in stream_resp.headers["content-type"]
    assert "event: task_started" in stream_resp.text
    assert "event: step_completed" in stream_resp.text
    assert "event: final_state" in stream_resp.text

    # Viewer lacks AGENT_EXECUTE permission
    denied = client.post(
        "/v1/agents/run",
        headers={"X-Tenant-Id": "acme", "X-User-Id": "v1", "X-Roles": "viewer"},
        json={"prompt": "SLA"},
    )
    assert denied.status_code == 403


def test_hitl_and_audit_endpoints() -> None:
    app = create_app()
    container = app.state.container
    requester = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))
    req = container.hitl_queue.submit(
        task_id="task_99",
        principal=requester,
        action_name="tickets.create",
        action_payload={"priority": "P1"},
        risk_level=RiskLevel.HIGH,
    )

    client = TestClient(app)
    pending = client.get(
        "/v1/hitl/pending",
        headers={"X-Tenant-Id": "acme", "X-User-Id": "op2", "X-Roles": "operator"},
    )
    assert pending.status_code == 200
    assert len(pending.json()["pending"]) == 1

    decide = client.post(
        f"/v1/hitl/{req.approval_id}/decide",
        headers={"X-Tenant-Id": "acme", "X-User-Id": "op2", "X-Roles": "operator"},
        json={"approve": True, "note": "Looks good"},
    )
    assert decide.status_code == 200
    assert decide.json()["status"] == "approved"

    audit = client.get(
        "/v1/audit",
        headers={"X-Tenant-Id": "acme", "X-User-Id": "adm1", "X-Roles": "admin"},
    )
    assert audit.status_code == 200
    assert audit.json()["integrity_valid"] is True
