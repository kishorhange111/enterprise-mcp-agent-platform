"""Unit tests for OpenTelemetry span tracing and Prometheus metrics instrumentation."""

from __future__ import annotations

import pytest

from src.core import Principal, Role
from src.mcp import MCPServer, ToolRegistry, ToolSpec
from src.observability import PlatformMetrics, TelemetryTracer


def test_telemetry_tracer_records_success_and_error_spans() -> None:
    tracer = TelemetryTracer(service_name="mcp-test")

    with tracer.start_span("agent.plan", attributes={"tenant_id": "acme"}) as attrs:
        attrs["step"] = 1

    with pytest.raises(RuntimeError):
        with tracer.start_span("mcp.tool", attributes={"tool": "sql.query"}):
            raise RuntimeError("db timeout")

    spans = tracer.get_spans()
    assert len(spans) == 2
    assert spans[0].name == "agent.plan"
    assert spans[0].status == "ok"
    assert spans[0].attributes["step"] == 1
    assert spans[1].status == "error"
    assert spans[1].error == "db timeout"


def test_prometheus_metrics_and_mcp_hook_exposition() -> None:
    metrics = PlatformMetrics()
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="health.ping",
            description="Ping",
            connector="core",
            input_schema={"type": "object", "properties": {}},
            handler=lambda args, ctx: {"pong": True},
        )
    )
    server = MCPServer(registry=registry)
    server.add_post_hook(metrics.make_mcp_hook())

    principal = Principal(user_id="u1", tenant_id="acme", roles=(Role.ANALYST,))
    server.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "health.ping", "arguments": {}},
        },
        principal,
    )
    metrics.record_guardrail_block(tenant_id="acme", rule="instruction_override")
    metrics.record_agent_run(tenant_id="acme", status="completed")
    metrics.set_hitl_pending(tenant_id="acme", count=3)

    text = metrics.render_prometheus_text()
    assert (
        'mcp_tool_calls_total{status="success",tenant_id="acme",tool_name="health.ping"} 1.0'
        in text
    )
    assert 'guardrail_blocks_total{rule="instruction_override",tenant_id="acme"} 1.0' in text
    assert 'hitl_pending_approvals{tenant_id="acme"} 3.0' in text
