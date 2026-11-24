"""Prometheus metrics instrumentation for MCP tools, guardrails, agents, and HITL."""

from __future__ import annotations

from typing import Callable

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from src.core.models import Principal, ToolCallRequest, ToolCallResult


class PlatformMetrics:
    """Isolated Prometheus metrics registry for multi-tenant MCP & agent observability."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()

        self.tool_calls_total = Counter(
            "mcp_tool_calls_total",
            "Total MCP tool invocations partitioned by tenant, tool, and status",
            labelnames=("tenant_id", "tool_name", "status"),
            registry=self.registry,
        )
        self.tool_latency_ms = Histogram(
            "mcp_tool_latency_ms",
            "Latency distribution of MCP tool calls in milliseconds",
            labelnames=("tenant_id", "tool_name"),
            buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
            registry=self.registry,
        )
        self.guardrail_blocks_total = Counter(
            "guardrail_blocks_total",
            "Total requests blocked by security guardrails",
            labelnames=("tenant_id", "rule"),
            registry=self.registry,
        )
        self.agent_runs_total = Counter(
            "agent_runs_total",
            "Total agent runtime executions by tenant and terminal status",
            labelnames=("tenant_id", "status"),
            registry=self.registry,
        )
        self.hitl_pending_approvals = Gauge(
            "hitl_pending_approvals",
            "Current number of pending HITL approval requests per tenant",
            labelnames=("tenant_id",),
            registry=self.registry,
        )

    def record_tool_call(
        self,
        *,
        tenant_id: str,
        tool_name: str,
        success: bool,
        latency_ms: float,
    ) -> None:
        """Increment tool call counter and observe latency histogram."""
        status = "success" if success else "error"
        self.tool_calls_total.labels(
            tenant_id=tenant_id, tool_name=tool_name, status=status
        ).inc()
        self.tool_latency_ms.labels(tenant_id=tenant_id, tool_name=tool_name).observe(latency_ms)

    def record_guardrail_block(self, *, tenant_id: str, rule: str) -> None:
        """Increment security guardrail block counter."""
        self.guardrail_blocks_total.labels(tenant_id=tenant_id, rule=rule).inc()

    def record_agent_run(self, *, tenant_id: str, status: str) -> None:
        """Increment agent run terminal status counter."""
        self.agent_runs_total.labels(tenant_id=tenant_id, status=status).inc()

    def set_hitl_pending(self, *, tenant_id: str, count: int) -> None:
        """Update gauge for pending HITL approvals."""
        self.hitl_pending_approvals.labels(tenant_id=tenant_id).set(count)

    def render_prometheus_text(self) -> str:
        """Render metrics in standard Prometheus text exposition format."""
        return generate_latest(self.registry).decode("utf-8")

    def make_mcp_hook(self) -> Callable[[ToolCallRequest, ToolCallResult, Principal], None]:
        """Return an MCPServer post-execution hook to record tool metrics automatically."""

        def _hook(req: ToolCallRequest, res: ToolCallResult, principal: Principal) -> None:
            self.record_tool_call(
                tenant_id=principal.tenant_id,
                tool_name=req.tool_name,
                success=res.success,
                latency_ms=res.latency_ms,
            )

        return _hook
