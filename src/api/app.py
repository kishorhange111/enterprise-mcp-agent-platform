"""ASGI application factory wiring MCP server, connectors, agent runtime, HITL, and telemetry."""

from __future__ import annotations

from dataclasses import dataclass

from starlette.applications import Starlette

from src.agent import AgentGraph, AgentRuntime, AgentState, HITLApprovalQueue, NodeResult
from src.api.routes import build_routes
from src.core import ToolCallRequest
from src.mcp import MCPServer, ToolRegistry
from src.mcp.connectors.docs import Document, KnowledgeBaseConnector
from src.mcp.connectors.tickets import TicketingConnector
from src.observability import AuditTrail, PlatformMetrics, TelemetryTracer
from src.security import RBACEngine


@dataclass
class PlatformContainer:
    """Dependency container holding all wired platform subsystems."""

    rbac: RBACEngine
    registry: ToolRegistry
    mcp_server: MCPServer
    runtime: AgentRuntime
    default_graph: AgentGraph
    hitl_queue: HITLApprovalQueue
    audit_trail: AuditTrail
    metrics: PlatformMetrics
    tracer: TelemetryTracer
    kb_connector: KnowledgeBaseConnector
    ticketing_connector: TicketingConnector


def _build_default_graph() -> AgentGraph:
    """Default triage graph: searches knowledge base, then synthesizes a grounded answer."""

    def retrieve_node(state: AgentState, mcp: MCPServer, ctx) -> NodeResult:
        res = mcp.invoke_tool(
            ToolCallRequest(
                tool_name="docs.search",
                arguments={"query": state.prompt, "top_k": 3},
                tenant_id=ctx.tenant_id,
                principal_id=ctx.principal.user_id,
                correlation_id=ctx.correlation_id,
            ),
            ctx.principal,
        )
        state.tool_results.append(res)
        docs = res.data.get("results", []) if res.success and isinstance(res.data, dict) else []
        return NodeResult(next_node="synthesize", state_updates={"retrieved_docs": docs})

    def synthesize_node(state: AgentState, mcp: MCPServer, ctx) -> NodeResult:
        docs = state.memory.get("retrieved_docs", [])
        titles = [d["title"] for d in docs]
        summary = (
            f"Found {len(docs)} relevant enterprise document(s): {', '.join(titles)}"
            if docs
            else "No matching knowledge base documents found for this tenant."
        )
        return NodeResult(
            next_node=None,
            final_output={"summary": summary, "citations": [d["doc_id"] for d in docs]},
        )

    return (
        AgentGraph("enterprise_triage")
        .add_node("retrieve", retrieve_node)
        .add_node("synthesize", synthesize_node)
        .set_entry_point("retrieve")
    )


def create_app(container: PlatformContainer | None = None) -> Starlette:
    """Create and wire the Enterprise MCP Agent Platform ASGI application."""
    if container is None:
        rbac = RBACEngine()
        registry = ToolRegistry()
        kb = KnowledgeBaseConnector()
        kb.ingest(
            Document(
                doc_id="DOC-SLA-01",
                tenant_id="acme",
                title="Enterprise SLA Incident Escalation Policy",
                content="P1 incidents must be acknowledged within 15 minutes and escalated to SRE.",
                classification="internal",
                tags=("sla", "runbook"),
            )
        )
        kb.register_tools(registry)

        tickets = TicketingConnector()
        tickets.register_tools(registry)

        audit = AuditTrail()
        metrics = PlatformMetrics()
        tracer = TelemetryTracer()

        mcp_server = MCPServer(registry=registry, rbac=rbac)
        mcp_server.add_post_hook(audit.make_mcp_hook())
        mcp_server.add_post_hook(metrics.make_mcp_hook())

        runtime = AgentRuntime(mcp_server)
        hitl = HITLApprovalQueue(rbac=rbac)
        container = PlatformContainer(
            rbac=rbac,
            registry=registry,
            mcp_server=mcp_server,
            runtime=runtime,
            default_graph=_build_default_graph(),
            hitl_queue=hitl,
            audit_trail=audit,
            metrics=metrics,
            tracer=tracer,
            kb_connector=kb,
            ticketing_connector=tickets,
        )

    routes = build_routes(
        mcp_server=container.mcp_server,
        runtime=container.runtime,
        default_graph=container.default_graph,
        hitl_queue=container.hitl_queue,
        audit_trail=container.audit_trail,
        metrics=container.metrics,
        tracer=container.tracer,
        rbac=container.rbac,
    )
    app = Starlette(routes=routes)
    app.state.container = container
    return app


app = create_app()
