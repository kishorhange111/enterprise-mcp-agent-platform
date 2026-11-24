"""HTTP and SSE streaming route handlers for MCP, Agent Runtime, HITL, and Audit."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

from src.agent import AgentGraph, AgentRuntime, ApprovalError, HITLApprovalQueue
from src.core import AgentTask, Principal, Role, TenantIsolationError
from src.mcp import MCPServer
from src.observability import AuditTrail, PlatformMetrics, TelemetryTracer
from src.security import AuthorizationError, Permission, RBACEngine


def parse_principal_from_headers(request: Request) -> Principal:
    """Extract authenticated Principal from enterprise gateway headers."""
    tenant_id = request.headers.get("x-tenant-id", "").strip()
    user_id = request.headers.get("x-user-id", "").strip()
    if not tenant_id or not user_id:
        raise ValueError("Missing required 'X-Tenant-Id' or 'X-User-Id' header")

    raw_roles = request.headers.get("x-roles", "viewer")
    roles: list[Role] = []
    for item in raw_roles.split(","):
        cleaned = item.strip().lower()
        if cleaned:
            roles.append(Role(cleaned))
    if not roles:
        roles = [Role.VIEWER]

    region = request.headers.get("x-region", "us-east-1").strip() or "us-east-1"
    return Principal(user_id=user_id, tenant_id=tenant_id, roles=tuple(roles), region=region)


def build_routes(
    *,
    mcp_server: MCPServer,
    runtime: AgentRuntime,
    default_graph: AgentGraph,
    hitl_queue: HITLApprovalQueue,
    audit_trail: AuditTrail,
    metrics: PlatformMetrics,
    tracer: TelemetryTracer,
    rbac: RBACEngine,
) -> list[Route]:
    """Construct all Starlette/FastAPI-compatible ASGI routes."""

    async def healthz(_: Request) -> Response:
        return JSONResponse(
            {
                "status": "ok",
                "service": mcp_server.server_name,
                "version": mcp_server.server_version,
            }
        )

    async def prometheus_metrics(_: Request) -> Response:
        return PlainTextResponse(
            metrics.render_prometheus_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    async def mcp_rpc(request: Request) -> Response:
        try:
            principal = parse_principal_from_headers(request)
            payload = await request.json()
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        with tracer.start_span("http.mcp_rpc", attributes={"tenant_id": principal.tenant_id}):
            resp = mcp_server.handle_rpc(payload, principal)
        return JSONResponse(resp)

    async def run_agent(request: Request) -> Response:
        try:
            principal = parse_principal_from_headers(request)
            body = await request.json()
            rbac.authorize(principal, Permission.AGENT_EXECUTE)
        except AuthorizationError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        prompt = str(body.get("prompt", "")).strip()
        if not prompt:
            return JSONResponse({"error": "Field 'prompt' is required"}, status_code=400)

        task = AgentTask(
            tenant_id=principal.tenant_id,
            principal=principal,
            prompt=prompt,
            max_steps=int(body.get("max_steps", 10)),
            metadata=dict(body.get("metadata") or {}),
        )
        with tracer.start_span("http.agent_run", attributes={"tenant_id": principal.tenant_id}):
            state = runtime.run(task, default_graph)
        metrics.record_agent_run(tenant_id=principal.tenant_id, status=state.status.value)
        return JSONResponse(json.loads(state.model_dump_json()))

    async def stream_agent(request: Request) -> Response:
        try:
            principal = parse_principal_from_headers(request)
            body = await request.json()
            rbac.authorize(principal, Permission.AGENT_EXECUTE)
        except AuthorizationError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        prompt = str(body.get("prompt", "")).strip()
        if not prompt:
            return JSONResponse({"error": "Field 'prompt' is required"}, status_code=400)

        task = AgentTask(
            tenant_id=principal.tenant_id,
            principal=principal,
            prompt=prompt,
            max_steps=int(body.get("max_steps", 10)),
            metadata=dict(body.get("metadata") or {}),
        )

        captured_events: list[dict[str, Any]] = []
        state = runtime.run(task, default_graph, on_event=captured_events.append)
        metrics.record_agent_run(tenant_id=principal.tenant_id, status=state.status.value)

        async def _sse_generator() -> AsyncIterator[str]:
            for ev in captured_events:
                event_name = ev.get("event", "message")
                yield f"event: {event_name}\ndata: {json.dumps(ev)}\n\n"
            yield f"event: final_state\ndata: {state.model_dump_json()}\n\n"

        return StreamingResponse(_sse_generator(), media_type="text/event-stream")

    async def list_hitl_pending(request: Request) -> Response:
        try:
            principal = parse_principal_from_headers(request)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        pending = hitl_queue.list_pending(principal.tenant_id)
        return JSONResponse(
            {
                "tenant_id": principal.tenant_id,
                "pending": [json.loads(item.model_dump_json()) for item in pending],
            }
        )

    async def decide_hitl(request: Request) -> Response:
        approval_id = request.path_params["approval_id"]
        try:
            principal = parse_principal_from_headers(request)
            body = await request.json()
            decided = hitl_queue.decide(
                approval_id,
                reviewer=principal,
                approve=bool(body.get("approve", False)),
                note=str(body.get("note", "")),
            )
            return JSONResponse(json.loads(decided.model_dump_json()))
        except (AuthorizationError, TenantIsolationError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except (ApprovalError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)

    async def query_audit(request: Request) -> Response:
        try:
            principal = parse_principal_from_headers(request)
            rbac.authorize(principal, Permission.AUDIT_READ)
        except AuthorizationError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        events = audit_trail.query(tenant_id=principal.tenant_id)
        valid, broken = audit_trail.verify_integrity()
        return JSONResponse(
            {
                "tenant_id": principal.tenant_id,
                "integrity_valid": valid,
                "broken_at_sequence": broken,
                "events": [json.loads(ev.model_dump_json()) for ev in events],
            }
        )

    return [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/metrics", prometheus_metrics, methods=["GET"]),
        Route("/mcp/rpc", mcp_rpc, methods=["POST"]),
        Route("/v1/agents/run", run_agent, methods=["POST"]),
        Route("/v1/agents/stream", stream_agent, methods=["POST"]),
        Route("/v1/hitl/pending", list_hitl_pending, methods=["GET"]),
        Route("/v1/hitl/{approval_id}/decide", decide_hitl, methods=["POST"]),
        Route("/v1/audit", query_audit, methods=["GET"]),
    ]
