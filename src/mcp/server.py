"""Enterprise MCP Server implementing JSON-RPC 2.0 protocol with RBAC & guardrails."""

from __future__ import annotations

import time
from typing import Any, Callable

from src.core.models import Principal, ToolCallRequest, ToolCallResult
from src.core.tenant import TenantRegistry, tenant_scope
from src.mcp.registry import ToolNotFoundError, ToolRegistry, ToolValidationError
from src.security.guardrails import GuardrailMiddleware
from src.security.rbac import AuthorizationError, RBACEngine

MCP_PROTOCOL_VERSION = "2024-11-05"

ToolHook = Callable[[ToolCallRequest, ToolCallResult, Principal], None]


class MCPServer:
    """Multi-tenant Model Context Protocol (MCP) server with security enforcement."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        rbac: RBACEngine | None = None,
        guardrails: GuardrailMiddleware | None = None,
        tenant_registry: TenantRegistry | None = None,
        server_name: str = "enterprise-mcp-agent-platform",
        server_version: str = "0.1.0",
    ) -> None:
        self.registry = registry or ToolRegistry()
        self.rbac = rbac or RBACEngine()
        self.guardrails = guardrails or GuardrailMiddleware()
        self.tenant_registry = tenant_registry
        self.server_name = server_name
        self.server_version = server_version
        self._post_hooks: list[ToolHook] = []

    def add_post_hook(self, hook: ToolHook) -> None:
        """Register a callback invoked after every tool execution (e.g., audit/metrics)."""
        self._post_hooks.append(hook)

    def invoke_tool(
        self,
        request: ToolCallRequest,
        principal: Principal,
    ) -> ToolCallResult:
        """Execute a registered MCP tool with tenant isolation, RBAC, and PII redaction."""
        start = time.perf_counter()

        if request.tenant_id != principal.tenant_id:
            result = ToolCallResult(
                call_id=request.call_id,
                tool_name=request.tool_name,
                success=False,
                error="Cross-tenant tool invocation denied",
                latency_ms=0.0,
            )
            self._emit_hooks(request, result, principal)
            return result

        try:
            spec = self.registry.get(request.tool_name)

            if self.tenant_registry is not None and not self.tenant_registry.is_connector_allowed(
                principal.tenant_id, spec.connector
            ):
                raise AuthorizationError(
                    f"Connector '{spec.connector}' is not enabled for tenant '{principal.tenant_id}'"
                )

            if spec.required_permission is not None:
                self.rbac.authorize(principal, spec.required_permission)

            self.registry.validate_arguments(spec, request.arguments)

            with tenant_scope(
                principal,
                correlation_id=request.correlation_id,
                request_metadata={"tool_name": spec.name, "call_id": request.call_id},
            ) as ctx:
                raw_output = spec.handler(request.arguments, ctx)

            redacted = False
            redacted_entities: tuple[str, ...] = ()
            output_data = raw_output
            if spec.redact_output:
                output_data, redacted, redacted_entities = self.guardrails.sanitize_output(
                    raw_output
                )

            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
            result = ToolCallResult(
                call_id=request.call_id,
                tool_name=request.tool_name,
                success=True,
                data=output_data,
                latency_ms=elapsed_ms,
                redacted=redacted,
                metadata={
                    "connector": spec.connector,
                    "risk_level": spec.risk_level.value,
                    "redacted_entities": list(redacted_entities),
                },
            )
        except (ToolNotFoundError, ToolValidationError, AuthorizationError, PermissionError) as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
            result = ToolCallResult(
                call_id=request.call_id,
                tool_name=request.tool_name,
                success=False,
                error=str(exc),
                latency_ms=elapsed_ms,
                metadata={"error_type": type(exc).__name__},
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
            result = ToolCallResult(
                call_id=request.call_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Tool execution failed: {exc}",
                latency_ms=elapsed_ms,
                metadata={"error_type": type(exc).__name__},
            )

        self._emit_hooks(request, result, principal)
        return result

    def handle_rpc(
        self,
        payload: dict[str, Any],
        principal: Principal,
    ) -> dict[str, Any]:
        """Handle a JSON-RPC 2.0 MCP request (`initialize`, `tools/list`, `tools/call`)."""
        rpc_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params") or {}

        if payload.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return self._rpc_error(rpc_id, -32600, "Invalid JSON-RPC 2.0 request")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.server_version,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            }

        if method == "tools/list":
            descriptors = self.registry.list_mcp_descriptors(principal, self.rbac)
            if self.tenant_registry is not None:
                descriptors = [
                    d
                    for d in descriptors
                    if self.tenant_registry.is_connector_allowed(
                        principal.tenant_id, d["annotations"]["connector"]
                    )
                ]
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"tools": descriptors},
            }

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return self._rpc_error(rpc_id, -32602, "tools/call requires 'name' and 'arguments'")

            req = ToolCallRequest(
                tool_name=tool_name,
                arguments=arguments,
                tenant_id=principal.tenant_id,
                principal_id=principal.user_id,
                idempotency_key=params.get("idempotencyKey"),
            )
            res = self.invoke_tool(req, principal)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "isError": not res.success,
                    "content": res.data if res.success else {"error": res.error},
                    "meta": {
                        "callId": res.call_id,
                        "latencyMs": res.latency_ms,
                        "redacted": res.redacted,
                    },
                },
            }

        return self._rpc_error(rpc_id, -32601, f"Method not found: {method}")

    def _emit_hooks(
        self,
        request: ToolCallRequest,
        result: ToolCallResult,
        principal: Principal,
    ) -> None:
        for hook in self._post_hooks:
            hook(request, result, principal)

    @staticmethod
    def _rpc_error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": code, "message": message},
        }
