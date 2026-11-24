"""MCP tool registry with JSON-Schema validation and RBAC-aware discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import jsonschema

from src.core.models import Principal, RiskLevel
from src.core.tenant import TenantContext
from src.security.rbac import Permission, RBACEngine


class ToolNotFoundError(KeyError):
    """Raised when a requested MCP tool is not registered."""


class ToolValidationError(ValueError):
    """Raised when tool call arguments fail JSON-Schema validation."""


ToolHandler = Callable[[dict[str, Any], TenantContext], Any]


@dataclass(frozen=True)
class ToolSpec:
    """Declarative specification for an enterprise MCP tool."""

    name: str
    description: str
    connector: str
    input_schema: dict[str, Any]
    handler: ToolHandler
    required_permission: Permission | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    requires_hitl: bool = False
    redact_output: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_mcp_descriptor(self) -> dict[str, Any]:
        """Serialize tool metadata into the MCP tools/list descriptor format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "connector": self.connector,
                "riskLevel": self.risk_level.value,
                "requiresHitl": self.requires_hitl,
                "tags": list(self.tags),
            },
        }


class ToolRegistry:
    """Thread-safe registry for MCP tool definitions and argument validation."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec, *, overwrite: bool = False) -> None:
        """Register an MCP tool specification."""
        if not overwrite and spec.name in self._tools:
            raise ValueError(f"Tool '{spec.name}' is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        """Fetch a registered ToolSpec by name."""
        spec = self._tools.get(name)
        if spec is None:
            raise ToolNotFoundError(f"MCP tool '{name}' is not registered")
        return spec

    def list_specs(
        self,
        principal: Principal | None = None,
        rbac: RBACEngine | None = None,
    ) -> list[ToolSpec]:
        """List registered tools, optionally filtered by principal permissions."""
        specs = list(self._tools.values())
        if principal is not None and rbac is not None:
            specs = [
                spec
                for spec in specs
                if spec.required_permission is None
                or rbac.check(principal, spec.required_permission).allowed
            ]
        return sorted(specs, key=lambda s: s.name)

    def list_mcp_descriptors(
        self,
        principal: Principal | None = None,
        rbac: RBACEngine | None = None,
    ) -> list[dict[str, Any]]:
        """Return MCP tools/list descriptors visible to the caller."""
        return [spec.to_mcp_descriptor() for spec in self.list_specs(principal, rbac)]

    def validate_arguments(self, spec: ToolSpec, arguments: dict[str, Any]) -> None:
        """Validate tool call arguments against the tool's JSON Schema."""
        try:
            jsonschema.validate(instance=arguments, schema=spec.input_schema)
        except jsonschema.ValidationError as exc:
            raise ToolValidationError(
                f"Invalid arguments for tool '{spec.name}': {exc.message}"
            ) from exc
