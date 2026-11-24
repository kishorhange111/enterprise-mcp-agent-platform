"""Core Pydantic domain models for the Enterprise MCP Agent Platform."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    """Generate a prefixed, collision-resistant identifier."""
    return f"{prefix}_{uuid4().hex[:12]}"


class Role(str, Enum):
    """Enterprise RBAC roles ordered from least to most privileged."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"
    SERVICE_ACCOUNT = "service_account"


class RiskLevel(str, Enum):
    """Operational risk classification for tools and agent actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """Lifecycle states of an agent execution task."""

    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"
    CANCELLED = "cancelled"


class Principal(BaseModel):
    """Authenticated caller identity scoped to a specific tenant."""

    model_config = ConfigDict(frozen=True)

    user_id: str = Field(..., min_length=1, max_length=128)
    tenant_id: str = Field(..., min_length=1, max_length=64)
    roles: tuple[Role, ...] = Field(default=(Role.VIEWER,))
    email: str | None = Field(default=None, max_length=256)
    region: str = Field(default="us-east-1", max_length=32)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or any(ch.isspace() for ch in cleaned):
            raise ValueError("tenant_id must be a non-empty identifier without whitespace")
        return cleaned

    def has_role(self, role: Role) -> bool:
        """Return True if the principal holds the requested role."""
        return role in self.roles


class TenantQuota(BaseModel):
    """Per-tenant resource limits and connector entitlements."""

    model_config = ConfigDict(frozen=True)

    max_requests_per_min: int = Field(default=120, ge=1, le=100_000)
    max_tool_calls_per_run: int = Field(default=15, ge=1, le=200)
    max_sql_rows: int = Field(default=500, ge=1, le=50_000)
    allowed_connectors: tuple[str, ...] = Field(
        default=("sql_readonly", "ticketing", "knowledge_base")
    )


class TenantProfile(BaseModel):
    """Configuration profile representing an enterprise customer tenant."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    tier: str = Field(default="enterprise", pattern="^(starter|growth|enterprise)$")
    data_residency: str = Field(default="us-east-1", max_length=32)
    quota: TenantQuota = Field(default_factory=TenantQuota)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    """Normalized MCP tool invocation request with tenant and tracing metadata."""

    call_id: str = Field(default_factory=lambda: new_id("call"))
    tool_name: str = Field(..., min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = Field(..., min_length=1, max_length=64)
    principal_id: str = Field(..., min_length=1, max_length=128)
    correlation_id: str = Field(default_factory=lambda: new_id("corr"))
    idempotency_key: str | None = Field(default=None, max_length=128)
    created_at: datetime = Field(default_factory=utc_now)


class ToolCallResult(BaseModel):
    """Structured result emitted by an MCP tool execution."""

    call_id: str
    tool_name: str
    success: bool
    data: Any = None
    error: str | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    redacted: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTask(BaseModel):
    """Top-level unit of work submitted to the agent runtime."""

    task_id: str = Field(default_factory=lambda: new_id("task"))
    tenant_id: str = Field(..., min_length=1, max_length=64)
    principal: Principal
    prompt: str = Field(..., min_length=1, max_length=16_000)
    status: TaskStatus = TaskStatus.PENDING
    max_steps: int = Field(default=10, ge=1, le=50)
    correlation_id: str = Field(default_factory=lambda: new_id("corr"))
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def check_tenant_matches_principal(self) -> AgentTask:
        if self.principal.tenant_id != self.tenant_id:
            raise ValueError("AgentTask tenant_id must match principal.tenant_id")
        return self
