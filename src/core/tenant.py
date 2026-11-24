"""Multi-tenant execution context propagation and isolation enforcement."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator

from src.core.models import Principal, TenantProfile, new_id


class TenantIsolationError(PermissionError):
    """Raised when an operation attempts to access another tenant's resources."""


class TenantNotFoundError(KeyError):
    """Raised when a tenant profile cannot be resolved or is disabled."""


@dataclass(frozen=True)
class TenantContext:
    """Ambient execution context bound to the active request/task."""

    tenant_id: str
    principal: Principal
    correlation_id: str = field(default_factory=lambda: new_id("corr"))
    data_residency: str = "us-east-1"
    request_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.principal.tenant_id != self.tenant_id:
            raise TenantIsolationError(
                f"Principal tenant '{self.principal.tenant_id}' does not match "
                f"context tenant '{self.tenant_id}'"
            )


_TENANT_CTX: ContextVar[TenantContext | None] = ContextVar("enterprise_tenant_ctx", default=None)


def get_current_tenant_context() -> TenantContext | None:
    """Return the active TenantContext, or None if outside a tenant scope."""
    return _TENANT_CTX.get()


def require_tenant_context() -> TenantContext:
    """Return the active TenantContext or raise TenantIsolationError."""
    ctx = _TENANT_CTX.get()
    if ctx is None:
        raise TenantIsolationError("No active tenant context bound to current execution")
    return ctx


def assert_tenant_isolation(resource_tenant_id: str) -> None:
    """Ensure the requested resource belongs to the active tenant."""
    ctx = require_tenant_context()
    if resource_tenant_id != ctx.tenant_id:
        raise TenantIsolationError(
            f"Cross-tenant access denied: active='{ctx.tenant_id}', resource='{resource_tenant_id}'"
        )


@contextmanager
def tenant_scope(
    principal: Principal,
    *,
    correlation_id: str | None = None,
    data_residency: str | None = None,
    request_metadata: dict[str, Any] | None = None,
) -> Iterator[TenantContext]:
    """Bind a TenantContext for the duration of a synchronous/async call frame."""
    ctx = TenantContext(
        tenant_id=principal.tenant_id,
        principal=principal,
        correlation_id=correlation_id or new_id("corr"),
        data_residency=data_residency or principal.region,
        request_metadata=dict(request_metadata or {}),
    )
    token = _TENANT_CTX.set(ctx)
    try:
        yield ctx
    finally:
        _TENANT_CTX.reset(token)


class TenantRegistry:
    """In-memory registry for resolving and validating enterprise tenant profiles."""

    def __init__(self) -> None:
        self._tenants: dict[str, TenantProfile] = {}

    def register(self, profile: TenantProfile) -> None:
        """Register or update a tenant profile."""
        self._tenants[profile.tenant_id] = profile

    def get(self, tenant_id: str) -> TenantProfile:
        """Fetch an active tenant profile or raise TenantNotFoundError."""
        profile = self._tenants.get(tenant_id)
        if profile is None:
            raise TenantNotFoundError(f"Tenant '{tenant_id}' is not registered")
        if not profile.enabled:
            raise TenantNotFoundError(f"Tenant '{tenant_id}' is disabled")
        return profile

    def list_tenants(self, include_disabled: bool = False) -> list[TenantProfile]:
        """Return all registered tenant profiles."""
        if include_disabled:
            return list(self._tenants.values())
        return [profile for profile in self._tenants.values() if profile.enabled]

    def is_connector_allowed(self, tenant_id: str, connector_name: str) -> bool:
        """Check whether a tenant's quota allows using a specific MCP connector."""
        profile = self.get(tenant_id)
        return connector_name in profile.quota.allowed_connectors
