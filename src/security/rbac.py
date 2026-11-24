"""Role-Based Access Control (RBAC) engine for enterprise MCP tools and agents."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from src.core.models import Principal, Role


class Permission(str, Enum):
    """Fine-grained platform permissions."""

    SQL_READ = "sql:read"
    TICKET_READ = "ticket:read"
    TICKET_WRITE = "ticket:write"
    DOC_READ = "doc:read"
    DOC_CONFIDENTIAL_READ = "doc:confidential:read"
    AGENT_EXECUTE = "agent:execute"
    HITL_APPROVE = "hitl:approve"
    AUDIT_READ = "audit:read"
    ADMIN_CONFIG = "admin:config"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.DOC_READ, Permission.TICKET_READ}),
    Role.ANALYST: frozenset(
        {
            Permission.DOC_READ,
            Permission.TICKET_READ,
            Permission.SQL_READ,
            Permission.AGENT_EXECUTE,
        }
    ),
    Role.OPERATOR: frozenset(
        {
            Permission.DOC_READ,
            Permission.DOC_CONFIDENTIAL_READ,
            Permission.TICKET_READ,
            Permission.TICKET_WRITE,
            Permission.SQL_READ,
            Permission.AGENT_EXECUTE,
            Permission.HITL_APPROVE,
        }
    ),
    Role.SERVICE_ACCOUNT: frozenset(
        {
            Permission.DOC_READ,
            Permission.TICKET_READ,
            Permission.TICKET_WRITE,
            Permission.SQL_READ,
            Permission.AGENT_EXECUTE,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}


class AuthorizationError(PermissionError):
    """Raised when a principal lacks the required permission for an action."""


@dataclass(frozen=True)
class AuthorizationDecision:
    """Structured result of an RBAC authorization check."""

    allowed: bool
    required_permission: Permission
    matched_roles: tuple[Role, ...]
    reason: str


class RBACEngine:
    """Evaluates role permissions with optional per-tenant role overrides."""

    def __init__(
        self,
        role_matrix: dict[Role, frozenset[Permission]] | None = None,
    ) -> None:
        self._base_matrix: dict[Role, frozenset[Permission]] = dict(role_matrix or ROLE_PERMISSIONS)
        self._tenant_overrides: dict[str, dict[Role, frozenset[Permission]]] = {}

    def set_tenant_override(
        self,
        tenant_id: str,
        role: Role,
        permissions: Iterable[Permission],
    ) -> None:
        """Override the permission set for a specific role within a tenant."""
        self._tenant_overrides.setdefault(tenant_id, {})[role] = frozenset(permissions)

    def effective_permissions(self, principal: Principal) -> frozenset[Permission]:
        """Compute the union of permissions granted to all roles on a principal."""
        overrides = self._tenant_overrides.get(principal.tenant_id, {})
        granted: set[Permission] = set()
        for role in principal.roles:
            perms = overrides.get(role, self._base_matrix.get(role, frozenset()))
            granted.update(perms)
        return frozenset(granted)

    def check(self, principal: Principal, permission: Permission) -> AuthorizationDecision:
        """Check whether principal holds the requested permission."""
        overrides = self._tenant_overrides.get(principal.tenant_id, {})
        matched = tuple(
            role
            for role in principal.roles
            if permission in overrides.get(role, self._base_matrix.get(role, frozenset()))
        )
        if matched:
            return AuthorizationDecision(
                allowed=True,
                required_permission=permission,
                matched_roles=matched,
                reason=f"Granted via roles: {[r.value for r in matched]}",
            )
        return AuthorizationDecision(
            allowed=False,
            required_permission=permission,
            matched_roles=(),
            reason=(
                f"Principal '{principal.user_id}' (roles={[r.value for r in principal.roles]}) "
                f"lacks permission '{permission.value}'"
            ),
        )

    def authorize(self, principal: Principal, permission: Permission) -> AuthorizationDecision:
        """Enforce permission check, raising AuthorizationError on deny."""
        decision = self.check(principal, permission)
        if not decision.allowed:
            raise AuthorizationError(decision.reason)
        return decision
