"""Unit tests for core domain models and tenant context isolation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.core import (
    AgentTask,
    Principal,
    Role,
    TaskStatus,
    TenantContext,
    TenantIsolationError,
    TenantNotFoundError,
    TenantProfile,
    TenantQuota,
    TenantRegistry,
    ToolCallRequest,
    ToolCallResult,
    assert_tenant_isolation,
    get_current_tenant_context,
    require_tenant_context,
    tenant_scope,
)


def test_principal_validation_and_roles() -> None:
    principal = Principal(
        user_id="usr_101",
        tenant_id="acme-corp",
        roles=(Role.ANALYST, Role.OPERATOR),
        email="alice@acme.example",
    )
    assert principal.has_role(Role.ANALYST)
    assert not principal.has_role(Role.ADMIN)

    with pytest.raises(ValidationError):
        Principal(user_id="usr_102", tenant_id="bad tenant")


def test_agent_task_enforces_matching_tenant() -> None:
    principal = Principal(user_id="usr_1", tenant_id="tenant-a", roles=(Role.ANALYST,))
    task = AgentTask(
        tenant_id="tenant-a",
        principal=principal,
        prompt="Summarize open P1 incidents",
    )
    assert task.status == TaskStatus.PENDING
    assert task.task_id.startswith("task_")

    with pytest.raises(ValidationError):
        AgentTask(
            tenant_id="tenant-b",
            principal=principal,
            prompt="Attempt cross-tenant task",
        )


def test_tenant_scope_propagation_and_nesting() -> None:
    assert get_current_tenant_context() is None
    with pytest.raises(TenantIsolationError):
        require_tenant_context()

    p_a = Principal(user_id="u1", tenant_id="tenant-a", roles=(Role.ANALYST,))
    p_b = Principal(user_id="u2", tenant_id="tenant-b", roles=(Role.ADMIN,))

    with tenant_scope(p_a, correlation_id="corr_outer") as outer:
        assert require_tenant_context().tenant_id == "tenant-a"
        assert outer.correlation_id == "corr_outer"
        assert_tenant_isolation("tenant-a")

        with pytest.raises(TenantIsolationError):
            assert_tenant_isolation("tenant-b")

        with tenant_scope(p_b) as inner:
            assert inner.tenant_id == "tenant-b"
            assert_tenant_isolation("tenant-b")

        assert require_tenant_context().tenant_id == "tenant-a"

    assert get_current_tenant_context() is None


def test_tenant_context_rejects_mismatched_principal() -> None:
    principal = Principal(user_id="u1", tenant_id="tenant-a")
    with pytest.raises(TenantIsolationError):
        TenantContext(tenant_id="tenant-b", principal=principal)


def test_tenant_registry_and_connector_entitlements() -> None:
    registry = TenantRegistry()
    active = TenantProfile(
        tenant_id="acme",
        name="Acme Corp",
        tier="enterprise",
        quota=TenantQuota(max_sql_rows=1000, allowed_connectors=("sql_readonly", "ticketing")),
    )
    disabled = TenantProfile(
        tenant_id="legacy",
        name="Legacy Co",
        tier="starter",
        enabled=False,
    )
    registry.register(active)
    registry.register(disabled)

    assert registry.get("acme").name == "Acme Corp"
    assert registry.is_connector_allowed("acme", "sql_readonly")
    assert not registry.is_connector_allowed("acme", "knowledge_base")
    assert len(registry.list_tenants()) == 1
    assert len(registry.list_tenants(include_disabled=True)) == 2

    with pytest.raises(TenantNotFoundError):
        registry.get("legacy")
    with pytest.raises(TenantNotFoundError):
        registry.get("unknown")


def test_tool_call_request_and_result_models() -> None:
    req = ToolCallRequest(
        tool_name="sql.query",
        arguments={"sql": "SELECT 1"},
        tenant_id="acme",
        principal_id="u1",
        idempotency_key="idem-123",
    )
    res = ToolCallResult(
        call_id=req.call_id,
        tool_name=req.tool_name,
        success=True,
        data={"rows": [{"1": 1}]},
        latency_ms=12.4,
    )
    assert res.call_id == req.call_id
    assert res.success is True
