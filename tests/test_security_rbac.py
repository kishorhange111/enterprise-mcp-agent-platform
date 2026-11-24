"""Unit tests for RBAC and row-level policy enforcement."""

from __future__ import annotations

import pytest

from src.core.models import Principal, Role
from src.security import (
    AuthorizationError,
    DataClassification,
    Permission,
    PolicyEngine,
    RBACEngine,
    RowLevelPolicy,
)


def test_rbac_default_role_permissions() -> None:
    rbac = RBACEngine()
    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    analyst = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))
    admin = Principal(user_id="adm1", tenant_id="acme", roles=(Role.ADMIN,))

    assert rbac.check(viewer, Permission.DOC_READ).allowed
    assert not rbac.check(viewer, Permission.SQL_READ).allowed
    assert rbac.check(analyst, Permission.SQL_READ).allowed
    assert not rbac.check(analyst, Permission.TICKET_WRITE).allowed
    assert rbac.check(admin, Permission.ADMIN_CONFIG).allowed

    with pytest.raises(AuthorizationError):
        rbac.authorize(viewer, Permission.TICKET_WRITE)


def test_rbac_tenant_override() -> None:
    rbac = RBACEngine()
    rbac.set_tenant_override("acme", Role.VIEWER, [Permission.DOC_READ, Permission.SQL_READ])

    acme_viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    other_viewer = Principal(user_id="v2", tenant_id="globex", roles=(Role.VIEWER,))

    assert rbac.check(acme_viewer, Permission.SQL_READ).allowed
    assert not rbac.check(other_viewer, Permission.SQL_READ).allowed


def test_row_level_policy_enforces_tenant_region_and_classification() -> None:
    engine = PolicyEngine()
    analyst = Principal(
        user_id="a1",
        tenant_id="acme",
        roles=(Role.ANALYST,),
        region="us-east-1",
    )
    operator = Principal(
        user_id="op1",
        tenant_id="acme",
        roles=(Role.OPERATOR,),
        region="us-east-1",
    )

    rows = [
        {"id": 1, "tenant_id": "acme", "region": "us-east-1", "classification": "public"},
        {"id": 2, "tenant_id": "acme", "region": "us-east-1", "classification": "internal"},
        {"id": 3, "tenant_id": "acme", "region": "us-east-1", "classification": "confidential"},
        {"id": 4, "tenant_id": "acme", "region": "eu-west-1", "classification": "internal"},
        {"id": 5, "tenant_id": "globex", "region": "us-east-1", "classification": "public"},
        {"id": 6, "region": "us-east-1", "classification": "public"},  # missing tenant_id
    ]

    analyst_visible = engine.filter_rows(analyst, rows, "documents")
    assert [r["id"] for r in analyst_visible] == [1, 2]

    operator_visible = engine.filter_rows(operator, rows, "documents")
    assert [r["id"] for r in operator_visible] == [1, 2, 3]


def test_row_level_custom_abac_predicate_and_sql_predicate() -> None:
    engine = PolicyEngine()
    engine.register_policy(
        RowLevelPolicy(
            resource_type="tickets",
            custom_predicate=lambda p, row: row.get("department") == p.attributes.get("dept"),
        )
    )

    principal = Principal(
        user_id="u1",
        tenant_id="acme",
        roles=(Role.OPERATOR,),
        attributes={"dept": "support"},
    )
    rows = [
        {"id": "T-1", "tenant_id": "acme", "classification": "internal", "department": "support"},
        {"id": "T-2", "tenant_id": "acme", "classification": "internal", "department": "finance"},
    ]
    assert [r["id"] for r in engine.filter_rows(principal, rows, "tickets")] == ["T-1"]

    clause, params = engine.build_sql_tenant_predicate(principal, table_alias="o")
    assert clause == "o.tenant_id = :rls_tenant_id"
    assert params == {"rls_tenant_id": "acme"}
    assert DataClassification.CONFIDENTIAL.value == "confidential"
