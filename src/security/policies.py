"""Row-level security (RLS) and attribute-based access control (ABAC) policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from src.core.models import Principal, Role


class DataClassification(str, Enum):
    """Sensitivity tiers for enterprise records and documents."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


_CLASSIFICATION_RANK: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}

DEFAULT_ROLE_MAX_CLASSIFICATION: dict[Role, DataClassification] = {
    Role.VIEWER: DataClassification.PUBLIC,
    Role.ANALYST: DataClassification.INTERNAL,
    Role.SERVICE_ACCOUNT: DataClassification.INTERNAL,
    Role.OPERATOR: DataClassification.CONFIDENTIAL,
    Role.ADMIN: DataClassification.RESTRICTED,
}


@dataclass(frozen=True)
class RowLevelPolicy:
    """Declarative row-level access policy for a resource type."""

    resource_type: str
    tenant_field: str = "tenant_id"
    classification_field: str = "classification"
    region_field: str = "region"
    enforce_region_residency: bool = True
    role_max_classification: dict[Role, DataClassification] = field(
        default_factory=lambda: dict(DEFAULT_ROLE_MAX_CLASSIFICATION)
    )
    custom_predicate: Callable[[Principal, dict[str, Any]], bool] | None = None


class PolicyEngine:
    """Evaluates row-level security policies across SQL, ticket, and doc connectors."""

    def __init__(self) -> None:
        self._policies: dict[str, RowLevelPolicy] = {}

    def register_policy(self, policy: RowLevelPolicy) -> None:
        """Register a RowLevelPolicy for a given resource type."""
        self._policies[policy.resource_type] = policy

    def get_policy(self, resource_type: str) -> RowLevelPolicy:
        """Return registered policy or a strict default tenant+classification policy."""
        return self._policies.get(resource_type, RowLevelPolicy(resource_type=resource_type))

    def max_classification_for(
        self, principal: Principal, policy: RowLevelPolicy
    ) -> DataClassification:
        """Determine the highest data classification tier accessible to principal."""
        max_rank = -1
        best = DataClassification.PUBLIC
        for role in principal.roles:
            tier = policy.role_max_classification.get(role, DataClassification.PUBLIC)
            rank = _CLASSIFICATION_RANK[tier]
            if rank > max_rank:
                max_rank = rank
                best = tier
        return best

    def evaluate_row(
        self,
        principal: Principal,
        row: dict[str, Any],
        resource_type: str = "default",
    ) -> bool:
        """Return True iff the principal is permitted to view the given record."""
        policy = self.get_policy(resource_type)

        # 1. Strict tenant isolation (deny-by-default if tenant_id missing or mismatched)
        row_tenant = row.get(policy.tenant_field)
        if row_tenant != principal.tenant_id:
            return False

        # 2. Optional data-residency region check (admins bypass only if explicitly allowed)
        if policy.enforce_region_residency and policy.region_field in row:
            row_region = row.get(policy.region_field)
            if row_region and row_region != principal.region and Role.ADMIN not in principal.roles:
                return False

        # 3. Data classification tier check
        raw_cls = row.get(policy.classification_field, DataClassification.INTERNAL.value)
        try:
            row_cls = (
                raw_cls
                if isinstance(raw_cls, DataClassification)
                else DataClassification(str(raw_cls).lower())
            )
        except ValueError:
            return False

        max_allowed = self.max_classification_for(principal, policy)
        if _CLASSIFICATION_RANK[row_cls] > _CLASSIFICATION_RANK[max_allowed]:
            return False

        # 4. Optional custom ABAC predicate
        if policy.custom_predicate is not None and not policy.custom_predicate(principal, row):
            return False

        return True

    def filter_rows(
        self,
        principal: Principal,
        rows: list[dict[str, Any]],
        resource_type: str = "default",
    ) -> list[dict[str, Any]]:
        """Filter a collection of records to only those visible to the principal."""
        return [row for row in rows if self.evaluate_row(principal, row, resource_type)]

    def build_sql_tenant_predicate(
        self,
        principal: Principal,
        table_alias: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Generate a parameterized SQL WHERE predicate enforcing tenant isolation."""
        prefix = f"{table_alias}." if table_alias else ""
        return f"{prefix}tenant_id = :rls_tenant_id", {"rls_tenant_id": principal.tenant_id}
