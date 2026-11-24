"""Human-in-the-loop (HITL) approval queue and SLA escalation workflow."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.core.models import Principal, RiskLevel, Role, new_id, utc_now
from src.core.tenant import TenantIsolationError
from src.security.rbac import Permission, RBACEngine


class ApprovalStatus(str, Enum):
    """Lifecycle states of a human-in-the-loop approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class ApprovalError(ValueError):
    """Raised when an approval transition violates workflow or separation-of-duties rules."""


class ApprovalRequest(BaseModel):
    """Record representing a high-risk agent action awaiting human review."""

    approval_id: str = Field(default_factory=lambda: new_id("apr"))
    task_id: str
    tenant_id: str
    requested_by: str
    action_name: str
    action_payload: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.HIGH
    status: ApprovalStatus = ApprovalStatus.PENDING
    escalation_target: str = "oncall-sre"
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    decided_by: str | None = None
    decision_note: str | None = None
    decided_at: datetime | None = None


class HITLApprovalQueue:
    """Tenant-scoped HITL approval queue with RBAC, four-eyes check, and SLA escalation."""

    def __init__(
        self,
        rbac: RBACEngine | None = None,
        *,
        enforce_four_eyes: bool = True,
    ) -> None:
        self.rbac = rbac or RBACEngine()
        self.enforce_four_eyes = enforce_four_eyes
        self._requests: dict[str, ApprovalRequest] = {}

    def submit(
        self,
        *,
        task_id: str,
        principal: Principal,
        action_name: str,
        action_payload: dict[str, Any],
        risk_level: RiskLevel = RiskLevel.HIGH,
        sla_seconds: int = 900,
        escalation_target: str = "oncall-sre",
        now: datetime | None = None,
    ) -> ApprovalRequest:
        """Enqueue a new action for human review."""
        created = now or utc_now()
        req = ApprovalRequest(
            task_id=task_id,
            tenant_id=principal.tenant_id,
            requested_by=principal.user_id,
            action_name=action_name,
            action_payload=dict(action_payload),
            risk_level=risk_level,
            escalation_target=escalation_target,
            created_at=created,
            expires_at=created + timedelta(seconds=sla_seconds),
        )
        self._requests[req.approval_id] = req
        return req

    def get(self, approval_id: str, tenant_id: str) -> ApprovalRequest:
        """Retrieve an approval request while enforcing tenant isolation."""
        req = self._requests.get(approval_id)
        if req is None:
            raise KeyError(f"Approval request '{approval_id}' not found")
        if req.tenant_id != tenant_id:
            raise TenantIsolationError(f"Cross-tenant access denied for approval '{approval_id}'")
        return req

    def decide(
        self,
        approval_id: str,
        *,
        reviewer: Principal,
        approve: bool,
        note: str = "",
        now: datetime | None = None,
    ) -> ApprovalRequest:
        """Approve or reject a pending HITL request with RBAC and separation-of-duties."""
        req = self.get(approval_id, reviewer.tenant_id)
        self.rbac.authorize(reviewer, Permission.HITL_APPROVE)

        if req.status != ApprovalStatus.PENDING:
            raise ApprovalError(
                f"Approval '{approval_id}' is already in terminal state '{req.status.value}'"
            )

        decision_time = now or utc_now()
        if decision_time > req.expires_at:
            req.status = ApprovalStatus.ESCALATED
            raise ApprovalError(
                f"Approval '{approval_id}' exceeded SLA deadline and has been escalated"
            )

        if (
            self.enforce_four_eyes
            and req.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            and reviewer.user_id == req.requested_by
            and Role.ADMIN not in reviewer.roles
        ):
            raise ApprovalError(
                "Four-eyes separation of duties: requester cannot self-approve high-risk actions"
            )

        req.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        req.decided_by = reviewer.user_id
        req.decision_note = note
        req.decided_at = decision_time
        return req

    def escalate_overdue(self, now: datetime | None = None) -> list[ApprovalRequest]:
        """Escalate all pending approvals that have breached their SLA deadline."""
        check_time = now or utc_now()
        escalated: list[ApprovalRequest] = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.PENDING and check_time > req.expires_at:
                req.status = ApprovalStatus.ESCALATED
                escalated.append(req)
        return escalated

    def list_pending(self, tenant_id: str) -> list[ApprovalRequest]:
        """List all pending approval requests for a tenant."""
        return [
            req
            for req in self._requests.values()
            if req.tenant_id == tenant_id and req.status == ApprovalStatus.PENDING
        ]
