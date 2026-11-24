"""Unit tests for the HITL approval queue and SLA escalation workflow."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.agent import ApprovalError, ApprovalStatus, HITLApprovalQueue
from src.core import Principal, RiskLevel, Role, TenantIsolationError
from src.security import AuthorizationError


def test_hitl_approval_four_eyes_and_rbac() -> None:
    queue = HITLApprovalQueue(enforce_four_eyes=True)
    requester = Principal(user_id="op1", tenant_id="acme", roles=(Role.OPERATOR,))
    peer_reviewer = Principal(user_id="op2", tenant_id="acme", roles=(Role.OPERATOR,))
    viewer = Principal(user_id="v1", tenant_id="acme", roles=(Role.VIEWER,))
    other_tenant = Principal(user_id="op3", tenant_id="globex", roles=(Role.OPERATOR,))

    req = queue.submit(
        task_id="task_1",
        principal=requester,
        action_name="tickets.create",
        action_payload={"priority": "P1"},
        risk_level=RiskLevel.HIGH,
    )
    assert len(queue.list_pending("acme")) == 1

    # Viewer lacks HITL_APPROVE permission
    with pytest.raises(AuthorizationError):
        queue.decide(req.approval_id, reviewer=viewer, approve=True)

    # Cross-tenant operator denied
    with pytest.raises(TenantIsolationError):
        queue.decide(req.approval_id, reviewer=other_tenant, approve=True)

    # Requester cannot self-approve HIGH risk action
    with pytest.raises(ApprovalError, match="Four-eyes"):
        queue.decide(req.approval_id, reviewer=requester, approve=True)

    # Peer operator approves successfully
    decided = queue.decide(
        req.approval_id,
        reviewer=peer_reviewer,
        approve=True,
        note="Verified incident severity",
    )
    assert decided.status == ApprovalStatus.APPROVED
    assert decided.decided_by == "op2"
    assert len(queue.list_pending("acme")) == 0


def test_hitl_sla_escalation_on_overdue_requests() -> None:
    queue = HITLApprovalQueue()
    requester = Principal(user_id="a1", tenant_id="acme", roles=(Role.ANALYST,))
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    req = queue.submit(
        task_id="task_2",
        principal=requester,
        action_name="prod.restart",
        action_payload={"service": "worker"},
        sla_seconds=300,
        escalation_target="vp-eng-oncall",
        now=t0,
    )
    assert queue.escalate_overdue(now=t0 + timedelta(seconds=100)) == []

    escalated = queue.escalate_overdue(now=t0 + timedelta(seconds=301))
    assert len(escalated) == 1
    assert escalated[0].approval_id == req.approval_id
    assert escalated[0].status == ApprovalStatus.ESCALATED
    assert escalated[0].escalation_target == "vp-eng-oncall"
