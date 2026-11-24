"""Agent trajectory, tool-call F1, and step-efficiency evaluation harness."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from src.agent import AgentGraph, AgentRuntime, AgentState
from src.core import AgentTask, Principal, Role, TaskStatus


class GoldenTrajectoryCase(BaseModel):
    """Single golden test case for evaluating agent tool selection and outcomes."""

    case_id: str
    tenant_id: str = "acme"
    role: Role = Role.ANALYST
    prompt: str
    expected_status: TaskStatus = TaskStatus.COMPLETED
    expected_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    max_steps: int = 10
    required_output_substrings: list[str] = Field(default_factory=list)


class TrajectoryScore(BaseModel):
    """Detailed per-case evaluation metrics for an agent execution trajectory."""

    case_id: str
    passed: bool
    status_match: bool
    tool_precision: float
    tool_recall: float
    tool_f1: float
    forbidden_tool_violation: bool
    step_efficiency: float
    output_match: bool
    failure_reasons: list[str] = Field(default_factory=list)


class TrajectoryEvalReport(BaseModel):
    """Aggregated evaluation report across a golden trajectory benchmark suite."""

    total_cases: int
    passed_cases: int
    pass_rate: float
    mean_tool_f1: float
    mean_step_efficiency: float
    scores: list[TrajectoryScore]


def load_golden_cases(path: str | Path) -> list[GoldenTrajectoryCase]:
    """Load golden trajectory cases from a JSON file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [GoldenTrajectoryCase.model_validate(item) for item in raw]


class TrajectoryEvaluator:
    """Scores actual AgentState trajectories against GoldenTrajectoryCase expectations."""

    def evaluate_state(self, case: GoldenTrajectoryCase, state: AgentState) -> TrajectoryScore:
        """Compute precision/recall/F1, efficiency, and pass/fail for one trajectory."""
        failures: list[str] = []
        status_match = state.status == case.expected_status
        if not status_match:
            failures.append(
                f"Expected status '{case.expected_status.value}', got '{state.status.value}'"
            )

        actual_tools = [r.tool_name for r in state.tool_results]
        actual_set = set(actual_tools)
        expected_set = set(case.expected_tools)
        forbidden_set = set(case.forbidden_tools)

        forbidden_hit = bool(actual_set & forbidden_set)
        if forbidden_hit:
            failures.append(f"Invoked forbidden tool(s): {sorted(actual_set & forbidden_set)}")

        if not expected_set and not actual_set:
            precision = recall = f1 = 1.0
        elif not expected_set:
            precision = 0.0
            recall = 1.0
            f1 = 0.0
        elif not actual_set:
            precision = 0.0
            recall = 0.0
            f1 = 0.0
        else:
            tp = len(actual_set & expected_set)
            precision = tp / len(actual_set)
            recall = tp / len(expected_set)
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        if expected_set and recall < 1.0:
            failures.append(f"Missing expected tools: {sorted(expected_set - actual_set)}")

        step_efficiency = (
            1.0
            if state.step_count <= case.max_steps
            else round(case.max_steps / max(1, state.step_count), 3)
        )
        if state.step_count > case.max_steps:
            failures.append(f"Step count {state.step_count} exceeded budget {case.max_steps}")

        serialized_out = json.dumps(state.final_output, default=str).lower()
        output_match = all(sub.lower() in serialized_out for sub in case.required_output_substrings)
        if not output_match:
            failures.append(
                f"Final output missing required substrings: {case.required_output_substrings}"
            )

        passed = (
            status_match
            and not forbidden_hit
            and (not expected_set or recall == 1.0)
            and output_match
            and state.step_count <= case.max_steps
        )
        return TrajectoryScore(
            case_id=case.case_id,
            passed=passed,
            status_match=status_match,
            tool_precision=round(precision, 4),
            tool_recall=round(recall, 4),
            tool_f1=round(f1, 4),
            forbidden_tool_violation=forbidden_hit,
            step_efficiency=round(step_efficiency, 4),
            output_match=output_match,
            failure_reasons=failures,
        )

    def run_suite(
        self,
        cases: list[GoldenTrajectoryCase],
        runtime: AgentRuntime,
        graph: AgentGraph,
    ) -> TrajectoryEvalReport:
        """Execute every golden case against AgentRuntime and aggregate benchmark metrics."""
        scores: list[TrajectoryScore] = []
        for case in cases:
            principal = Principal(
                user_id=f"eval_{case.case_id}",
                tenant_id=case.tenant_id,
                roles=(case.role,),
            )
            task = AgentTask(
                tenant_id=case.tenant_id,
                principal=principal,
                prompt=case.prompt,
                max_steps=case.max_steps,
            )
            state = runtime.run(task, graph)
            scores.append(self.evaluate_state(case, state))

        total = len(scores)
        passed = sum(1 for s in scores if s.passed)
        mean_f1 = round(sum(s.tool_f1 for s in scores) / total, 4) if total else 0.0
        mean_eff = round(sum(s.step_efficiency for s in scores) / total, 4) if total else 0.0
        return TrajectoryEvalReport(
            total_cases=total,
            passed_cases=passed,
            pass_rate=round(passed / total, 4) if total else 0.0,
            mean_tool_f1=mean_f1,
            mean_step_efficiency=mean_eff,
            scores=scores,
        )
