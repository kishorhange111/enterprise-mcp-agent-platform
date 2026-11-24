"""Unit tests for the agent trajectory and tool-call evaluation harness."""

from __future__ import annotations

from pathlib import Path

from evals import GoldenTrajectoryCase, TrajectoryEvaluator, load_golden_cases
from src.agent import AgentState
from src.api import create_app
from src.core import TaskStatus, ToolCallResult

GOLDEN_PATH = Path(__file__).resolve().parent.parent / "evals" / "golden_cases.json"


def test_golden_trajectory_eval_suite_passes_100_percent() -> None:
    app = create_app()
    container = app.state.container
    cases = load_golden_cases(GOLDEN_PATH)
    assert len(cases) == 4

    evaluator = TrajectoryEvaluator()
    report = evaluator.run_suite(cases, container.runtime, container.default_graph)
    assert report.total_cases == 4
    assert report.passed_cases == 4
    assert report.pass_rate == 1.0
    assert report.mean_tool_f1 == 1.0


def test_trajectory_evaluator_detects_forbidden_tool_and_missing_output() -> None:
    case = GoldenTrajectoryCase(
        case_id="strict_case",
        prompt="Read docs only",
        expected_tools=["docs.search"],
        forbidden_tools=["tickets.create"],
        required_output_substrings=["verified"],
    )
    state = AgentState(
        task_id="t1",
        tenant_id="acme",
        principal_id="u1",
        correlation_id="c1",
        prompt="Read docs only",
        status=TaskStatus.COMPLETED,
        step_count=2,
        tool_results=[
            ToolCallResult(call_id="1", tool_name="docs.search", success=True),
            ToolCallResult(call_id="2", tool_name="tickets.create", success=True),
        ],
        final_output={"summary": "draft_only"},
    )
    score = TrajectoryEvaluator().evaluate_state(case, state)
    assert score.passed is False
    assert score.forbidden_tool_violation is True
    assert score.output_match is False
    assert score.tool_precision == 0.5
    assert score.tool_recall == 1.0
