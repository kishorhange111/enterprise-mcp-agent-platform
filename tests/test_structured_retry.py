"""Unit tests for structured output validation, repair loop, retry, and circuit breaker."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from src.agent import (
    CircuitBreaker,
    CircuitOpenError,
    RetryPolicy,
    StructuredOutputError,
    StructuredOutputValidator,
    execute_with_retry_and_fallback,
)


class IncidentSummary(BaseModel):
    severity: str = Field(..., pattern="^P[1-4]$")
    root_cause: str = Field(..., min_length=3)
    action_items: list[str] = Field(default_factory=list)


def test_structured_output_extracts_fenced_json_and_repairs() -> None:
    validator = StructuredOutputValidator()
    responses = iter(
        [
            "```json\n{\"severity\": \"INVALID\", \"root_cause\": \"db\"}\n```",
            "```json\n{\"severity\": \"P1\", \"root_cause\": \"connection pool exhausted\", "
            "\"action_items\": [\"scale pool\"]}\n```",
        ]
    )
    feedbacks: list[str | None] = []

    def fake_llm(feedback: str | None) -> str:
        feedbacks.append(feedback)
        return next(responses)

    res = validator.generate_with_repair(fake_llm, IncidentSummary, max_repairs=2)
    assert res.attempts == 2
    assert res.used_fallback is False
    assert res.data.severity == "P1"
    assert feedbacks[0] is None
    assert feedbacks[1] is not None and "IncidentSummary" in feedbacks[1]


def test_structured_output_uses_fallback_or_raises() -> None:
    validator = StructuredOutputValidator()

    res = validator.generate_with_repair(
        lambda _: "not valid json at all",
        IncidentSummary,
        max_repairs=1,
        fallback_generator=lambda _: '{"severity": "P2", "root_cause": "fallback summary"}',
    )
    assert res.used_fallback is True
    assert res.data.severity == "P2"

    with pytest.raises(StructuredOutputError):
        validator.generate_with_repair(lambda _: "{broken", IncidentSummary, max_repairs=1)


def test_retry_policy_backoff_and_fallback() -> None:
    sleeps: list[float] = []
    calls = {"n": 0}

    def flaky_primary() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("transient timeout")
        return "primary-ok"

    policy = RetryPolicy(max_attempts=3, base_delay_s=0.1, backoff_multiplier=2.0)
    outcome = execute_with_retry_and_fallback(
        flaky_primary, policy=policy, sleep_fn=sleeps.append
    )
    assert outcome.value == "primary-ok"
    assert outcome.attempts == 3
    assert outcome.used_fallback is False
    assert sleeps == [0.1, 0.2]

    # Exhausted retries invoke fallback
    fb_outcome = execute_with_retry_and_fallback(
        lambda: (_ for _ in ()).throw(ConnectionError("down")),
        policy=RetryPolicy(max_attempts=2, base_delay_s=0.01),
        fallback_fn=lambda: "fallback-ok",
        sleep_fn=lambda _: None,
    )
    assert fb_outcome.value == "fallback-ok"
    assert fb_outcome.used_fallback is True


def test_circuit_breaker_opens_and_recovers() -> None:
    now = {"t": 100.0}
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout_s=10.0, clock=lambda: now["t"])

    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "open"

    with pytest.raises(CircuitOpenError):
        execute_with_retry_and_fallback(lambda: "ok", circuit_breaker=cb)

    # Advance clock past recovery_timeout_s -> half_open -> success closes circuit
    now["t"] = 115.0
    assert cb.state == "half_open"
    res = execute_with_retry_and_fallback(lambda: "recovered", circuit_breaker=cb)
    assert res.value == "recovered"
    assert cb.state == "closed"
