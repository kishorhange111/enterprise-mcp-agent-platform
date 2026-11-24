"""Exponential backoff retry policy, circuit breaker, and fallback orchestration."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    """Raised when a circuit breaker is open and fast-failing calls."""


@dataclass(frozen=True)
class RetryPolicy:
    """Declarative exponential backoff retry configuration."""

    max_attempts: int = 3
    base_delay_s: float = 0.05
    max_delay_s: float = 2.0
    backoff_multiplier: float = 2.0
    retryable_exceptions: tuple[type[BaseException], ...] = (
        TimeoutError,
        ConnectionError,
        RuntimeError,
    )

    def delay_for_attempt(self, attempt_number: int) -> float:
        """Compute delay in seconds before retry `attempt_number` (1-indexed)."""
        delay = self.base_delay_s * (self.backoff_multiplier ** max(0, attempt_number - 1))
        return min(delay, self.max_delay_s)


@dataclass
class CircuitBreaker:
    """Lightweight circuit breaker preventing cascading failures against unstable backends."""

    failure_threshold: int = 3
    recovery_timeout_s: float = 30.0
    clock: Callable[[], float] = time.monotonic
    _failure_count: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if (self.clock() - self._opened_at) >= self.recovery_timeout_s:
            return "half_open"
        return "open"

    def allow_request(self) -> bool:
        return self.state in {"closed", "half_open"}

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._opened_at = self.clock()


@dataclass(frozen=True)
class ExecutionOutcome(Generic[T]):
    """Structured outcome from retry + fallback execution."""

    value: T
    attempts: int
    used_fallback: bool
    errors: tuple[str, ...]


def execute_with_retry_and_fallback(
    primary_fn: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    fallback_fn: Callable[[], T] | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> ExecutionOutcome[T]:
    """Run primary_fn with retries & optional circuit breaker, falling back on exhaustion."""
    cfg = policy or RetryPolicy()
    errors: list[str] = []
    attempts = 0

    if circuit_breaker is not None and not circuit_breaker.allow_request():
        errors.append("Circuit breaker open; skipping primary")
        if fallback_fn is not None:
            return ExecutionOutcome(
                value=fallback_fn(),
                attempts=0,
                used_fallback=True,
                errors=tuple(errors),
            )
        raise CircuitOpenError("Primary dependency circuit breaker is open")

    last_exc: BaseException | None = None
    for attempt in range(1, cfg.max_attempts + 1):
        attempts = attempt
        try:
            result = primary_fn()
            if circuit_breaker is not None:
                circuit_breaker.record_success()
            return ExecutionOutcome(
                value=result,
                attempts=attempts,
                used_fallback=False,
                errors=tuple(errors),
            )
        except cfg.retryable_exceptions as exc:
            last_exc = exc
            errors.append(f"attempt {attempt}: {exc}")
            if circuit_breaker is not None:
                circuit_breaker.record_failure()
            if attempt < cfg.max_attempts:
                sleep_fn(cfg.delay_for_attempt(attempt))

    if fallback_fn is not None:
        return ExecutionOutcome(
            value=fallback_fn(),
            attempts=attempts,
            used_fallback=True,
            errors=tuple(errors),
        )

    assert last_exc is not None
    raise last_exc
