"""Structured output validation, JSON extraction, and schema-repair loop."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


class StructuredOutputError(ValueError):
    """Raised when model output cannot be parsed or validated against the target schema."""

    def __init__(self, message: str, raw_output: str = "", attempts: int = 0) -> None:
        super().__init__(message)
        self.raw_output = raw_output
        self.attempts = attempts


@dataclass(frozen=True)
class StructuredGenerationResult(Generic[T]):
    """Typed result of structured output generation with repair/fallback metadata."""

    data: T
    attempts: int
    used_fallback: bool
    repair_errors: tuple[str, ...]


def extract_json_payload(raw_text: str) -> str:
    """Extract a JSON object/array from raw text or markdown code fences."""
    stripped = raw_text.strip()
    fence_match = _FENCE_RE.search(stripped)
    if fence_match:
        return fence_match.group(1).strip()

    first_brace = stripped.find("{")
    first_bracket = stripped.find("[")
    starts = [idx for idx in (first_brace, first_bracket) if idx != -1]
    if starts:
        start = min(starts)
        end_char = "}" if stripped[start] == "{" else "]"
        end = stripped.rfind(end_char)
        if end > start:
            return stripped[start : end + 1]
    return stripped


class StructuredOutputValidator:
    """Validates and repairs LLM outputs into strict Pydantic models."""

    def parse(self, raw_output: str | dict[str, Any], schema_cls: type[T]) -> T:
        """Parse and validate a raw JSON string or dict into `schema_cls`."""
        if isinstance(raw_output, dict):
            return schema_cls.model_validate(raw_output)

        candidate = extract_json_payload(raw_output)
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise StructuredOutputError(
                f"Invalid JSON syntax: {exc.msg} (line {exc.lineno}, col {exc.colno})",
                raw_output=raw_output,
            ) from exc

        try:
            return schema_cls.model_validate(parsed)
        except ValidationError as exc:
            raise StructuredOutputError(
                f"Schema validation failed for {schema_cls.__name__}: {exc}",
                raw_output=raw_output,
            ) from exc

    def generate_with_repair(
        self,
        generator_fn: Callable[[str | None], str | dict[str, Any]],
        schema_cls: type[T],
        *,
        max_repairs: int = 2,
        fallback_generator: Callable[[str | None], str | dict[str, Any]] | None = None,
    ) -> StructuredGenerationResult[T]:
        """Invoke generator with automatic schema-error repair feedback and optional fallback."""
        repair_errors: list[str] = []
        feedback: str | None = None
        total_attempts = 0
        last_raw = ""

        for _ in range(max_repairs + 1):
            total_attempts += 1
            raw = generator_fn(feedback)
            last_raw = raw if isinstance(raw, str) else json.dumps(raw)
            try:
                validated = self.parse(raw, schema_cls)
                return StructuredGenerationResult(
                    data=validated,
                    attempts=total_attempts,
                    used_fallback=False,
                    repair_errors=tuple(repair_errors),
                )
            except (StructuredOutputError, ValidationError) as exc:
                err_msg = str(exc)
                repair_errors.append(err_msg)
                feedback = (
                    f"Previous output failed validation for {schema_cls.__name__}. "
                    f"Fix the following errors and return valid JSON only: {err_msg}"
                )

        if fallback_generator is not None:
            total_attempts += 1
            fallback_raw = fallback_generator(feedback)
            validated = self.parse(fallback_raw, schema_cls)
            return StructuredGenerationResult(
                data=validated,
                attempts=total_attempts,
                used_fallback=True,
                repair_errors=tuple(repair_errors),
            )

        raise StructuredOutputError(
            f"Exhausted {total_attempts} attempts validating {schema_cls.__name__}: "
            f"{repair_errors[-1] if repair_errors else 'unknown error'}",
            raw_output=last_raw,
            attempts=total_attempts,
        )
