"""PII redaction and prompt-injection guardrail middleware."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class GuardrailViolationError(ValueError):
    """Raised when an input or output violates a security guardrail."""

    def __init__(self, message: str, matched_rules: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.matched_rules = matched_rules


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of a PII redaction pass over text."""

    text: str
    redactions_count: int
    entity_types: tuple[str, ...]


@dataclass(frozen=True)
class InjectionCheckResult:
    """Outcome of a prompt-injection scan."""

    blocked: bool
    risk_score: float
    matched_rules: tuple[str, ...] = field(default_factory=tuple)


def _passes_luhn(digits: str) -> bool:
    """Validate candidate credit card numbers using the Luhn checksum."""
    nums = [int(ch) for ch in digits if ch.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for idx, digit in enumerate(nums):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


class PIIRedactor:
    """Detects and masks PII and secrets in strings and nested JSON payloads."""

    _PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
        (
            "API_KEY",
            re.compile(
                r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
                r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b"
            ),
            "[REDACTED_SECRET]",
        ),
        (
            "SSN",
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "[REDACTED_SSN]",
        ),
        (
            "EMAIL",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        (
            "PHONE",
            re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
            "[REDACTED_PHONE]",
        ),
    )
    _CC_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def redact_text(self, text: str) -> RedactionResult:
        """Redact sensitive entities from a string."""
        if not text:
            return RedactionResult(text=text, redactions_count=0, entity_types=())

        redacted = text
        count = 0
        entities: list[str] = []

        for label, pattern, replacement in self._PATTERNS:
            matches = pattern.findall(redacted)
            if matches:
                redacted = pattern.sub(replacement, redacted)
                count += len(matches)
                if label not in entities:
                    entities.append(label)

        # Credit card detection with Luhn validation to minimize false positives
        def _cc_replace(match: re.Match[str]) -> str:
            nonlocal count
            candidate = match.group(0)
            digits = "".join(ch for ch in candidate if ch.isdigit())
            if _passes_luhn(digits):
                count += 1
                if "CREDIT_CARD" not in entities:
                    entities.append("CREDIT_CARD")
                return "[REDACTED_CARD]"
            return candidate

        redacted = self._CC_PATTERN.sub(_cc_replace, redacted)

        return RedactionResult(
            text=redacted,
            redactions_count=count,
            entity_types=tuple(entities),
        )

    def redact_payload(self, payload: Any) -> tuple[Any, int, tuple[str, ...]]:
        """Recursively redact PII across dicts, lists, tuples, and strings."""
        total_count = 0
        seen_entities: list[str] = []

        def _walk(obj: Any) -> Any:
            nonlocal total_count
            if isinstance(obj, str):
                res = self.redact_text(obj)
                total_count += res.redactions_count
                for ent in res.entity_types:
                    if ent not in seen_entities:
                        seen_entities.append(ent)
                return res.text
            if isinstance(obj, list):
                return [_walk(item) for item in obj]
            if isinstance(obj, tuple):
                return tuple(_walk(item) for item in obj)
            if isinstance(obj, dict):
                return {k: _walk(v) for k, v in obj.items()}
            return obj

        cleaned = _walk(payload)
        return cleaned, total_count, tuple(seen_entities)


class PromptInjectionDetector:
    """Heuristic + pattern-based prompt-injection and jailbreak detector."""

    _RULES: tuple[tuple[str, float, re.Pattern[str]], ...] = (
        (
            "instruction_override",
            0.85,
            re.compile(
                r"\b(ignore|disregard|forget|override)\b.{0,40}\b"
                r"(previous|prior|above|system|all)\b.{0,25}\b(instructions?|prompts?|rules?)\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "system_prompt_exfiltration",
            0.80,
            re.compile(
                r"\b(reveal|print|dump|show|output|repeat)\b.{0,40}\b"
                r"(system\s+prompt|hidden\s+instructions?|developer\s+message|secret\s+instructions?)\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "jailbreak_persona",
            0.75,
            re.compile(
                r"\b(dan\s+mode|developer\s+mode\s+enabled|act\s+as\s+an?\s+unfiltered|"
                r"bypass\s+(?:all\s+)?(?:safety|guardrails|filters))\b",
                re.IGNORECASE,
            ),
        ),
        (
            "delimiter_injection",
            0.70,
            re.compile(
                r"(<\|im_start\|>|<\|system\|>|\[INST\]|###\s*SYSTEM\s*:|</system>)",
                re.IGNORECASE,
            ),
        ),
        (
            "privilege_or_tenant_escalation",
            0.90,
            re.compile(
                r"\b(switch|change|set|escalate|spoof)\b.{0,30}\b"
                r"(tenant_id|tenant|role\s+to\s+admin|rbac|other\s+tenant)\b",
                re.IGNORECASE,
            ),
        ),
    )

    def __init__(self, block_threshold: float = 0.70) -> None:
        self._threshold = block_threshold

    def inspect(self, text: str) -> InjectionCheckResult:
        """Scan text for prompt injection signals and return a scored verdict."""
        if not text:
            return InjectionCheckResult(blocked=False, risk_score=0.0)

        matched: list[str] = []
        max_score = 0.0
        for name, weight, pattern in self._RULES:
            if pattern.search(text):
                matched.append(name)
                max_score = max(max_score, weight)

        # Compound risk boost if multiple independent signals fire
        if len(matched) > 1:
            max_score = min(1.0, max_score + 0.1 * (len(matched) - 1))

        return InjectionCheckResult(
            blocked=max_score >= self._threshold,
            risk_score=round(max_score, 3),
            matched_rules=tuple(matched),
        )


class GuardrailMiddleware:
    """Combines prompt-injection blocking on ingress with PII redaction on egress."""

    def __init__(
        self,
        redactor: PIIRedactor | None = None,
        injection_detector: PromptInjectionDetector | None = None,
        redact_inputs: bool = True,
    ) -> None:
        self.redactor = redactor or PIIRedactor()
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.redact_inputs = redact_inputs

    def process_input(self, prompt: str) -> RedactionResult:
        """Validate ingress prompt against injection rules and optionally redact PII."""
        verdict = self.injection_detector.inspect(prompt)
        if verdict.blocked:
            raise GuardrailViolationError(
                f"Prompt blocked by injection guardrail (score={verdict.risk_score}, "
                f"rules={list(verdict.matched_rules)})",
                matched_rules=verdict.matched_rules,
            )
        if self.redact_inputs:
            return self.redactor.redact_text(prompt)
        return RedactionResult(text=prompt, redactions_count=0, entity_types=())

    def sanitize_output(self, payload: Any) -> tuple[Any, bool, tuple[str, ...]]:
        """Redact PII from tool outputs or agent responses before returning to callers."""
        cleaned, count, entities = self.redactor.redact_payload(payload)
        return cleaned, count > 0, entities
