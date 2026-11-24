"""Security red-team suite: adversarial prompts, SQL payloads and PII leakage against the real defences."""

from __future__ import annotations

import pytest

from src.mcp.connectors.sql import SQLSafetyError, SQLSafetyValidator
from src.security import GuardrailMiddleware, GuardrailViolationError, PromptInjectionDetector

from . import corpus

DETECTOR = PromptInjectionDetector()
VALIDATOR = SQLSafetyValidator(allowed_tables=corpus.ALLOWED_TABLES)


@pytest.mark.parametrize("prompt", corpus.INJECTION_BLOCK)
def test_injection_prompts_are_blocked(prompt):
    assert DETECTOR.inspect(prompt).blocked
    with pytest.raises(GuardrailViolationError):
        GuardrailMiddleware().process_input(prompt)


@pytest.mark.parametrize("prompt", corpus.INJECTION_KNOWN_GAPS)
@pytest.mark.xfail(strict=True, reason="known heuristic-detector gap; see docs/security-redteam.md")
def test_known_injection_gaps_are_tracked(prompt):
    assert DETECTOR.inspect(prompt).blocked


@pytest.mark.parametrize("prompt", corpus.BENIGN_PROMPTS)
def test_benign_prompts_are_not_blocked(prompt):
    assert not DETECTOR.inspect(prompt).blocked
    GuardrailMiddleware().process_input(prompt)


def test_injection_detection_rate_is_reported_honestly():
    total = len(corpus.INJECTION_BLOCK) + len(corpus.INJECTION_KNOWN_GAPS)
    caught = sum(
        DETECTOR.inspect(p).blocked for p in corpus.INJECTION_BLOCK + corpus.INJECTION_KNOWN_GAPS
    )
    assert caught >= len(corpus.INJECTION_BLOCK)
    assert caught / total >= 0.5


@pytest.mark.parametrize("sql", corpus.SQL_BLOCK)
def test_malicious_sql_is_rejected(sql):
    with pytest.raises(SQLSafetyError):
        VALIDATOR.validate(sql)


@pytest.mark.parametrize("sql", corpus.SQL_ALLOW)
def test_legitimate_sql_is_allowed_and_bounded(sql):
    result = VALIDATOR.validate(sql)
    assert result.sql.upper().startswith("SELECT * FROM (")
    assert result.applied_limit <= VALIDATOR.max_rows
    assert set(result.referenced_tables) <= corpus.ALLOWED_TABLES


def test_row_limit_cannot_be_raised_by_caller():
    assert (
        VALIDATOR.validate("SELECT * FROM orders", limit=10**9).applied_limit == VALIDATOR.max_rows
    )


@pytest.mark.parametrize(("value", "entity"), corpus.PII_LEAKS)
def test_pii_never_survives_output_sanitisation(value, entity):
    payload = {"rows": [{"note": f"contact {value} please"}], "meta": [f"x {value}"]}
    cleaned, changed, entities = GuardrailMiddleware().sanitize_output(payload)
    assert changed
    assert value not in str(cleaned)
    assert entity in entities
