# ADR 0001: Defence in depth for every tool call

- Status: accepted

## Context
Agents emit tool calls from untrusted text. A single check (a prompt filter, or a SQL regex) fails open when it is bypassed; the red-team suite showed this for both.

## Decision
Every call passes independent layers: tenant context, RBAC and row-level policy, connector-level validation (SQL allowlist, ACL filtering, idempotency keys), output PII redaction, and an immutable audit record. No layer assumes another has run.

## Consequences
Heuristic layers (injection detection) are allowed to be imperfect because the layers behind them are deterministic. Each layer has its own tests, and the red-team suite tracks known misses.
