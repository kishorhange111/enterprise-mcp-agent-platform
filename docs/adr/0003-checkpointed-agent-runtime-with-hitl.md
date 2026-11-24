# ADR 0003: Checkpointed DAG runtime with human-in-the-loop approvals

- Status: accepted

## Context
Enterprise agents take side-effecting actions (tickets, writes) and must survive restarts and pause for approval.

## Decision
The runtime executes an explicit DAG, persists step state through checkpoints, validates structured outputs with retry and fallback policy, and parks high-risk steps in an approval queue with escalation.

## Consequences
Runs are resumable and auditable; the cost is an explicit graph definition instead of free-form loops.
