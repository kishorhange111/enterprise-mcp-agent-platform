"""Stateful DAG/agent execution runtime with checkpointing, guardrails, and streaming events."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from src.agent.checkpoint import (
    AgentState,
    CheckpointStore,
    InMemoryCheckpointStore,
    StepRecord,
)
from src.core.models import AgentTask, Principal, TaskStatus, utc_now
from src.core.tenant import TenantContext, TenantIsolationError, tenant_scope
from src.mcp.server import MCPServer
from src.security.guardrails import GuardrailMiddleware, GuardrailViolationError

NodeFn = Callable[[AgentState, MCPServer, TenantContext], "NodeResult"]
EventCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class NodeResult:
    """Transition directive returned by a graph node."""

    next_node: str | None = None
    state_updates: dict[str, Any] = field(default_factory=dict)
    final_output: Any = None
    pause_for_approval: bool = False


class AgentGraph:
    """Directed graph of stateful agent execution nodes."""

    def __init__(self, name: str = "default_agent_graph") -> None:
        self.name = name
        self._nodes: dict[str, NodeFn] = {}
        self._entry_point: str | None = None

    def add_node(self, name: str, fn: NodeFn) -> AgentGraph:
        if name in self._nodes:
            raise ValueError(f"Node '{name}' is already registered in graph '{self.name}'")
        self._nodes[name] = fn
        if self._entry_point is None:
            self._entry_point = name
        return self

    def set_entry_point(self, name: str) -> AgentGraph:
        if name not in self._nodes:
            raise KeyError(f"Entry point node '{name}' does not exist in graph '{self.name}'")
        self._entry_point = name
        return self

    @property
    def entry_point(self) -> str:
        if self._entry_point is None:
            raise ValueError(f"Graph '{self.name}' has no nodes registered")
        return self._entry_point

    def get_node(self, name: str) -> NodeFn:
        fn = self._nodes.get(name)
        if fn is None:
            raise KeyError(f"Node '{name}' not found in graph '{self.name}'")
        return fn


class AgentRuntime:
    """Executes AgentGraphs with ingress guardrails, step checkpointing, and pause/resume."""

    def __init__(
        self,
        mcp_server: MCPServer,
        *,
        checkpoint_store: CheckpointStore | None = None,
        guardrails: GuardrailMiddleware | None = None,
    ) -> None:
        self.mcp_server = mcp_server
        self.checkpoint_store: CheckpointStore = checkpoint_store or InMemoryCheckpointStore()
        self.guardrails = guardrails or GuardrailMiddleware()

    def run(
        self,
        task: AgentTask,
        graph: AgentGraph,
        *,
        on_event: EventCallback | None = None,
    ) -> AgentState:
        """Start a new stateful agent execution from the graph's entry point."""
        state = AgentState(
            task_id=task.task_id,
            tenant_id=task.tenant_id,
            principal_id=task.principal.user_id,
            correlation_id=task.correlation_id,
            prompt=task.prompt,
            current_node=graph.entry_point,
            status=TaskStatus.RUNNING,
            memory=dict(task.metadata),
        )

        # Ingress prompt-injection & PII guardrail check
        try:
            redaction = self.guardrails.process_input(task.prompt)
            state.prompt = redaction.text
        except GuardrailViolationError as exc:
            state.status = TaskStatus.FAILED
            state.error = str(exc)
            state.updated_at = utc_now()
            self.checkpoint_store.save(state)
            self._emit(on_event, "task_blocked", state)
            return state

        self.checkpoint_store.save(state)
        self._emit(on_event, "task_started", state)
        return self._execute_loop(
            state=state,
            graph=graph,
            principal=task.principal,
            max_steps=task.max_steps,
            on_event=on_event,
        )

    def resume(
        self,
        task_id: str,
        graph: AgentGraph,
        principal: Principal,
        *,
        resume_updates: dict[str, Any] | None = None,
        max_steps: int = 10,
        on_event: EventCallback | None = None,
    ) -> AgentState:
        """Resume a paused/checkpointed task after HITL approval or crash recovery."""
        state = self.checkpoint_store.load_latest(task_id)
        if state is None:
            raise KeyError(f"No checkpoint found for task '{task_id}'")
        if state.tenant_id != principal.tenant_id:
            raise TenantIsolationError(f"Cross-tenant resume denied for task '{task_id}'")

        if resume_updates:
            state.memory.update(resume_updates)
        state.status = TaskStatus.RUNNING
        state.updated_at = utc_now()
        self.checkpoint_store.save(state)
        self._emit(on_event, "task_resumed", state)

        return self._execute_loop(
            state=state,
            graph=graph,
            principal=principal,
            max_steps=max_steps,
            on_event=on_event,
        )

    def _execute_loop(
        self,
        *,
        state: AgentState,
        graph: AgentGraph,
        principal: Principal,
        max_steps: int,
        on_event: EventCallback | None,
    ) -> AgentState:
        with tenant_scope(
            principal,
            correlation_id=state.correlation_id,
            request_metadata={"task_id": state.task_id},
        ) as ctx:
            while state.current_node is not None:
                if state.step_count >= max_steps:
                    state.status = TaskStatus.FAILED
                    state.error = f"Exceeded max_steps limit ({max_steps})"
                    state.updated_at = utc_now()
                    self.checkpoint_store.save(state)
                    self._emit(on_event, "task_failed", state)
                    return state

                node_name = state.current_node
                node_fn = graph.get_node(node_name)
                t0 = time.perf_counter()

                try:
                    directive = node_fn(state, self.mcp_server, ctx)
                    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

                    state.memory.update(directive.state_updates)
                    state.step_count += 1
                    state.step_history.append(
                        StepRecord(
                            step_index=state.step_count,
                            node_name=node_name,
                            status="paused" if directive.pause_for_approval else "ok",
                            latency_ms=elapsed_ms,
                            output_summary=directive.final_output or directive.state_updates,
                        )
                    )

                    if directive.pause_for_approval:
                        state.current_node = directive.next_node
                        state.status = TaskStatus.AWAITING_APPROVAL
                        state.updated_at = utc_now()
                        self.checkpoint_store.save(state)
                        self._emit(on_event, "awaiting_approval", state, node=node_name)
                        return state

                    if directive.final_output is not None:
                        sanitized, _, _ = self.guardrails.sanitize_output(directive.final_output)
                        state.final_output = sanitized

                    state.current_node = directive.next_node
                    state.updated_at = utc_now()
                    self.checkpoint_store.save(state)
                    self._emit(on_event, "step_completed", state, node=node_name)

                except Exception as exc:  # noqa: BLE001
                    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                    state.step_count += 1
                    state.step_history.append(
                        StepRecord(
                            step_index=state.step_count,
                            node_name=node_name,
                            status="error",
                            latency_ms=elapsed_ms,
                            error=str(exc),
                        )
                    )
                    state.status = TaskStatus.FAILED
                    state.error = str(exc)
                    state.updated_at = utc_now()
                    self.checkpoint_store.save(state)
                    self._emit(on_event, "task_failed", state, node=node_name)
                    return state

        state.status = TaskStatus.COMPLETED
        state.updated_at = utc_now()
        self.checkpoint_store.save(state)
        self._emit(on_event, "task_completed", state)
        return state

    @staticmethod
    def _emit(
        callback: EventCallback | None,
        event_type: str,
        state: AgentState,
        *,
        node: str | None = None,
    ) -> None:
        if callback is not None:
            callback(
                {
                    "event": event_type,
                    "task_id": state.task_id,
                    "tenant_id": state.tenant_id,
                    "status": state.status.value,
                    "step_count": state.step_count,
                    "node": node or state.current_node,
                }
            )
