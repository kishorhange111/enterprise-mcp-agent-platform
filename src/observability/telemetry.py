"""OpenTelemetry span tracing wrapper with deterministic in-memory span recording."""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator
from uuid import uuid4

from opentelemetry import trace


@dataclass(frozen=True)
class SpanRecord:
    """Captured telemetry span record for structured logging and unit assertions."""

    trace_id: str
    span_id: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "ok"
    error: str | None = None


class TelemetryTracer:
    """Bridges OpenTelemetry API spans with an inspectable in-memory span buffer."""

    def __init__(self, service_name: str = "enterprise-mcp-agent-platform") -> None:
        self.service_name = service_name
        self._otel_tracer = trace.get_tracer(service_name)
        self._spans: list[SpanRecord] = []

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        attributes: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Start an OpenTelemetry span and record its duration and status."""
        attrs = dict(attributes or {})
        attrs.setdefault("service.name", self.service_name)
        tid = trace_id or uuid4().hex
        sid = uuid4().hex[:16]
        start = time.perf_counter()
        status = "ok"
        err_msg: str | None = None

        with self._otel_tracer.start_as_current_span(name) as otel_span:
            for key, val in attrs.items():
                otel_span.set_attribute(key, str(val))
            try:
                yield attrs
            except Exception as exc:
                status = "error"
                err_msg = str(exc)
                otel_span.record_exception(exc)
                raise
            finally:
                elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
                self._spans.append(
                    SpanRecord(
                        trace_id=tid,
                        span_id=sid,
                        name=name,
                        attributes=attrs,
                        duration_ms=elapsed_ms,
                        status=status,
                        error=err_msg,
                    )
                )

    def get_spans(self, name: str | None = None) -> list[SpanRecord]:
        """Return recorded spans, optionally filtered by span name."""
        if name is None:
            return list(self._spans)
        return [s for s in self._spans if s.name == name]

    def clear(self) -> None:
        """Clear buffered span records."""
        self._spans.clear()
