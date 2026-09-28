"""Observability: ForensiQ-compatible spans + env-guarded OTel/Langfuse paths.

The hand-rolled span dicts are the always-on default (pluggable ``span_sink``);
OpenTelemetry and Langfuse export activate only when their SDK is installed
AND configured — silent no-op otherwise, so nothing here ever requires
infrastructure. Industry framework first in production, fallback always on.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Protocol


class SpanSink(Protocol):
    def __call__(self, span: dict) -> None: ...


def _noop(span: dict) -> None:  # pragma: no cover - trivial
    pass


class SpanEmitter:
    """Emits ForensiQ-compatible span dicts: {span_id, parent_id, name, stage,
    duration_ms, status, attrs}."""

    def __init__(self, campaign_id: str, sink: Callable[[dict], None] | None = None) -> None:
        self.campaign_id = campaign_id
        self.sink = sink or _noop
        self._seq = 0

    def emit(self, parent_id: str | None, name: str, stage: str,
             started: float, status: str, **attrs) -> str:
        self._seq += 1
        span_id = f"{self.campaign_id}-s{self._seq}"
        self.sink({
            "span_id": span_id,
            "parent_id": parent_id,
            "name": name,
            "stage": stage,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "status": status,
            "attrs": attrs,
        })
        return span_id


def _otel_enabled() -> bool:
    try:
        import opentelemetry.sdk  # noqa: F401

        return bool(os.environ.get("REDFORCE_OTEL_ENDPOINT"))
    except ImportError:
        return False


def otel_export(span: dict) -> None:
    """Optional OTLP export. Silent no-op unless the SDK + endpoint exist."""
    if not _otel_enabled():
        return
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("redforge")
        with tracer.start_as_current_span(span["name"]) as ot_span:
            ot_span.set_attribute("stage", span["stage"])
            ot_span.set_attribute("status", span["status"])
            for k, v in span["attrs"].items():
                ot_span.set_attribute(str(k)[:80], str(v)[:200])
    except Exception:
        pass  # telemetry must never break a campaign


def _langfuse_enabled() -> bool:
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"))


def langfuse_export(span: dict) -> None:
    """Optional Langfuse span export (free-tier friendly). Silent no-op otherwise."""
    if not _langfuse_enabled():
        return
    try:
        from langfuse import Langfuse

        lf = Langfuse()
        lf.trace(id=span["parent_id"] or span["span_id"], name="redforge-campaign")
        lf.span(
            trace_id=span["parent_id"] or span["span_id"],
            id=span["span_id"], name=span["name"],
            metadata={"stage": span["stage"], **span["attrs"]},
        )
    except Exception:
        pass  # optional telemetry: never break the campaign
