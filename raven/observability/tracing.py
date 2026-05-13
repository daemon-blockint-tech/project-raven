"""OpenTelemetry tracing configuration.

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set (e.g. `http://tempo:4317`), spans
are exported via OTLP/gRPC. Otherwise tracing is a no-op (safe in dev).

Auto-instruments:
  - FastAPI routes
  - outbound `requests` (provider SDKs, Shodan, NVD)
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)


def configure_tracing(service_name: str = "raven-api") -> bool:
    """Initialise OTel tracing. Returns True if configured, False if disabled."""
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        log.info("OpenTelemetry: OTEL_EXPORTER_OTLP_ENDPOINT not set, tracing disabled")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:
        log.warning("OpenTelemetry SDK not installed; tracing disabled")
        return False

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "raven",
            "deployment.environment": os.getenv("RAVEN_ENVIRONMENT", "dev"),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)

    # Auto-instrument FastAPI + requests
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: F401
    except ImportError:
        pass
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        RequestsInstrumentor().instrument()
    except ImportError:
        pass

    log.info("OpenTelemetry: tracing enabled, endpoint=%s", endpoint)
    return True


def instrument_app(app) -> None:
    """Apply FastAPI auto-instrumentation to a running app instance."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        pass
