"""OpenTelemetry traces, metrics and logs for Agent Relay.

* Providers are built here and passed to the instrumentors explicitly; nothing is
  registered as the process-global provider, so ``configure`` can be called again
  (tests inject in-memory exporters) without OpenTelemetry's set-once warnings.
* Exporters are attached ONLY when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set (OTLP over
  HTTP/protobuf, so that is the collector's port 4318). Without it the providers
  have no processors/readers: trace ids still show up in the JSON logs, but nothing
  is sent anywhere and there is no connection-error noise.
* Secrets: no HTTP headers are captured (``http_capture_headers_*`` are left unset),
  SQL spans carry the statement with placeholders only (SQLAlchemy's cursor-level
  ``statement``; the engine is also created with ``hide_parameters=True`` so bound
  values never appear in exception text), and metric labels are fixed low-cardinality
  enums: never ids, tokens or idempotency keys.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Iterable, Sequence
from typing import Any

# Opt in to the stable HTTP semantic conventions (http.server.request.duration in
# seconds, http.route, http.response.status_code). This has to be set before the
# instrumentation packages are imported.
os.environ.setdefault("OTEL_SEMCONV_STABILITY_OPT_IN", "http")

from opentelemetry import metrics as metrics_api
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.utils import suppress_instrumentation
from opentelemetry.metrics import CallbackOptions, Observation
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler, LogRecordProcessor
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

import buildinfo

LOGGER = logging.getLogger("agent_relay.telemetry")

# Matched with re.search against the full request URL. The dashboard (/ and
# /dashboard) and the probe/version endpoints are not worth a trace each.
EXCLUDED_URLS = ",".join(
    [
        r"/health(\?.*)?$",
        r"/ready(\?.*)?$",
        r"/version(\?.*)?$",
        r"/dashboard(\?.*)?$",
        r"^https?://[^/]+/?(\?.*)?$",
    ]
)

# relay.claim.duration is a long-poll (wait_seconds <= 30), so buckets must reach past 30s.
CLAIM_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 35, 60)

_HANDLER_NAME = "agent-relay-otel"


def build_resource() -> Resource:
    return Resource.create(
        {
            "service.name": buildinfo.SERVICE_NAME,
            "service.version": buildinfo.app_version(),
            "deployment.environment.name": buildinfo.environment(),
        }
    )


class Instruments:
    """Business metrics. Starts as no-ops and is bound by :func:`configure`."""

    def __init__(self) -> None:
        self.bind(metrics_api.NoOpMeterProvider().get_meter(buildinfo.SERVICE_NAME))

    def bind(self, meter: metrics_api.Meter) -> None:
        self.tasks_created = meter.create_counter(
            "relay.tasks.created", unit="{task}", description="Task submissions by outcome (ok|error)."
        )
        self.tasks_claims = meter.create_counter(
            "relay.tasks.claims", unit="{claim}", description="Claim requests by outcome (claimed|empty|error)."
        )
        self.tasks_terminal = meter.create_counter(
            "relay.tasks.terminal",
            unit="{task}",
            description="Complete/fail submissions by action and outcome (ok|conflict|error).",
        )
        self.claim_duration = meter.create_histogram(
            "relay.claim.duration",
            unit="s",
            description="Claim request duration including the long-poll wait.",
            explicit_bucket_boundaries_advisory=CLAIM_DURATION_BUCKETS,
        )
        self.lease_recoveries = meter.create_counter(
            "relay.lease.recoveries", unit="{attempt}", description="Expired attempts recovered."
        )
        meter.create_observable_gauge(
            "relay.queue.depth", callbacks=[_observe_queue_depth], unit="{task}", description="Queued tasks."
        )
        meter.create_observable_gauge(
            "relay.queue.oldest_age",
            callbacks=[_observe_oldest_age],
            unit="s",
            description="Age of the oldest queued task (0 when the queue is empty).",
        )



def _observe_queue_depth(_options: CallbackOptions) -> Iterable[Observation]:
    # Must never raise: the DB may be down or mid-migration when metrics are collected.
    try:
        from sqlalchemy import func, select

        from database import SessionLocal, Task

        with suppress_instrumentation(), SessionLocal() as db:
            depth = db.scalar(select(func.count()).select_from(Task).where(Task.status == "queued"))
        return [Observation(int(depth or 0))]
    except Exception:
        return []


def _observe_oldest_age(_options: CallbackOptions) -> Iterable[Observation]:
    try:
        from sqlalchemy import func, select

        from database import SessionLocal, Task, db_time, utcnow

        with suppress_instrumentation(), SessionLocal() as db:
            oldest = db.scalar(select(func.min(Task.created_at)).where(Task.status == "queued"))
        age = 0.0 if oldest is None else max(0.0, (utcnow() - db_time(oldest)).total_seconds())
        return [Observation(age)]
    except Exception:
        return []


instruments = Instruments()


class _OtelLogHandler(LoggingHandler):
    """Forward records to the OTel logger provider.

    Flattens the ``fields`` dict used by the JSON formatter into plain attributes,
    and never forwards the SDK's own log records (which would feed back into export).
    """

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith("opentelemetry"):
            return
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            record = copy.copy(record)
            del record.fields
            record.__dict__.update(fields)
        super().emit(record)


class _State:
    tracer_provider: TracerProvider | None = None
    meter_provider: MeterProvider | None = None
    logger_provider: LoggerProvider | None = None


_state = _State()


def configure(
    app: Any,
    engine: Any,
    *,
    span_processors: Sequence[SpanProcessor] = (),
    metric_readers: Sequence[MetricReader] = (),
    log_processors: Sequence[LogRecordProcessor] = (),
) -> None:
    """(Re)build providers and instrumentation. Safe to call repeatedly."""

    shutdown()
    resource = build_resource()

    tracer_provider = TracerProvider(resource=resource)
    for processor in span_processors:
        tracer_provider.add_span_processor(processor)
    meter_provider = MeterProvider(resource=resource, metric_readers=list(metric_readers))
    logger_provider = LoggerProvider(resource=resource)
    for log_processor in log_processors:
        logger_provider.add_log_record_processor(log_processor)

    # Uninstrument first: both instrumentors ignore a second instrument() call.
    if getattr(app, "_is_instrumented_by_opentelemetry", False):
        FastAPIInstrumentor.uninstrument_app(app)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        excluded_urls=EXCLUDED_URLS,
        exclude_spans=["receive", "send"],  # per-message ASGI spans are pure noise here
    )
    # uninstrument_app() eagerly builds the middleware stack, and Starlette keeps
    # using a built stack; force a rebuild so the (re)installed middleware is in it.
    app.middleware_stack = None
    if SQLAlchemyInstrumentor()._is_instrumented_by_opentelemetry:
        SQLAlchemyInstrumentor().uninstrument()
    SQLAlchemyInstrumentor().instrument(
        engine=engine,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        enable_commenter=False,
    )

    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if h.get_name() != _HANDLER_NAME]
    handler = _OtelLogHandler(level=logging.NOTSET, logger_provider=logger_provider)
    handler.set_name(_HANDLER_NAME)
    root.addHandler(handler)

    instruments.bind(meter_provider.get_meter(buildinfo.SERVICE_NAME, buildinfo.app_version()))
    _state.tracer_provider = tracer_provider
    _state.meter_provider = meter_provider
    _state.logger_provider = logger_provider


def configure_from_env(app: Any, engine: Any) -> None:
    """Production entry point: export over OTLP only if an endpoint is configured."""

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        configure(app, engine)
        return

    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    configure(
        app,
        engine,
        span_processors=[BatchSpanProcessor(OTLPSpanExporter())],
        metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=15_000)],
        log_processors=[BatchLogRecordProcessor(OTLPLogExporter())],
    )
    LOGGER.info("OTLP export enabled")


def shutdown() -> None:
    """Flush and stop the current providers (used before reconfiguring)."""

    for provider in (_state.tracer_provider, _state.meter_provider, _state.logger_provider):
        if provider is not None:
            try:
                provider.shutdown()
            except Exception:  # pragma: no cover - best effort
                pass
    _state.tracer_provider = _state.meter_provider = _state.logger_provider = None


__all__ = [
    "CLAIM_DURATION_BUCKETS",
    "EXCLUDED_URLS",
    "Instruments",
    "build_resource",
    "configure",
    "configure_from_env",
    "instruments",
    "shutdown",
]
