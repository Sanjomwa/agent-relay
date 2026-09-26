"""JSON-lines logging to stdout.

One JSON object per line with: timestamp (UTC ISO), level, logger, message,
service, version, environment, and trace_id/span_id when a span is active.

Log records only ever carry the message and an explicit ``fields`` dict; the
request logger passes method/route/status/duration and nothing else, so headers,
bodies and credentials cannot reach this formatter through it.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

from opentelemetry import trace

import buildinfo


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": buildinfo.SERVICE_NAME,
            "version": buildinfo.app_version(),
            "environment": buildinfo.environment(),
        }
        context = trace.get_current_span().get_span_context()
        if context.is_valid:
            payload["trace_id"] = format(context.trace_id, "032x")
            payload["span_id"] = format(context.span_id, "016x")
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class _StdoutHandler(logging.StreamHandler):
    """Resolve ``sys.stdout`` on every write so pytest's capture sees it."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):  # type: ignore[override]
        return sys.stdout

    @stream.setter
    def stream(self, _value) -> None:
        pass


def configure_logging() -> None:
    """Send every log record to stdout as JSON; silence uvicorn's access log."""

    level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = _StdoutHandler()
    handler.setFormatter(JsonFormatter())
    handler.set_name("agent-relay-json")

    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if h.get_name() != "agent-relay-json"]
    root.addHandler(handler)
    root.setLevel(level if level in logging.getLevelNamesMapping() else "INFO")

    # uvicorn installs its own text handlers before importing the app; route its
    # server logs through the root JSON handler instead.
    for name in ("uvicorn", "uvicorn.error"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers = []
        uv_logger.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False
    access.disabled = True

    # Client libraries log full request URLs at INFO; keep them out of the stream.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


__all__ = ["JsonFormatter", "configure_logging"]
