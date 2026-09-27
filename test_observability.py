"""Observability tests: version, structured logs, spans/metrics/logs, secret hygiene.

The OpenTelemetry providers are rebuilt per test with in-memory exporters (see
``telemetry.configure``), so nothing here needs a collector. Presence assertions
always run before the "no secrets anywhere" scan so the scan cannot pass vacuously
on empty exporters.
"""

from __future__ import annotations

import os

# Same scratch-DB default as test_agent_relay.py; an explicit URL (e.g. CI/Postgres) wins.
os.environ.setdefault("RELAY_DATABASE_URL", "sqlite:////tmp/agent-relay-test.db")

import json
import re
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import main
import telemetry
from database import Attempt, Base, as_db_time, db_session, engine, utcnow

APP_VERSION = "20260926-120000-abc1234"
ENROLLMENT_SECRET = "enroll-Secret-Vq83LmZx-4471"
WRONG_ENROLLMENT_SECRET = "wrong-enroll-Kd02PqRw-9915"
BAD_BEARER = "agt_not-a-real-token-Zt61YyBn"
TASK_INPUT = "task-input-payload-Hn77WkQe"
IDEMPOTENCY_KEY = "idem-key-Bc29TgLs-3308"


@pytest.fixture(autouse=True)
def no_enrollment_secret(monkeypatch):
    # A secret exported in the developer's shell would make every unauthenticated
    # registration below return 401. Tests that exercise enrollment set it explicitly.
    monkeypatch.delenv("RELAY_ENROLLMENT_SECRET", raising=False)
    monkeypatch.delenv("ENROLLMENT_SECRET", raising=False)


@pytest.fixture(autouse=True)
def empty_database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setenv("APP_VERSION", APP_VERSION)
    monkeypatch.setenv("GIT_SHA", "abc1234")
    monkeypatch.setenv("DEPLOYMENT_ENVIRONMENT", "test")
    monkeypatch.setenv("RELAY_ENROLLMENT_SECRET", ENROLLMENT_SECRET)
    spans, logs, reader = InMemorySpanExporter(), InMemoryLogRecordExporter(), InMemoryMetricReader()
    telemetry.configure(
        main.app,
        engine,
        span_processors=[SimpleSpanProcessor(spans)],
        metric_readers=[reader],
        log_processors=[SimpleLogRecordProcessor(logs)],
    )
    yield SimpleNamespace(spans=spans, logs=logs, reader=reader)
    monkeypatch.delenv("RELAY_ENROLLMENT_SECRET", raising=False)
    telemetry.configure_from_env(main.app, engine)


# --------------------------------------------------------------------------- helpers


def metrics_by_name(reader: InMemoryMetricReader) -> dict:
    data = reader.get_metrics_data()
    assert data is not None and data.resource_metrics, "no metrics were exported"
    return {m.name: m for rm in data.resource_metrics for sm in rm.scope_metrics for m in sm.metrics}


def counter_value(metric, **attributes) -> int:
    return sum(
        p.value
        for p in metric.data.data_points
        if all(p.attributes.get(k) == v for k, v in attributes.items())
    )


def log_record(item):
    return getattr(item, "log_record", item)


def serialized_signals(capture, stdout: str) -> dict[str, str]:
    """Every exported signal rendered to JSON text, keyed by signal name."""

    return {
        "spans": "\n".join(span.to_json() for span in capture.spans.get_finished_spans()),
        "otel_logs": "\n".join(x.to_json() for x in capture.logs.get_finished_logs()),
        "metrics": capture.reader.get_metrics_data().to_json(),
        "stdout_logs": stdout,
    }


def find_leaks(signals: dict[str, str], secrets: dict[str, str]) -> list[str]:
    return [f"{name!r} leaked in {signal}" for signal, blob in signals.items() for name, value in secrets.items() if value in blob]


def register(client: TestClient, name: str, secret: str | None = ENROLLMENT_SECRET) -> dict:
    headers = {"X-Enrollment-Secret": secret} if secret else {}
    response = client.post("/api/v1/agents", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------- tests


def test_version_endpoint_reads_environment(monkeypatch):
    monkeypatch.delenv("APP_VERSION", raising=False)
    monkeypatch.delenv("GIT_SHA", raising=False)
    monkeypatch.delenv("DEPLOYMENT_ENVIRONMENT", raising=False)
    client = TestClient(main.app)
    assert client.get("/version").json() == {
        "service": "agent-relay",
        "version": "dev",
        "git_sha": "unknown",
        "environment": "dev",
    }
    monkeypatch.setenv("APP_VERSION", APP_VERSION)
    monkeypatch.setenv("GIT_SHA", "abc1234")
    monkeypatch.setenv("DEPLOYMENT_ENVIRONMENT", "local")
    assert client.get("/version").json() == {
        "service": "agent-relay",
        "version": APP_VERSION,
        "git_sha": "abc1234",
        "environment": "local",
    }
    # /health and /ready are unchanged.
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/ready").json() == {"status": "ready"}


def test_probe_dashboard_and_version_routes_are_not_traced(capture, capsys):
    client = TestClient(main.app)  # no lifespan: only the requests below can create spans
    for path in ("/health", "/ready", "/version", "/", "/dashboard"):
        assert client.get(path).status_code == 200
    assert capture.spans.get_finished_spans() == ()
    # ...but each is still logged once.
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if '"agent_relay.access"' in line]
    assert [line["route"] for line in lines] == ["/health", "/ready", "/version", "/", "/dashboard"]


def test_full_flow_emits_telemetry_without_leaking_secrets(capture, capsys):
    requests = 0
    with TestClient(main.app) as client:
        sender = register(client, "sender")
        recipient = register(client, "recipient")
        requests += 2
        sender_auth = {"Authorization": f"Bearer {sender['token']}"}
        recipient_auth = {"Authorization": f"Bearer {recipient['token']}"}

        sent = client.post(
            "/api/v1/tasks",
            headers={**sender_auth, "Idempotency-Key": IDEMPOTENCY_KEY},
            json={"to": recipient["agent_id"], "input": TASK_INPUT},
        )
        assert sent.status_code == 201
        task_id = sent.json()["task_id"]

        claim = client.post("/api/v1/tasks/claim", headers=recipient_auth, json={"worker_id": "w1", "wait_seconds": 0})
        assert claim.status_code == 200
        claim_token = claim.json()["claim_token"]
        empty = client.post("/api/v1/tasks/claim", headers=recipient_auth, json={"worker_id": "w1", "wait_seconds": 0})
        assert empty.status_code == 204

        done = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_auth,
            json={"claim_token": claim_token, "output": "DONE"},
        )
        assert done.status_code == 200
        conflict = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_auth,
            json={"claim_token": claim_token, "output": "SOMETHING ELSE"},
        )
        assert conflict.status_code == 409

        bad = client.get("/api/v1/agents/me", headers={"Authorization": f"Bearer {BAD_BEARER}"})
        assert bad.status_code == 401
        wrong_enrollment = client.post(
            "/api/v1/agents", json={"name": "x"}, headers={"X-Enrollment-Secret": WRONG_ENROLLMENT_SECRET}
        )
        assert wrong_enrollment.status_code == 401
        requests += 7

        # One expired lease -> one recovery, so relay.lease.recoveries is exercised too.
        second = client.post(
            "/api/v1/tasks", headers=sender_auth, json={"to": recipient["agent_id"], "input": "again"}
        )
        assert second.status_code == 201
        assert client.post("/api/v1/tasks/claim", headers=recipient_auth, json={"wait_seconds": 0}).status_code == 200
        requests += 2
        with db_session() as db:
            for attempt in db.query(Attempt).filter(Attempt.outcome == "processing"):
                attempt.lease_expires_at = as_db_time(utcnow() - timedelta(seconds=1))
        assert main.recover_expired() == 1

    # ---- presence first: spans ------------------------------------------------
    spans: list[ReadableSpan] = list(capture.spans.get_finished_spans())
    server_spans = {s.name for s in spans if s.kind.name == "SERVER"}
    assert {
        "POST /api/v1/agents",
        "POST /api/v1/tasks",
        "POST /api/v1/tasks/claim",
        "POST /api/v1/tasks/{task_id}/complete",
        "GET /api/v1/agents/me",
    } <= server_spans
    assert not any(task_id in name for name in server_spans), "span names must use the route template"
    sql_spans = [s for s in spans if s.attributes and "db.system" in s.attributes]
    statements = [str(s.attributes.get("db.statement") or s.attributes.get("db.query.text")) for s in sql_spans]
    assert any(re.search(r"INSERT INTO tasks", st) for st in statements)
    assert all("token" not in st.lower() or "token_hash" in st.lower() for st in statements)
    for span in spans:
        assert span.resource.attributes["service.name"] == "agent-relay"
        assert span.resource.attributes["service.version"] == APP_VERSION
        assert span.resource.attributes["deployment.environment.name"] == "test"
    # No HTTP headers captured on any span.
    assert not [k for s in spans for k in (s.attributes or {}) if k.startswith(("http.request.header", "http.response.header"))]

    # ---- presence: metrics ---------------------------------------------------
    metrics = metrics_by_name(capture.reader)
    assert counter_value(metrics["relay.tasks.created"], outcome="ok") == 2
    assert counter_value(metrics["relay.tasks.claims"], outcome="claimed") == 2
    assert counter_value(metrics["relay.tasks.claims"], outcome="empty") == 1
    assert counter_value(metrics["relay.tasks.terminal"], action="complete", outcome="ok") == 1
    assert counter_value(metrics["relay.tasks.terminal"], action="complete", outcome="conflict") == 1
    assert counter_value(metrics["relay.lease.recoveries"]) == 1
    duration = metrics["relay.claim.duration"]
    assert metrics["relay.claim.duration"].unit == "s"
    assert max(duration.data.data_points[0].explicit_bounds) >= 30
    assert "relay.queue.depth" in metrics and "relay.queue.oldest_age" in metrics
    http_duration = metrics["http.server.request.duration"]
    assert {p.attributes.get("http.route") for p in http_duration.data.data_points} >= {
        "/api/v1/tasks/claim",
        "/api/v1/tasks/{task_id}/complete",
    }
    assert {p.attributes.get("http.response.status_code") for p in http_duration.data.data_points} >= {200, 201, 401, 409}
    resource = capture.reader.get_metrics_data().resource_metrics[0].resource.attributes
    assert resource["service.name"] == "agent-relay" and resource["service.version"] == APP_VERSION
    assert resource["deployment.environment.name"] == "test"
    allowed_labels = {"outcome", "action"}
    for name, metric in metrics.items():
        if name.startswith("relay."):
            for point in metric.data.data_points:
                assert set(point.attributes) <= allowed_labels, f"{name} has unexpected labels {dict(point.attributes)}"

    # ---- presence: logs (OTel-exported and stdout JSON) ------------------------
    otel_logs = list(capture.logs.get_finished_logs())
    access_otel = [x for x in otel_logs if log_record(x).attributes.get("route")]
    assert len(access_otel) >= requests
    assert any(log_record(x).trace_id for x in access_otel), "request logs must carry the trace context"
    assert all(x.resource.attributes["service.version"] == APP_VERSION for x in otel_logs)
    assert all(x.resource.attributes["service.name"] == "agent-relay" for x in otel_logs)
    stdout = capsys.readouterr().out
    parsed = [json.loads(line) for line in stdout.splitlines()]  # every line must be JSON
    for entry in parsed:
        assert {"timestamp", "level", "logger", "message", "service", "version", "environment"} <= set(entry)
        assert entry["version"] == APP_VERSION and entry["environment"] == "test" and entry["service"] == "agent-relay"
    access = [e for e in parsed if e["logger"] == "agent_relay.access"]
    assert len(access) == requests, "exactly one access line per request"
    assert all({"method", "route", "status", "duration_ms"} <= set(e) for e in access)
    assert any(e["route"] == "/api/v1/tasks/{task_id}/complete" and e["status"] == 409 for e in access)
    assert any("trace_id" in e and "span_id" in e for e in access)
    assert task_id not in stdout, "raw task ids must not appear in request logs"

    # ---- only now: nothing secret anywhere -------------------------------------
    secrets = {
        "bearer token (sender)": sender["token"],
        "bearer token (recipient)": recipient["token"],
        "bad bearer token": BAD_BEARER,
        "claim token": claim_token,
        "enrollment secret": ENROLLMENT_SECRET,
        "wrong enrollment secret": WRONG_ENROLLMENT_SECRET,
        "idempotency key": IDEMPOTENCY_KEY,
        "task input value": TASK_INPUT,
    }
    password = engine.url.password
    if password:
        # The full DSN is distinctive whatever the password is.
        secrets["database url"] = engine.url.render_as_string(hide_password=False)
        # A bare password is only meaningful if it can't collide with legitimate telemetry
        # text (e.g. CI uses user=password=agent_relay, which is also a logger name).
        benign = [engine.url.username, engine.url.database, engine.url.host, "agent_relay", "agent-relay"]
        if len(password) >= 8 and not any(b and (password in b or b in password) for b in benign):
            secrets["database password"] = password
    signals = serialized_signals(capture, stdout)
    assert all(signals.values()), "an exporter produced nothing; the leak scan would be vacuous"
    leaks = find_leaks(signals, secrets)
    # Ids are legitimate in URLs/spans but must never become metric labels.
    ids = {"sender agent id": sender["agent_id"], "recipient agent id": recipient["agent_id"], "task id": task_id}
    leaks += [f"{name!r} leaked in metrics" for name, value in ids.items() if value in signals["metrics"]]
    assert not leaks, "secrets leaked into telemetry:\n" + "\n".join(leaks)
