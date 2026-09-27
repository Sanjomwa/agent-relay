"""Safety-relevant tests for the orchestrator (no Claude calls, no Docker)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")
pytest.importorskip("jsonschema")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import policy as pol  # noqa: E402
import respond  # noqa: E402


def test_responder_env_is_an_allowlist(monkeypatch):
    # Fake URLs are assembled at runtime so repo-wide secret scans stay clean.
    poisoned = {
        "RELAY_DATABASE_URL": "postgresql" + "+psycopg://u:" + "hunter2" + "@db/x", "RELAY_ENROLLMENT_SECRET": "s3cret",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://x", "GRAFANA_ADMIN_PASSWORD": "pw", "POSTGRES_PASSWORD": "pw",
        "DATABASE_URL": "postgresql" + "://u:" + "pw" + "@db/x", "CLAUDE_CODE_MESSAGING_TOKEN": "tok", "CLAUDECODE": "1",
        "CLAUDE_CODE_SESSION_ID": "abc", "AWS_SECRET_ACCESS_KEY": "aws", "GITHUB_TOKEN": "gh",
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HOME", "/home/x")
    env = respond.responder_env()
    assert set(env) <= set(respond.ENV_ALLOWLIST) | {"PATH", "LANG", "TERM"}
    joined = json.dumps(env)
    for value in poisoned.values():
        assert value not in joined
    assert env["HOME"] == "/home/x" and env["TERM"] == "dumb"


def test_responder_command_is_read_only_and_locked_down():
    cmd = respond.responder_command('{"type":"object"}')
    flags = {cmd[i]: cmd[i + 1] for i in range(len(cmd) - 1) if cmd[i].startswith("--")}
    assert flags["--tools"] == "Read,Grep,Glob"
    assert flags["--permission-mode"] == "dontAsk"
    assert flags["--output-format"] == "json"
    assert flags["--json-schema"] == '{"type":"object"}'
    assert flags["--mcp-config"] == '{"mcpServers":{}}' and "--strict-mcp-config" in cmd
    assert "--no-session-persistence" in cmd and flags["--model"] == "sonnet"
    assert float(flags["--max-budget-usd"]) <= 1.0
    assert json.loads(flags["--settings"]) == {"advisorModel": ""}
    assert flags["--setting-sources"] == ""  # no user/project/local settings files (K-008)
    for forbidden in ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "--allowedTools", "--add-dir", "--bare"):
        assert forbidden not in cmd
    assert not {"Bash", "Write", "Edit", "WebFetch"} & set(flags["--tools"].split(","))


@pytest.mark.parametrize("envelope,ok", [
    ({"is_error": False, "structured_output": {"a": 1}}, True),
    ({"is_error": False, "result": '{"a": 1}'}, True),
    ({"is_error": True, "result": "Not logged in"}, False),
    ({"is_error": False, "result": "prose, not json"}, False),
    ({"is_error": False}, False),
    ("just a string", False),
    (None, False),
])
def test_extract_response(envelope, ok):
    response, problem = respond.extract_response(envelope)
    assert (problem is None) == ok and (response is not None) == ok


def test_runbook_runner_refuses_anything_not_an_allowed_script_or_argument():
    class T:  # minimal timeline stand-in
        def add(self, *a, **k):
            pass

    for bad in ({"runbook": "../../bin/sh", "args": []}, {"runbook": "rm -rf /", "args": []}, {"runbook": "nonexistent.sh", "args": []},
                {"runbook": "rollback.sh", "args": ["x; docker compose down"]}, {"runbook": "rollback.sh", "args": ["--build"]}):
        with pytest.raises(pol.PolicyError):
            respond.run_runbook("INC-20260926-000000-x", Path("/tmp"), bad, T(), approved_by=None)


def test_incident_ids_and_alert_keys():
    alert = {"labels": {"alertname": "A", "route": "/api/v1/tasks/{task_id}/complete", "version": "v", "environment": "local"}, "activeAt": "t"}
    iid = respond.new_incident_id(alert)
    assert respond.INCIDENT_ID_RE.fullmatch(iid) and iid.endswith("-api-v1-tasks-task-id-complete")
    assert respond.alert_key(alert) == "A|/api/v1/tasks/{task_id}/complete|v|local|t"
    assert respond.alert_key(alert) != respond.alert_key({**alert, "activeAt": "later"})  # a re-fire is a new incident
    assert not respond.INCIDENT_ID_RE.fullmatch("INC-20260926-000000-../../etc")
