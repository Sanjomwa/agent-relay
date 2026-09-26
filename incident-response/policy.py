"""Autonomy policy engine for the incident responder.

The responder (a model) only ever returns a *proposal*. This module turns a
proposal plus independently observed facts into a decision. It is pure: it never
runs anything and never treats model text as an instruction.

Rules enforced here (mirrored in autonomy-policy.yaml):

* Only actions listed in the policy exist. Anything else (an unknown action type, a
  free-form command in the type field) is DENIED and turned into an escalation.
* The only things that can ever be executed are the runbook scripts named in the
  policy, with arguments validated by regex and by equality with observed facts.
* Levels: L0 record only, L1 needs explicit human approval, L2 automatic when every
  precondition holds.
* Confidence can only DOWNGRADE. Below the threshold the outcome is forced to
  escalate; at or above it NOTHING changes: it never raises a level, skips a
  precondition, or overturns a denial. The code below never reads `confidence`
  except in the downgrade check.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

VERSION_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{7}(-dirty)?$")
RUNBOOK_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\.sh$")
LEVELS = ("L0", "L1", "L2")

# Argument validators for runbook arguments, keyed by argument name.
ARG_VALIDATORS: dict[str, re.Pattern[str]] = {"target_version": VERSION_RE}


class PolicyError(Exception):
    """The policy file itself is malformed. Fail closed."""


@dataclass
class Facts:
    """Everything the engine may rely on, observed by code (never by the model)."""

    now: datetime
    alert_firing: bool | None  # None: could not be determined -> preconditions fail
    running_version: str | None  # from the app's own /version
    previous_version: str | None  # previous_version recorded for the running version in deploy history
    running_deployed_at: datetime | None
    rollbacks: list[datetime] = field(default_factory=list)  # executed rollbacks (deploy history)
    executed_actions: int = 0  # actions already executed in THIS incident
    image_exists: Callable[[str], bool] = lambda _v: False


# ---------------------------------------------------------------------------- history


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def facts_from_history(records: list[dict[str, Any]], running_version: str | None) -> dict[str, Any]:
    """Derive previous_version / deployed_at / rollback times from deploy/history.jsonl.

    The file holds two record shapes: releases ``{version, previous_version, timestamp, ...}``
    and rollbacks ``{action: "rollback", from, to, timestamp, incident_id}``.
    """

    previous_version: str | None = None
    deployed_at: datetime | None = None
    rollbacks: list[datetime] = []
    for record in records:
        when = parse_time(record.get("timestamp"))
        if record.get("action") == "rollback":
            if when:
                rollbacks.append(when)
            if record.get("to") == running_version:
                deployed_at = when or deployed_at
        elif record.get("version"):
            if record["version"] == running_version:
                previous_version = record.get("previous_version")
                deployed_at = when or deployed_at
    return {"previous_version": previous_version, "running_deployed_at": deployed_at, "rollbacks": rollbacks}


# ---------------------------------------------------------------------------- preconditions

Precondition = Callable[[dict[str, Any], Facts, dict[str, Any], dict[str, Any]], tuple[bool, str]]


def _target(action: dict[str, Any]) -> str | None:
    target = action.get("target_version")
    return target if isinstance(target, str) else None


def pre_alert_still_firing(action, facts, params, policy):
    if facts.alert_firing is True:
        return True, "alert is still firing (observed in Prometheus)"
    if facts.alert_firing is None:
        return False, "could not determine whether the alert is firing"
    return False, "alert is no longer firing"


def pre_target_is_previous_version(action, facts, params, policy):
    target = _target(action)
    if target is None or not VERSION_RE.fullmatch(target):
        return False, f"target_version {target!r} is missing or not a valid version string"
    if facts.previous_version is None:
        return False, "no previous_version recorded in deploy history for the running version"
    if target != facts.previous_version:
        return False, f"target_version {target} is not the previous_version {facts.previous_version} in deploy history"
    if target == facts.running_version:
        return False, "target_version is the version already running"
    return True, f"target_version equals previous_version {facts.previous_version}"


def pre_target_image_exists_locally(action, facts, params, policy):
    target = _target(action)
    if target is None or not VERSION_RE.fullmatch(target):
        return False, "no valid target_version to look up"
    try:
        exists = bool(facts.image_exists(target))
    except Exception as exc:  # fail closed
        return False, f"could not check for image agent-relay:{target}: {type(exc).__name__}"
    return (True, f"image agent-relay:{target} exists locally") if exists else (False, f"image agent-relay:{target} does not exist locally")


def pre_current_deployed_within_max_age(action, facts, params, policy):
    hours = float(params.get("current_version_max_age_hours", 24))
    if facts.running_deployed_at is None:
        return False, "deployment time of the running version is unknown"
    age = facts.now - facts.running_deployed_at
    if age < timedelta(0):
        return False, "deployment time of the running version is in the future"
    if age > timedelta(hours=hours):
        return False, f"running version was deployed {age} ago (> {hours:g}h)"
    return True, f"running version was deployed {age} ago (<= {hours:g}h)"


def pre_no_recent_rollback(action, facts, params, policy):
    minutes = float(params.get("rollback_cooldown_minutes", 30))
    recent = [t for t in facts.rollbacks if timedelta(0) <= facts.now - t <= timedelta(minutes=minutes)]
    if recent:
        return False, f"a rollback was executed {facts.now - max(recent)} ago (cooldown {minutes:g} min)"
    return True, f"no rollback executed in the last {minutes:g} minutes"


def pre_under_action_limit(action, facts, params, policy):
    limit = int(policy.get("limits", {}).get("max_executed_actions_per_incident", 1))
    if facts.executed_actions >= limit:
        return False, f"{facts.executed_actions} action(s) already executed in this incident (max {limit})"
    return True, f"{facts.executed_actions} of {limit} allowed actions executed in this incident"


PRECONDITIONS: dict[str, Precondition] = {
    "alert_still_firing": pre_alert_still_firing,
    "target_is_previous_version": pre_target_is_previous_version,
    "target_image_exists_locally": pre_target_image_exists_locally,
    "current_deployed_within_max_age": pre_current_deployed_within_max_age,
    "no_recent_rollback": pre_no_recent_rollback,
    "under_action_limit": pre_under_action_limit,
}


# ---------------------------------------------------------------------------- policy loading


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise PolicyError("policy must be a mapping with version: 1")
    threshold = policy.get("confidence", {}).get("escalate_below")
    if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
        raise PolicyError("confidence.escalate_below must be a number in [0, 1]")
    actions = policy.get("actions")
    if not isinstance(actions, dict) or not actions:
        raise PolicyError("policy has no actions")
    for name, spec in actions.items():
        if spec.get("level") not in LEVELS:
            raise PolicyError(f"action {name}: level must be one of {LEVELS}")
        for pre in spec.get("preconditions", []):
            if pre not in PRECONDITIONS:
                raise PolicyError(f"action {name}: unknown precondition {pre!r}")
        runbook = spec.get("runbook")
        if runbook is not None and not RUNBOOK_RE.fullmatch(runbook):
            raise PolicyError(f"action {name}: runbook {runbook!r} must be a plain script filename")
        for arg in spec.get("args", []):
            if arg not in ARG_VALIDATORS:
                raise PolicyError(f"action {name}: unknown runbook argument {arg!r}")
        if spec["level"] in ("L1", "L2") and not runbook:
            raise PolicyError(f"action {name}: executable actions need a runbook")
    return policy


def load_policy(path: str | Path) -> dict[str, Any]:
    import yaml  # PyYAML, supplied by `uv run --with pyyaml` / the script's inline metadata

    with open(path, encoding="utf-8") as handle:
        return validate_policy(yaml.safe_load(handle))


# ---------------------------------------------------------------------------- decision


def _result(decision: str, disposition: str, *, action_type: Any, level: str | None, reasons: list[str],
            confidence: dict[str, Any], preconditions: list[dict[str, Any]] | None = None,
            execution: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "decision": decision,  # deny | escalate | record | require_approval | allow_auto
        "disposition": disposition,  # escalate | record | await_approval | execute
        "action_type": action_type if isinstance(action_type, str) else None,
        "level": level,
        "reasons": reasons,
        "confidence_gate": confidence,
        "preconditions": preconditions or [],
        "execution": execution,
    }


def build_execution(policy: dict[str, Any], action_type: str, action: dict[str, Any]) -> dict[str, Any]:
    """Runbook + validated args for an allowed action. Raises PolicyError if anything is off."""

    spec = policy["actions"][action_type]
    args: list[str] = []
    for arg in spec.get("args", []):
        value = action.get(arg)
        if not isinstance(value, str) or not ARG_VALIDATORS[arg].fullmatch(value):
            raise PolicyError(f"argument {arg!r} is missing or invalid")
        args.append(value)
    return {"runbook": spec["runbook"], "args": args}


def decide(policy: dict[str, Any], response: Any, facts: Facts) -> dict[str, Any]:
    """Turn a (schema-valid) responder response into a policy decision.

    `response` is treated as untrusted data. `confidence` is consulted ONLY for the
    downgrade below; it is never an input to any allow decision.
    """

    threshold = float(policy["confidence"]["escalate_below"])
    gate: dict[str, Any] = {"value": None, "escalate_below": threshold, "downgraded": False}

    if not isinstance(response, dict) or not isinstance(response.get("proposed_action"), dict):
        return _result("deny", "escalate", action_type=None, level=None, confidence=gate,
                       reasons=["response has no usable proposed_action; escalating"])
    action = response["proposed_action"]
    action_type = action.get("type")
    confidence = response.get("confidence")
    gate["value"] = confidence if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) else None

    # 1. Unknown or free-form action: deny -> escalate. (Checked before anything else.)
    if not isinstance(action_type, str) or action_type not in policy["actions"]:
        shown = action_type if isinstance(action_type, str) and len(action_type) <= 60 else "<invalid>"
        return _result("deny", "escalate", action_type=action_type, level=None, confidence=gate,
                       reasons=[f"action type {shown!r} is not in the autonomy policy; anything else is denied"])

    # 2. Confidence can only downgrade.
    if gate["value"] is None or not 0 <= gate["value"] <= 1:
        gate["downgraded"] = True
        return _result("escalate", "escalate", action_type=action_type, level="L0", confidence=gate,
                       reasons=["confidence is missing or out of range; escalating"])
    if gate["value"] < threshold:
        gate["downgraded"] = True
        return _result("escalate", "escalate", action_type=action_type, level="L0", confidence=gate,
                       reasons=[f"confidence {gate['value']} is below {threshold}; forced to escalate (confidence can only downgrade)"])

    spec = policy["actions"][action_type]
    level = spec["level"]

    # 3. Always-allowed L0 actions.
    if action_type == "escalate":
        return _result("escalate", "escalate", action_type=action_type, level=level, confidence=gate,
                       reasons=["escalate is always allowed; an escalation packet is produced for a human"])
    if action_type == "no_action":
        return _result("record", "record", action_type=action_type, level=level, confidence=gate,
                       reasons=["no_action is recorded; nothing is executed"])

    # 4. Executable actions: evaluate EVERY precondition (recorded), any failure denies.
    results = []
    for name in spec.get("preconditions", []):
        ok, detail = PRECONDITIONS[name](action, facts, spec.get("params", {}), policy)
        results.append({"name": name, "ok": ok, "detail": detail})
    failed = [r for r in results if not r["ok"]]
    if failed:
        return _result("deny", "escalate", action_type=action_type, level=level, confidence=gate, preconditions=results,
                       reasons=[f"precondition failed: {r['name']}: {r['detail']}" for r in failed])

    try:
        execution = build_execution(policy, action_type, action)
    except PolicyError as exc:
        return _result("deny", "escalate", action_type=action_type, level=level, confidence=gate, preconditions=results,
                       reasons=[f"cannot build a safe execution: {exc}"])

    if level == "L2":
        return _result("allow_auto", "execute", action_type=action_type, level=level, confidence=gate, preconditions=results,
                       execution=execution, reasons=["level L2 and every precondition holds"])
    if level == "L1":
        return _result("require_approval", "await_approval", action_type=action_type, level=level, confidence=gate,
                       preconditions=results, execution=execution,
                       reasons=["level L1: every precondition holds, but a human must approve (respond.py approve <ID>)"])
    return _result("record", "record", action_type=action_type, level=level, confidence=gate, preconditions=results,
                   reasons=["level L0: recorded only"])


def revalidate_for_approval(policy: dict[str, Any], response: Any, facts: Facts, stored_execution: dict[str, Any] | None) -> dict[str, Any]:
    """Approval-time re-check: decide() again on FRESH facts. The approved command must
    still be allowed and must be exactly what was originally proposed."""

    fresh = decide(policy, response, facts)
    if fresh["disposition"] != "await_approval":
        fresh["reasons"].insert(0, "approval refused: the action is no longer allowed on fresh facts")
        return fresh
    if stored_execution is not None and fresh["execution"] != stored_execution:
        return _result("deny", "escalate", action_type=fresh["action_type"], level=fresh["level"], confidence=fresh["confidence_gate"],
                       preconditions=fresh["preconditions"],
                       reasons=["approval refused: the executable command differs from the one originally decided"])
    return fresh


# ---------------------------------------------------------------------------- output validation


def load_schema(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def validate_response(schema: dict[str, Any], response: Any, expected_incident_id: str | None = None) -> list[str]:
    """Strict schema validation of the responder's output (run again in code, whatever the CLI did)."""

    import jsonschema  # supplied by `uv run --with jsonschema` / the script's inline metadata

    validator = jsonschema.Draft202012Validator(schema)
    errors = [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"[:300] for e in validator.iter_errors(response)]
    if not errors and expected_incident_id is not None and response.get("incident_id") != expected_incident_id:
        errors.append(f"incident_id {response.get('incident_id')!r} does not match {expected_incident_id!r}")
    return errors


def decide_from_output(policy: dict[str, Any], schema: dict[str, Any], output: Any, facts: Facts,
                       expected_incident_id: str | None = None) -> dict[str, Any]:
    """Schema-validate first; invalid output means escalate, never an action."""

    errors = validate_response(schema, output, expected_incident_id)
    if errors:
        threshold = float(policy["confidence"]["escalate_below"])
        return _result("escalate", "escalate", action_type=None, level="L0",
                       confidence={"value": None, "escalate_below": threshold, "downgraded": False},
                       reasons=["responder output failed schema validation; escalating"] + errors[:5])
    return decide(policy, output, facts)


__all__ = [
    "Facts",
    "PolicyError",
    "VERSION_RE",
    "build_execution",
    "decide",
    "decide_from_output",
    "facts_from_history",
    "load_policy",
    "load_schema",
    "parse_time",
    "revalidate_for_approval",
    "validate_policy",
    "validate_response",
]
