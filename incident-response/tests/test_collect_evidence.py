"""collect-evidence.sh quarantine behaviour, run hermetically in a temp tree.

curl and docker are stubbed so nothing touches the network or the Docker daemon, and
the script runs from a copy so the real incidents/ and deploy/ folders are untouched.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
INCIDENT_ID = "INC-20260101-000000-quarantine-test"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("bash", "jq", "python3", "sha256sum")),
    reason="collect-evidence.sh needs bash, jq, python3 and sha256sum",
)


def run_collect(tmp_path: Path, *, keep_record: bool) -> tuple[subprocess.CompletedProcess, Path]:
    root = tmp_path / "repo"
    (root / "incident-response").mkdir(parents=True)
    for name in ("collect-evidence.sh", "redact_secrets.py"):
        shutil.copy2(HERE / name, root / "incident-response" / name)
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for tool, body in (("curl", "exit 7"), ("docker", "echo stubbed")):
        (stubs / tool).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / tool).chmod(0o755)

    incident_dir = root / "incident-response" / "incidents" / INCIDENT_ID
    if keep_record:
        # respond.py writes the alert (and timeline) here before collecting evidence.
        incident_dir.mkdir(parents=True)
        (incident_dir / "alert.json").write_text("{}")

    # The alert is copied into the packet, so a token-shaped label forces a scan hit.
    alert = tmp_path / "alert.json"
    token = "agt_" + "A" * 24
    alert.write_text(json.dumps({"labels": {"alertname": "Test", "note": token}, "activeAt": "2026-01-01T00:00:00Z", "state": "firing"}))

    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
    proc = subprocess.run(
        ["bash", str(root / "incident-response" / "collect-evidence.sh"), INCIDENT_ID, str(alert)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    return proc, root


def test_quarantine_removes_the_empty_incident_dir(tmp_path):
    proc, root = run_collect(tmp_path, keep_record=False)
    assert proc.returncode == 3, proc.stderr
    assert not (root / "incident-response" / "incidents" / INCIDENT_ID).exists()
    quarantined = list((root / "deploy" / "quarantine").glob(f"{INCIDENT_ID}-*"))
    assert len(quarantined) == 1 and (quarantined[0] / "alert.json").is_file()


def test_quarantine_keeps_an_incident_dir_that_holds_a_record(tmp_path):
    proc, root = run_collect(tmp_path, keep_record=True)
    assert proc.returncode == 3, proc.stderr
    incident_dir = root / "incident-response" / "incidents" / INCIDENT_ID
    assert (incident_dir / "alert.json").is_file()
    assert not (incident_dir / "evidence").exists()
