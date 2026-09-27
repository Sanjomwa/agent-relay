# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema"]
# ///
"""Run the read-only model security review over a snapshot of TRACKED files.

    uv run security-audit/run-model-review.py <run-dir>      # e.g. security-audit/runs/20260926

The snapshot (<run-dir>/snapshot/, gitignored) must already exist (git ls-files copy).
Same lockdown as the incident responder: Read/Grep/Glob only, dontAsk, empty strict MCP
config, no session persistence, advisor disabled, allowlisted environment, budget cap.
Writes <run-dir>/model-review.json (validated findings), model-review-envelope.json (raw
CLI output incl. cost/usage) and model-review-command.txt.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

HERE = Path(__file__).resolve().parent
MODEL = "sonnet"
BUDGET = "2.00"
FORBIDDEN = ("observability/.env", "deploy", "reports.md")
ENV_ALLOWLIST = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
                 "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")


def main() -> int:
    run = Path(sys.argv[1]).resolve()
    snap = run / "snapshot"
    present = [p for p in FORBIDDEN if (snap / p).exists()]
    if present:
        print(f"STOP: snapshot contains {present}; not running the model review", file=sys.stderr)
        return 2
    finding = json.loads((HERE / "findings.schema.json").read_text())
    output_schema = {"type": "object", "additionalProperties": False, "required": ["findings"],
                     "properties": {"findings": {"type": "array", "maxItems": 40, "items": finding}}}
    claude = shutil.which("claude")
    env = {k: os.environ[k] for k in ENV_ALLOWLIST if k in os.environ}
    env.update(LANG=env.get("LANG", "C.UTF-8"), TERM="dumb",
               PATH=":".join((os.path.dirname(claude), "/usr/local/bin", "/usr/bin", "/bin")))
    cmd = ["claude", "-p", "--output-format", "json", "--json-schema", json.dumps(output_schema),
           "--tools", "Read,Grep,Glob", "--permission-mode", "dontAsk",
           "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--no-session-persistence",
           "--disable-slash-commands", "--no-chrome", "--settings", '{"advisorModel":""}',
           "--max-budget-usd", BUDGET, "--model", MODEL]
    prompt = ((HERE / "audit-brief.md").read_text()
              + "\n\nThe files are in your working directory (a snapshot of the repository's tracked files). "
                "Review the scope above and return your findings in the JSON schema.\n")
    version = subprocess.run(["claude", "--version"], capture_output=True, text=True, env=env).stdout.strip()
    started = datetime.now(timezone.utc)
    shown = [c if c != cmd[cmd.index("--json-schema") + 1] else "SCHEMA_FROM_security-audit/findings.schema.json(wrapped in {findings:[...]})" for c in cmd]
    (run / "model-review-command.txt").write_text(
        f"# recorded {started:%Y-%m-%dT%H:%M:%SZ}\ncwd: {snap}\nclaude --version: {version}\nmodel: {MODEL}\nbudget: {BUDGET} USD\n"
        f"environment (names only): {', '.join(sorted(env))}\nprompt: security-audit/audit-brief.md + one closing sentence, on stdin\n"
        f"command:\n  {shlex.join(shown)}\n")
    proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, env=env, cwd=snap, timeout=1800)
    (run / "model-review-envelope.json").write_text(proc.stdout or json.dumps({"stderr": proc.stderr[-2000:], "exit": proc.returncode}))
    env_doc = json.loads(proc.stdout)
    if env_doc.get("is_error"):
        print("responder error:", str(env_doc.get("result"))[:300], file=sys.stderr)
        return 1
    review = env_doc.get("structured_output")
    errors = [e.message for e in jsonschema.Draft202012Validator(output_schema).iter_errors(review)]
    for f in review.get("findings", []) if isinstance(review, dict) else []:
        if f.get("source") != "model" or f.get("disposition") is not None:
            errors.append(f"{f.get('id')}: source must be 'model' and disposition null")
    if errors:
        (run / "model-review.invalid.json").write_text(json.dumps(review, indent=2))
        print("schema validation FAILED:", *errors[:10], sep="\n  ", file=sys.stderr)
        return 1
    (run / "model-review.json").write_text(json.dumps(review, indent=2) + "\n")
    print(f"model review: {len(review['findings'])} findings; cost ${env_doc.get('total_cost_usd'):.3f}; "
          f"turns {env_doc.get('num_turns')}; {env_doc.get('duration_ms', 0) / 1000:.0f}s; "
          f"permission denials {len(env_doc.get('permission_denials') or [])}; schema valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
