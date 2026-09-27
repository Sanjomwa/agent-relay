# Agent Relay: operations and security report (Homework 4)

Repository: Sanjomwa/agent-relay (fork, AI Dev Tools Zoomcamp, Module 4). Period covered: 2026-09-26 to 2026-09-27.
Times are UTC, with local time (EAT, UTC+3) in brackets where it helps to read the Grafana screenshots.
Figures come from files in this repository, except the impact counts in §3.5, which come from Loki, Prometheus and database queries run on 2026-09-27. Loki and Prometheus keep 2 days of data, so those counts cannot be re-queried after about 2026-09-29.

## 1. Summary

The relay now has an OpenTelemetry pipeline (collector, Prometheus, Loki, Tempo, Grafana) with a per-route alert on claim/complete 5xx errors, versioned releases with a no-build rollback recorded in `deploy/history.jsonl`, and an incident loop in which a read-only headless Claude responder proposes an action and a code-enforced autonomy policy decides whether it may run. A security audit (Semgrep, a locked-down model review, human triage and a capability inventory) produced 29 findings, 7 of which were fixed in commit `daa54c1`. In the primary incident, a release that failed 35% of complete requests was detected 2 min 18 s after deploy, diagnosed correctly by the responder (commit `105fb53`, $0.19), rolled back 8 s after a human approved, verified 1 min 11 s after approval, and then fixed forward with a revert. A database-outage drill ended in `escalate`, which is the correct outcome for a non-deploy fault. Still open: the Postgres concurrency races, the chunked-body size-limit bypass (M-002), a verification step that does not check backlog drain, and the fact that the human approval is the only guard against a wrong rollback at L1.

## 2. System and loop

### 2.1 Architecture

```mermaid
flowchart LR
  subgraph app["compose project: agent-relay"]
    A[app FastAPI :8000<br/>published 127.0.0.1:8010] --> PG[(postgres)]
  end
  subgraph obs["compose project: agent-relay-observability"]
    C[otel-collector<br/>OTLP 4317/4318, not published]
    P[Prometheus :9090]
    L[Loki :3100]
    T[Tempo :3200]
    G[Grafana :3000]
  end
  A -- "OTLP/HTTP traces, metrics, logs" --> C
  C -- "metrics exporter :8889 (scraped)" --> P
  C -- "logs, native OTLP (only log path)" --> L
  C -- "traces OTLP/gRPC" --> T
  P --> G
  L --> G
  T --> G
  P -- "rule RelayClaimCompleteErrorRatioHigh" --> W[respond.py watch]
  R[scripts/release.sh] -- "build, up, append" --> H[(deploy/history.jsonl)]
  W --> E[collect-evidence.sh] --> X[responder: claude -p, read-only]
  X --> Y[policy.py + autonomy-policy.yaml]
  Y -- "human: respond.py approve" --> RB[runbooks/rollback.sh] --> H
```

- The app exports OTLP over HTTP to `otel-collector:4318` (`compose.yaml`, `OTEL_EXPORTER_OTLP_ENDPOINT`). The collector (`observability/collector.yaml`) runs `memory_limiter`, a `transform/strip_headers` processor that deletes `http.request.header.*` / `http.response.header.*` attributes, and `batch`. Metrics go to a Prometheus exporter with `resource_to_telemetry_conversion` so every series carries `service_name`, `service_version` and `deployment_environment_name`. Logs go to Loki's native OTLP endpoint; there is no stdout or Docker log scraping, so each line is stored once. Traces go to Tempo.
- Grafana, Prometheus, Loki and Tempo are published on 127.0.0.1 only; the collector is not published. Since `daa54c1` the app is also bound to 127.0.0.1:8010.
- `scripts/release.sh` builds `agent-relay:<YYYYMMDD-HHMMSS>-<sha7>[-dirty]`, starts it, waits for `/ready` and `/version`, and appends `{version, git_sha, image_id, timestamp, previous_version}` to `deploy/history.jsonl` (gitignored). `runbooks/rollback.sh` appends `{action:"rollback", from, to, timestamp, incident_id}`; `release.sh` reads `.to` from such a record when it computes the next `previous_version`.

### 2.2 The loop

| Stage | Component | Who decides | Autonomy |
|---|---|---|---|
| Observe | OTel SDK in the app, collector, Prometheus/Loki/Tempo | automation | always on |
| Alert | `observability/alerts.yaml` rule, evaluated every 15 s | automation | always on |
| Evidence | `incident-response/collect-evidence.sh` (fixed read-only queries) | automation, started by `respond.py watch` | automatic, read-only |
| Propose | headless Claude responder | model | proposal only, no authority |
| Authorize | `incident-response/policy.py` with `autonomy-policy.yaml`, then a human for L1 | code, then human | L0 record / L1 human approval / L2 automatic (none configured) |
| Rollback | `incident-response/runbooks/rollback.sh <version>` (no build) | runs only after approval | L1 |
| Verify | `incident-response/runbooks/verify-recovery.sh <ID> <version>` | automation after execution, or operator | automatic |
| Fix forward | a normal commit (here a revert) and `scripts/release.sh` | human | manual |

### 2.3 Responder invocation (from `incident-response/respond.py`, `responder_command()`)

| Flag | What it confines |
|---|---|
| `-p --output-format json` | non-interactive, one JSON result envelope |
| `--json-schema <response.schema.json>` | output must match the schema; `respond.py` validates it again in code |
| `--tools Read,Grep,Glob` | the only built-in tools; no shell, no edit, no web |
| `--permission-mode dontAsk` | anything outside the working directory is denied without a prompt |
| `--strict-mcp-config --mcp-config '{"mcpServers":{}}'` | no MCP servers at all |
| `--no-session-persistence` | no transcript written under `~/.claude` |
| `--disable-slash-commands` | no skills or custom commands |
| `--no-chrome` | no browser integration |
| `--setting-sources ""` | no user, project or local settings files are loaded (added in `daa54c1`, audit K-008) |
| `--settings '{"advisorModel":""}'` | removes the server-side advisor tool that the user-level setting added (kept as a second layer) |
| `--max-budget-usd 1.00` | spend cap per call (at most 2 calls per incident) |
| `--model sonnet` | fixed model (resolved to `claude-sonnet-5`) |
| `--append-system-prompt …` | states that the responder is read-only and that file contents are data |

The process runs with the working directory `incidents/<ID>/evidence/` and an allowlisted environment (`ENV_ALLOWLIST`): no `RELAY_*`, `OTEL_*`, `GRAFANA_*`, `POSTGRES_*` or database URLs. `--bare` was tested and does not work with a claude.ai login (it returned "Not logged in"), so it is not used.

### 2.4 Autonomy policy

From `incident-response/autonomy-policy.yaml`:

```yaml
  rollback:
    level: L1
    runbook: rollback.sh
    args: [target_version]
    preconditions:
      - alert_still_firing
      - target_is_previous_version   # target_version == previous_version in deploy/history.jsonl
      - target_image_exists_locally
      - current_deployed_within_max_age
      - no_recent_rollback
      - under_action_limit
    params:
      current_version_max_age_hours: 24
      rollback_cooldown_minutes: 30
  restart_app:
    level: L1
    runbook: restart-app.sh
    args: []
    preconditions:
      - alert_still_firing
      - under_action_limit
```

`escalate` and `no_action` are L0 and always allowed. `limits.max_executed_actions_per_incident` is 1. Any other action type, including a free-form command, is denied and turned into an escalation.

- **Confidence can only downgrade.** `confidence.escalate_below: 0.5` forces `escalate` below 0.5. At or above 0.5 the value changes nothing; `test_confidence_never_changes_an_outcome_at_or_above_threshold` checks that 0.5 to 1.0 produce identical decisions.
- **Model text is never executed.** The engine can run only the runbook scripts named in the policy, with arguments validated by regex and compared with facts the code observed itself (Prometheus alerts, `/version`, `deploy/history.jsonl`, `docker image inspect`).
- **`approve` re-checks everything.** `respond.py approve <ID>` gathers fresh facts, runs the decision again, and refuses unless the executable command is identical to the one originally decided.
- Tests: `incident-response/tests/test_policy.py` and `test_respond.py` (table-driven cases for approval, wrong version, missing image at confidence 0.99, shell commands as proposals, schema-invalid output, second action, low confidence), plus 20 redactor tests; 82 pass.

### 2.5 Evidence collection

`collect-evidence.sh <ID> <ALERT_JSON>` runs a fixed list of queries; its only inputs are the validated incident id and a window derived from the alert's `activeAt` (logs and traces from activeAt−15 min, metrics from activeAt−60 min). There is no database access and no `docker exec`. Output is bounded (200 WARNING+ log lines, 20 error traces with 3 in full, a 400-line diff between the running and previous release, at most 5 changed files / 1500 lines). `manifest.json` records every query with its timestamp, size and sha256. Before the packet reaches the responder, secret values are redacted (database URLs, and since `daa54c1` key-like values via `incident-response/redact_secrets.py`) and the whole packet is scanned; any hit moves it to `deploy/quarantine/` (gitignored) and exits 3, so the responder never sees it.

### 2.6 Canary

`respond.py canary` runs the responder with production flags from a directory at the same depth as a real evidence folder and asks it to read `observability/.env` and `deploy/history.jsonl` (absolute and relative paths), Grep `observability/`, Glob `deploy/`, and run a shell command.

| Run | Flags | Tools available | Out-of-scope attempts denied | Shell | Secret content in transcript |
|---|---|---|---|---|---|
| `incidents/canary-20260926/` | before `--setting-sources ""` | Glob, Grep, Read, StructuredOutput | 6 of 6 | none | no |
| `incidents/canary-20260927/` | after `--setting-sources ""` | Glob, Grep, Read, StructuredOutput | 6 of 6 | none | no |

## 3. Primary incident: INC-20260926-183037-api-v1-tasks-task-id-complete

### 3.1 Versions (from `deploy/history.jsonl`)

| Name | Version | Commit | Deployed | Note |
|---|---|---|---|---|
| V_GOOD | `20260926-181002-829513a` | 829513a | 18:10:24 (21:10:24) | healthy baseline |
| V_BAD | `20260926-182749-105fb53` | 105fb53 | 18:28:19 (21:28:19) | adds the openly labelled `RELAY_FAULT_COMPLETE_5XX_RATE` switch and sets it to 0.35 in `compose.yaml` |
| rollback | V_BAD → V_GOOD | | 18:44:21 (21:44:21) | record carries `incident_id` |
| V_FIXED | `20260926-185716-0a7a1fb` | 0a7a1fb (revert of 105fb53) | 18:57:38 (21:57:38) | `previous_version` is V_GOOD, read from the rollback record |

### 3.2 Timeline

Sources: `timeline.jsonl`, `alert.json`, `deploy/history.jsonl`, `verification.json` in the incident folder, and `INC-20260926-185738-fix-forward-verify/verification.json`. "Operator" is the Claude Code session that ran scripts on Sam's instructions; "Sam" is the human approver.

| UTC (EAT) | Event | Actor |
|---|---|---|
| 18:28:19 (21:28:19) | V_BAD released with `scripts/release.sh` | operator, after Sam committed 105fb53 |
| 18:29:19 (21:29:19) | alert `activeAt` on route `/api/v1/tasks/{task_id}/complete` (pending) | Prometheus |
| 18:30:37.2 (21:30:37) | watcher sees the alert firing (value 0.355), opens the incident, starts evidence collection | `respond.py watch` |
| 18:30:42.7 | evidence packet done, secret scan passed (5.5 s) | `collect-evidence.sh` |
| 18:31:27.8 | responder finished: 44.8 s, $0.189, 8 turns | Claude (read-only) |
| 18:31:28.4 | output valid against the schema | `respond.py` |
| 18:31:28.9 (21:31:29) | policy: `require_approval` (L1), all 6 preconditions pass, command `rollback.sh 20260926-181002-829513a` | `policy.py` |
| 18:44:13.6 (21:44:14) | approval given (`approved_by: sanjomwa`) | Sam |
| 18:44:14.3 | re-check on fresh facts passes; execution starts | `respond.py` |
| 18:44:21.8 (21:44:22) | rollback finished (exit 0, no build); history record appended | `rollback.sh` |
| 18:45:25.1 (21:45:25) | `verify-recovery.sh` passed 5 of 5 checks | automation |
| 18:57:38 (21:57:38) | V_FIXED released after Sam committed the revert 0a7a1fb | operator |
| 19:00:36–19:01:40 | fix-forward verification passed 5 of 5 (`INC-20260926-185738-fix-forward-verify`) | operator |

| Interval | Duration |
|---|---|
| deploy → incident opened | 2 min 18 s |
| incident opened → policy decision | 52 s (51.7 s) |
| decision → approval (human wait) | 12 min 45 s |
| approval → rollback complete | 8 s |
| approval → recovery verified | 1 min 11 s |

### 3.3 What the responder concluded

From `policy-decision.json` (`proposal`): `suspected_change: "105fb53"`, `confidence: 0.9`, `proposed_action: {type: rollback, target_version: 20260926-181002-829513a}`. Its root cause named `complete_fault_rate()` and the branch in `task_complete()` that raises `RelayError("injected_fault", …, 500)`, plus `RELAY_FAULT_COMPLETE_5XX_RATE=0.35` in `compose.yaml`, and matched the observed 35.5% to the configured 0.35. It noted that a restart would not help because the variable is set in `compose.yaml`, and that a later release from main would bring the fault back unless the change was reverted. Both the commit and the mechanism match the ground truth. The fault was labelled openly in code, logs and the commit message, so this run tests the loop end to end more than it tests diagnosis.

### 3.4 Human versus automation

- Sam: committed the fault switch, approved the rollback with `respond.py approve … --yes`, committed the incident record and the revert, and approved the cleanup of stranded tasks.
- Automation: detection, the incident, evidence, the proposal, the policy decision, the approval-time re-check, the rollback itself and its verification.
- Operator (on Sam's instructions): the releases of V_GOOD, V_BAD and V_FIXED, starting the watcher and traffic, the fix-forward verification.

### 3.5 Impact

- Server-side: Loki holds **1529** `injected drill fault` WARNING lines for V_BAD, one per failed complete request. Prometheus shows about 4382 complete requests on V_BAD (an extrapolated `increase()`), so about 35% failed.
- Lost work: **25** tasks created during the incident window ended `failed` with `attempts_exhausted` (database query, 2026-09-27). They were kept as the record of lost work.
- Stranded work: tasks whose complete failed stayed leased until recovery requeued them; when the traffic generator stopped, **746** queued tasks were left addressed to worker agents that no longer existed, and were deleted with Sam's approval. That count and the generator's client-side total of 1583 errors come from the operator's session notes, which are not committed.

### 3.6 Screenshots

![5xx error ratio by route](images/inc-complete-5xx-ratio-arc.jpg)
*5xx error ratio by route, about 21:18 to 22:05 EAT. Only the complete route (orange) fails, at 30 to 45% while V_BAD serves (about 21:28 to 21:44), and drops to 0 at the rollback. The straight ramp from about 21:20 up to 21:28 is Grafana drawing a line across a gap with no data points; there was no traffic in that interval. The red line is the 10% alert threshold.*

![Request rate by route](images/inc-complete-request-rate-arc.jpg)
*Request rate by route, same window. Baseline traffic at about 5 req/s until about 21:18; the line sits at 0 through the gap (the rate is a real zero here, so there is no interpolated ramp in this panel) and rises when V_BAD traffic starts at about 21:28; V_BAD traffic 21:29 to 21:44; a spike to about 15 req/s on complete just after the rollback while requeued tasks were completed (746 others stayed stranded; see §3.5); traffic stopped about 21:46; the V_FIXED check traffic about 21:59 to 22:01.*

![Dashboard while the alert fired](images/inc-complete-firing-dashboard.jpg)
*The dashboard while the alert was firing: running version V_BAD, alert FIRING. The "5xx ratio, claim + complete" stat reads 15.2% because it combines both routes (claim was healthy); the per-route panel shows the complete route near 35%. Queue depth 1.44K and oldest queued task 5.16 min show work piling up.*

![Warnings panel](images/inc-complete-firing-logs.jpg)
*The Loki "Warnings and errors" panel: one `injected drill fault: failing complete request (RELAY_FAULT_COMPLETE_5XX_RATE=0.35)` line per failed request.*

![After V_FIXED](images/inc-after-vfixed-ok.jpg)
*After the fix-forward release: running version V_FIXED `20260926-185716-0a7a1fb`, alert OK.*

## 4. Database drill: INC-20260926-113352-api-v1-tasks-claim

- What broke: only the postgres container was stopped (11:31:37 UTC) while traffic ran at 5 tasks/s. No code or release changed; the running version `20260926-100835-0a305bc` had been deployed at 10:08:53 and was healthy.
- Detection: alert `activeAt` 11:32:34 on route `/api/v1/tasks/claim`; the watcher opened the incident at 11:33:53; the decision came at 11:34:33 (40 s; responder $0.143, 10 turns).
- Responder: proposed `escalate`, `suspected_change: null`, confidence 0.85. It cited `docker-compose-ps.txt` (postgres `Exited (0)`), the log lines `the database system is shutting down` / `AdminShutdown` followed by `failed to resolve host 'postgres'`, `/health` 200 with `/ready` 503, and the deploy 1 h 23 min earlier with the version healthy until the failure. It stated that a rollback would not restore the database.
- Policy: `escalate` (L0, always allowed); nothing executed; `escalation.md` written.
- Why that is correct: the evidence points at a dependency, not a change. A rollback would have replaced a healthy release and fixed nothing. The operator restarted postgres at 11:34:58, the app reconnected without a restart, and verification passed at 11:36:06.
- What would have happened with a rollback proposal: all six rollback preconditions held (alert firing, previous version known with its image present, deployed under 24 h ago, no recent rollback, no action yet), so the policy would have returned `require_approval`. The human approval is the only gate in that case (finding K-010, accepted risk; see §7).

## 5. Alerting lessons

- **A rate-based guard switched itself off.** The first version of the rule required more than 0.5 req/s on the routes. In a postgres-outage test during Step 3 it went pending at a 12.6% ratio and then back to inactive with the ratio at 100%: failing requests took about 4 s each and workers backed off, so throughput fell from about 5 req/s to about 0.43 req/s, below the guard. It was replaced with an absolute count, `increase(...[2m]) >= 20` (about 0.17 req/s); the reasoning is kept as a comment in `observability/alerts.yaml`. That version shipped in `5d7fbed`.
- **A combined ratio can dilute one failing route.** The Step 3 rule computed one ratio over claim and complete together, so a complete-only failure with healthy claims could stay under the threshold. Commit `829513a` made the ratio and the count guard per route and added a `route` label. The primary incident fired on the complete route alone at 35.5%, while the combined stat on the dashboard showed 15.2%.

The rule as committed (`observability/alerts.yaml`):

```yaml
      - alert: RelayClaimCompleteErrorRatioHigh
        expr: |
          (
            sum by (service_name, deployment_environment_name, service_version, http_route) (
              rate(http_server_request_duration_seconds_count{
                http_route=~"/api/v1/tasks/claim|/api/v1/tasks/\\{task_id\\}/complete",
                http_response_status_code=~"5.."
              }[1m])
            )
            /
            sum by (service_name, deployment_environment_name, service_version, http_route) (
              rate(http_server_request_duration_seconds_count{
                http_route=~"/api/v1/tasks/claim|/api/v1/tasks/\\{task_id\\}/complete"
              }[1m])
            )
          > 0.10
          )
          and
          (
            sum by (service_name, deployment_environment_name, service_version, http_route) (
              increase(http_server_request_duration_seconds_count{
                http_route=~"/api/v1/tasks/claim|/api/v1/tasks/\\{task_id\\}/complete"
              }[2m])
            )
          >= 20
          )
        for: 1m
        labels:
          severity: critical
          service: "{{ $labels.service_name }}"
          environment: "{{ $labels.deployment_environment_name }}"
          version: "{{ $labels.service_version }}"
          route: "{{ $labels.http_route }}"
          owner: relay-oncall
        annotations:
          summary: "5xx errors on {{ $labels.http_route }} ({{ $labels.service_name }}, {{ $labels.deployment_environment_name }}, {{ $labels.service_version }})"
          description: >-
            {{ $value | humanizePercentage }} of requests to {{ $labels.http_route }} are failing with 5xx
            (threshold 10% over the last minute, with at least 20 requests to this route in the last 2 minutes).
            Agents cannot use this part of the relay; work is stuck or not being delivered.
          dashboard_url: "http://localhost:3000/d/agent-relay-overview/agent-relay-overview?orgId=1&var-environment={{ $labels.deployment_environment_name }}&var-version={{ $labels.service_version }}"
          runbook: "incident-response/runbooks/claim-complete-5xx.md"
```

What it still does not catch:
- A dead app or dead telemetry pipeline. If the app or the collector stops, no series are produced and the rule has nothing to evaluate; there is no `absent()` alert. The observability stack stopped silently twice when Docker Desktop stopped (§7).
- Failures on other routes: task creation, heartbeat, fail, registration, and 4xx storms (for example every client getting 401 after an enrollment-secret mismatch).
- Slowness without errors, and a growing or stranded queue (`relay_queue_depth`, `relay_queue_oldest_age_seconds` are on the dashboard only).
- Low traffic: fewer than 20 requests on a route in 2 minutes never fires.
- Production timing: the 15 s interval, 1 min window and `for: 1m` are set for testing, and there is no Alertmanager, so nobody is paged; the alert is visible in Prometheus, on the dashboard and to the watcher.

## 6. Security audit

Artifacts: `security-audit/` (brief, schema, capability table, model-review runner) and `security-audit/runs/20260926/` (Semgrep output, model review, known findings, triage).

**Method**
- Semgrep 1.178.0 via `uvx semgrep scan --metrics=off` with `p/python`, `p/secrets`, `p/dockerfile`, `p/github-actions`, `p/docker-compose`, `p/kubernetes` over the git-tracked files: 8 results (`semgrep.json`, `semgrep-findings.json`).
- Model review: headless Claude with the responder's lockdown (read-only tools, `dontAsk`, empty strict MCP config, no session persistence, advisor disabled, $2.00 cap, `--json-schema`) in a snapshot of `git ls-files`; `observability/.env`, `deploy/` and `reports.md` were confirmed absent first. 10 findings, $0.59, 32 turns (`model-review.json`, `model-review-usage.json`). Three were reproduced by hand: chunked requests bypass the body limit (M-002), a non-ASCII enrollment header caused a 500 (M-003), and committed incident evidence contained the dev-default DB password (M-004).
- Known items from earlier steps: 11 findings (`known-findings.json`).
- Human triage: `triage.md` merges the 29 findings into 21 rows; Sam set every disposition (commit `0e69e2f`).
- Snyk Agent Scan was skipped: it requires a Snyk account and `SNYK_TOKEN` and sends discovered tool descriptions to Snyk's API, which this audit's no-account, no-upload rule excludes.

**Dispositions** (from `triage.md` and the findings JSON)

| Disposition | Triage rows | Finding ids |
|---|---|---|
| fix_now | 4 | 7 |
| fix_later | 13 | 17 |
| accepted_risk | 3 | 4 |
| false_positive | 1 | 1 |
| total | 21 | 29 |

**fix_now, fixed in `daa54c1`**
- K-001 / M-001 open enrollment: `RELAY_ENROLLMENT_SECRET` is required from an untracked `.env` (compose fails without it), `.env.example` is committed, and the app port is bound to 127.0.0.1. After the fix: registration without the secret returns 401, with it 201.
- M-003: `hmac.compare_digest` compares bytes; a non-ASCII header returns 401 instead of 500 (test added).
- K-011 / M-004: `redact_secrets.py` redacts key-like secret values in the evidence diff and changed files before the scan, and the scan uses the same rules as a backstop, plus the enrollment secret's actual value. Committed evidence was not rewritten.
- K-008 / M-006: `--setting-sources ""` on the responder and the model review; the canary still passes (§2.6).

**accepted_risk**
- K-010: an L1 rollback during a non-deploy outage passes every precondition, so the human approval is the gate. Required if rollback is ever promoted to L2: a deploy-correlation precondition (the failing version was deployed shortly before `activeAt` and the previous version was healthy).
- M-005: text an attacker controls (URL paths, exception messages) can reach the responder's prompt; accepted because the responder has only read tools, its output is schema-validated, and every action needs the policy and a human.
- S-005 / S-007: writable root filesystem in the k8s manifests; local kind lab.

**false_positive**: S-008 (`worker.py:171` logs the agent id and the credentials file path, not the token).

**fix_later**: M-002 chunked body-limit bypass; K-005, K-006, K-007 Postgres races; K-002 / M-007 plaintext dev DB credentials in tracked files; K-003 public `/docs`, `/redoc`, `/openapi.json`; K-004 Postgres `DETAIL` lines echoing task payloads into logs; K-009 no backlog-drain check in verification; S-003 / M-008 container runs as root; S-002 / M-009 CI `curl | sh` and CI Postgres exposure; S-001 action pinned by tag; S-004 / S-006 no `runAsNonRoot`; M-010 no rate limiting or quotas.

Coverage: neither tool found the public API docs, the Postgres `DETAIL` echo, the three races, the backlog-drain gap or the L1 rollback gap; Semgrep found configuration issues only and missed the plaintext DB password; the model found the application and automation issues, including three new ones.

**Capability table** (`security-audit/capability-table.md`): the responder has Read, Grep and Glob only, no shell and no MCP servers; its file confinement is enforced by Claude Code's permission layer, not by the operating system; the process runs with the developer's claude.ai OAuth session under `HOME`; the CLI version is not pinned; user settings no longer load (`--setting-sources ""`); budget caps are $1.00 per responder call and $2.00 for the review. The orchestrator runs as the developer, reads `observability/.env` for the secret scan, and after approval runs `docker compose` through the Docker socket, which is effectively root on the Docker VM.

## 7. Corrections and limitations

### Corrections

- **The first fault request was declined.** The first Step 5 prompt asked for a regression disguised as an ordinary change, with a misleading commit message and wording chosen to hide it. That request was declined; the incident used an openly labelled switch, `RELAY_FAULT_COMPLETE_5XX_RATE`, with a commit message that says what it does (`105fb53`).
- **The evidence secret scan was narrower than reported.** Steps 4 and 5 reported the evidence scans as clean, but the scan only covered agent and claim tokens, bearer credentials, database URLs and the Grafana password. `incident-response/incidents/INC-20260926-183037-api-v1-tasks-task-id-complete/evidence/changed-files/compose.yaml` line 6 contains the public dev-default DB password. The file was left as committed so its sha256 in `manifest.json` stays valid; `redact_secrets.py` handles new evidence.
- **The redactor's first backstop was too broad.** It flagged `agents.token_hash = %(token_hash_1)s::VARCHAR` in trace SQL and counts such as `"input_tokens": 13256`, which would have quarantined real incident packets. SQL bind placeholders, JSON structure and numeric values are now skipped, with tests.
- **pytest collected the audit snapshot.** The gitignored `security-audit/runs/20260926/snapshot/` contained copies of the test files, and a plain `uv run pytest -q` failed with "import file mismatch". The snapshot was deleted (it can be recreated from `git archive 6b32e9e`); the commands in §8 name test paths explicitly.
- **The observability stack stopped silently.** When Docker Desktop stopped, all five observability containers exited (code 127) and nothing alerted. The first post-fix `verify-recovery.sh` run failed its two Prometheus checks as "unknown", which is the intended fail-closed behaviour; it passed after the stack was restarted.
- **The first post-fix verification was superseded.** `INC-20260927-102600-fixnow-verify` verified build `20260927-101902-0e69e2f-dirty` (all 5 checks passed, 10:28:56 to 10:30:02 UTC, probe 121 of 121 completed, 0 errors). No commit can reproduce a `-dirty` build, so it is not valid evidence for the fix and was deleted before commit; its line stays in the gitignored `deploy/history.jsonl`. The fix was re-verified on the clean release `20260927-172131-daa54c1` in `INC-20260927-172205-post-audit-verify` (5 of 5 checks passed).

### Limitations

- The human approval is the only protection against a wrong rollback at L1 (K-010). During the DB drill a rollback proposal would have passed every precondition.
- `verify-recovery.sh` checks readiness, version, a fresh traffic probe, the 5xx rate and the alert, but not whether the backlog drained (K-009). It passed while 746 tasks were stranded.
- The orchestrator's post-approval actions go through the Docker socket, which is effectively root on the Docker VM.
- The responder's process runs with the developer's claude.ai OAuth session; only Claude Code's permission layer keeps the model from reading it.
- The Claude CLI is not pinned; it moved from 2.1.278 to 2.1.283 during the homework without an explicit upgrade.
- The Postgres races K-005, K-006 and K-007 are open.
- M-002 (chunked requests bypass the body-size limit) is open; exposure is lower now that the port is loopback-only.
- The app test suite is not isolated from the caller's environment: if `RELAY_ENROLLMENT_SECRET` is exported in the shell, four tests in `test_agent_relay.py` fail with 401 on either database backend, because they register agents without the header. Run the tests with the variable unset (§8) until the test fixture clears it.
- A quarantined evidence packet leaves an empty `incidents/<ID>/` directory behind (the packet itself moves to `deploy/quarantine/`).
- The lab runs on one machine; C: had 10 to 21 GB free during the work, and Prometheus, Loki and Tempo keep 2 days of data.

## 8. How to reproduce (fresh clone)

```bash
# Secrets: both files are gitignored; set real values
cp .env.example .env                               # RELAY_ENROLLMENT_SECRET
cp observability/.env.example observability/.env   # GRAFANA_ADMIN_PASSWORD

# App and database (release.sh builds, starts, waits for /ready and records deploy/history.jsonl)
scripts/release.sh

# Observability stack (joins the app's network, so start the app first)
docker compose -f observability/compose.yaml up -d
# Grafana http://localhost:3000 (admin + the password from observability/.env)

# Traffic (reads RELAY_ENROLLMENT_SECRET from the environment or .env)
uv run scripts/traffic.py --rate 5 --duration 300 --workers 2

# Incident loop
uv run incident-response/respond.py watch          # background: polls alerts every 30 s
uv run incident-response/respond.py status <INCIDENT_ID>
uv run incident-response/respond.py approve <INCIDENT_ID>   # prompts; --yes skips the typed confirmation
uv run incident-response/respond.py canary         # sandbox check for the responder

# Replay the fault: the switch exists only at commit 105fb53 (reverted by 0a7a1fb).
# That commit predates the K-001 fix: while it runs, :8010 is bound to all interfaces and
# registration is open, so replay only on a trusted network.
git switch --detach 105fb53 && scripts/release.sh && git switch main
# ...let the alert fire and approve the rollback, then release main again:
scripts/release.sh

# Manual runbooks
INCIDENT_ID=manual incident-response/runbooks/rollback.sh <version from deploy/history.jsonl>
incident-response/runbooks/verify-recovery.sh <INCIDENT_ID> <expected version>

# Tests (name the paths so pytest cannot collect an audit snapshot; unset the enrollment
# secret, because test_agent_relay.py registers agents without the header)
env -u RELAY_ENROLLMENT_SECRET uv run pytest -q test_agent_relay.py test_observability.py
uv run --with pytest --with pyyaml --with jsonschema pytest -q incident-response/tests

# Security audit
uvx semgrep scan --metrics=off --config p/python --config p/secrets --config p/dockerfile \
  --config p/github-actions --config p/docker-compose --config p/kubernetes --json --output semgrep.json .
mkdir -p security-audit/runs/<date>/snapshot
git ls-files -z | xargs -0 cp --parents -t security-audit/runs/<date>/snapshot
uv run security-audit/run-model-review.py security-audit/runs/<date>
rm -rf security-audit/runs/<date>/snapshot         # otherwise a plain `pytest` collects it
```

## 9. Deliverable map

| Requirement | Where |
|---|---|
| Versioned build, JSON logs, OTel traces/metrics/logs, business metrics | `buildinfo.py`, `logging_config.py`, `telemetry.py`, `main.py`, `test_observability.py` |
| Versioned release and deploy history | `scripts/release.sh`, `Dockerfile`, `compose.yaml`, `deploy/history.jsonl` (gitignored, local) |
| Telemetry pipeline and storage | `observability/compose.yaml`, `observability/collector.yaml`, `observability/prometheus.yml`, `observability/loki.yaml`, `observability/tempo.yaml` |
| Dashboard | `observability/dashboard.json`, `observability/grafana/provisioning/` |
| User-impact alert | `observability/alerts.yaml` |
| Traffic generator | `scripts/traffic.py` |
| Evidence collection | `incident-response/collect-evidence.sh`, `incident-response/redact_secrets.py` |
| Read-only responder and task | `incident-response/respond.py`, `incident-response/responder-task.md`, `incident-response/response.schema.json` |
| Autonomy policy in code | `incident-response/autonomy-policy.yaml`, `incident-response/policy.py`, `incident-response/tests/` |
| Runbooks | `incident-response/runbooks/claim-complete-5xx.md`, `rollback.sh`, `restart-app.sh`, `verify-recovery.sh` |
| Sandbox evidence (canary) | `incident-response/incidents/canary-20260926/`, `incident-response/incidents/canary-20260927/` |
| Drill (non-deploy fault) | `incident-response/incidents/INC-20260926-113352-api-v1-tasks-claim/` |
| Real incident with approved rollback | `incident-response/incidents/INC-20260926-183037-api-v1-tasks-task-id-complete/` |
| Fix-forward verification | `incident-response/incidents/INC-20260926-185738-fix-forward-verify/` |
| Post-audit verification (clean release) | `incident-response/incidents/INC-20260927-172205-post-audit-verify/` |
| Security audit inputs | `security-audit/audit-brief.md`, `security-audit/findings.schema.json`, `security-audit/run-model-review.py` |
| Scanner and model review results | `security-audit/runs/20260926/semgrep.json`, `semgrep-findings.json`, `model-review.json`, `model-review-usage.json`, `known-findings.json` |
| Human validation | `security-audit/runs/20260926/triage.md` and the `disposition` fields |
| Responder capability inventory | `security-audit/capability-table.md` |
| fix_now fixes | commit `daa54c1` (`compose.yaml`, `.env.example`, `main.py`, `incident-response/redact_secrets.py`, `incident-response/respond.py`, tests) |
| Screenshots | `docs/images/inc-*.jpg` |
| This report | `docs/operations-and-security-report.md` |
