# Runbook: claim/complete 5xx (`RelayClaimCompleteErrorRatioHigh`)

This is the runbook the alert's `runbook` annotation points to.

## What the alert means
More than **10%** of requests to one route (`route` label: `/api/v1/tasks/claim` or `/api/v1/tasks/{task_id}/complete`) returned **5xx** over the last minute, with at least 20 requests to that route in the last 2 minutes, for at least 1 minute. The rule is evaluated **per route**, so a failing `complete` cannot be hidden by a healthy `claim`. User impact: agents cannot receive tasks (claim) or cannot finish them (complete), so senders' work is stuck or lost.

Labels tell you where to look: `service`, `environment`, `version` (the running version), `route`, `severity`.

## First checks (2 minutes)
1. **Dashboard** (link in the alert's `dashboard_url`): which routes fail, since when, and which `version` was serving. Is the queue growing (`relay_queue_depth`, `relay_queue_oldest_age_seconds`)?
2. **App health:** `curl -s localhost:8010/ready` (503 means the database check failed) and `curl -s localhost:8010/version`.
3. **Containers:** `docker compose ps -a` and `docker compose -f observability/compose.yaml ps -a`. Is `postgres` up, restarted recently, or unhealthy?
4. **Logs:** Grafana → the "Warnings and errors" panel, or Loki `{service_name="agent-relay"} | detected_level=~"(?i)error|warn.*"`. Look at `exception_type` / message: `failed to resolve host 'postgres'` or `Connection refused` means the **database**, not the app code.
5. **Did anything change?** `tail -n 5 deploy/history.jsonl` (release timestamps, `previous_version`), then compare with when the errors started. **A recent deploy is not proof of cause**: check that the version was healthy before the failure (dashboard, version filter).

## Use the responder
The alert watcher normally does this for you (`uv run incident-response/respond.py watch`). To run it by hand for an alert JSON (from Prometheus `/api/v1/alerts`):

```
uv run incident-response/respond.py run --alert-file <alert.json>
uv run incident-response/respond.py status <INCIDENT_ID>
```

It collects a read-only evidence packet, asks a read-only headless Claude for a **proposal**, validates it, and applies the autonomy policy. Everything is recorded in `incident-response/incidents/<INCIDENT_ID>/` (`timeline.jsonl` first). The model's proposal never runs anything by itself: only code outside the model can, and only the runbook scripts, after your approval.

## Approve a rollback, or escalate?
The responder proposes one of `rollback`, `restart_app`, `escalate`, `no_action`.

**Approve a rollback only when ALL of these hold:**
- the errors are application errors (exceptions from app code, bad responses), not dependency failures;
- the failure started **after** the running version was deployed, and that version was healthy for a while before that or the failure began right at deploy (compare with `deploy/history.jsonl` timestamps and the by-version metrics);
- the proposed target is the running version's `previous_version` and its image exists locally;
- you have read the evidence yourself, not just the summary.

The policy independently enforces: the alert is still firing, target == `previous_version`, the image exists, the running version was deployed within 24 h, no rollback in the last 30 min, and at most one executed action per incident. Approval **re-checks all of that against fresh facts** and refuses if anything changed.

**Escalate (do not roll back) when** the errors point at the database, network, disk or another dependency, when nothing correlates with a deploy, or when the evidence is thin. Rolling back a healthy release does not fix an infrastructure fault and adds risk. `escalate` is always allowed and is the default answer under uncertainty. Confidence below 0.5 is forced to escalate; high confidence never authorizes anything.

**`restart_app`** is for a wedged app process only (`/health` failing, the app not recovering by itself). The app reconnects to the database on its own (`pool_pre_ping`), so restarting for a database outage does not help.

To approve (the command that will run is shown first; add `--yes` to skip the typed confirmation):
```
uv run incident-response/respond.py approve <INCIDENT_ID>
```
The rollback runbook **never builds**: it runs `APP_VERSION=<previous> docker compose up -d --no-build app`, waits for `/version` and `/ready`, and appends `{action:"rollback", from, to, timestamp, incident_id}` to `deploy/history.jsonl`.

## Fixing a dependency outage (the usual case)
- Postgres stopped: `docker compose start postgres` (never `down -v`; that deletes the data volume). The app reconnects by itself; there is nothing to roll back.
- Then verify (below) and record what happened in the incident folder.

## Verify recovery
```
incident-response/runbooks/verify-recovery.sh <INCIDENT_ID> <expected_version>
```
Checks `/ready` = 200, `/version` = expected, a 60 s low-rate traffic probe with 0 errors, the per-route 5xx rate back to 0, and the alert no longer firing (waits up to ~4 minutes for the rate windows). It writes `incidents/<ID>/verification.json` and exits non-zero on failure. `respond.py approve` runs it automatically after an executed action.

## After the incident
Keep the incident folder (`alert.json`, `evidence/`, `responder-*`, `policy-decision.json`, `execution.log`, `verification.json`/`escalation.md`, `timeline.jsonl`). It is the record of what was observed, proposed, authorized, done and verified.
