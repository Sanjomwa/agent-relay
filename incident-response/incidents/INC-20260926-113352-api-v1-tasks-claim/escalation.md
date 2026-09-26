# Escalation: INC-20260926-113352-api-v1-tasks-claim

**Why a human is needed:** escalate is always allowed; an escalation packet is produced for a human

## Alert
- `RelayClaimCompleteErrorRatioHigh` on route `/api/v1/tasks/claim`, version `20260926-100835-0a305bc`, environment `local`
- active since 2026-09-26T11:32:34.038480383Z; 100% of requests to /api/v1/tasks/claim are failing with 5xx (threshold 10% over the last minute, with at least 20 requests to this route in the last 2 minutes). Agents cannot use this part of the relay; work is stuck or not being delivered.
- runbook: `incident-response/runbooks/claim-complete-5xx.md`; dashboard: http://localhost:3000/d/agent-relay-overview/agent-relay-overview?orgId=1&var-environment=local&var-version=20260926-100835-0a305bc

## Policy decision
- decision `escalate` (level L0), disposition `escalate`
- escalate is always allowed; an escalation packet is produced for a human

## Responder's proposal (advisory only)
- summary: All claim requests are failing with 5xx because the app cannot reach its Postgres database. The postgres container was shut down cleanly at about 11:31:36 and is still Exited. The running release 0a305bc was deployed at 10:08 and was serving normally until then. The evidence does not support a code or deploy cause.
- root-cause hypothesis: The agent-relay-postgres-1 container was stopped (Exited (0), "administrator command" shutdown) around 11:31:36. This is an infrastructure or operator action, not a crash of the app. The app first got "the database system is shutting down" and AdminShutdown errors. Once the container was gone, every DB call failed with "failed to resolve host 'postgres'". The claim route needs the DB, so it returns 5xx, as do the lease recovery passes and /ready. The app process is not wedged: /health returns 200 and /ready returns 503 not_ready. The app will likely recover on its own once Postgres is back, though whether its DB connection pool reconnects cleanly is not shown in the evidence. Rolling back to 20260926-093326-64dddaf-dirty would not fix a stopped database.
- proposed action: `escalate` (target_version: None); confidence 0.85
- rationale: The root cause is the stopped postgres container, an infrastructure dependency. A rollback would not restore the database and would only add risk. A restart_app is not justified: /health is 200 and the app is not wedged. It would also fail to connect while postgres is down. A human should find out why postgres was stopped (deliberate stop, compose down, or an operator command) and bring it back with docker compose up -d postgres. They should then confirm the app reconnects.
- suspected change: None
- evidence cited:
  - `docker-compose-ps.txt`: agent-relay-postgres-1 is 'Exited (0) 2 minutes ago', so it was stopped cleanly. The app container is 'Up About an hour (unhealthy)' on image agent-relay:20260926-100835-0a305bc. All observability containers are up.
  - `logs-warn-error.txt`: Earliest errors at 11:31:36-37 are 'FATAL: the database system is shutting down' and 'AdminShutdown terminating connection due to administrator command'. From 11:31:41 on, every error is "failed to resolve host 'postgres'". 'lease recovery pass failed' repeats every ~9s with the same error.
  - `app-ready.json`: /ready returns HTTP 503 {"status":"not_ready"}, consistent with the DB being unreachable.
  - `app-health.json`: /health returns 200 ok, so the app process is alive and responsive. It is not wedged.
  - `deploy-history-last5.jsonl`: Release 20260926-100835-0a305bc (git 0a305bc) was deployed at 2026-09-26T10:08:53Z, about 1h23m before the alert at 11:32. The previous version is 20260926-093326-64dddaf-dirty.
  - `metrics-5xx-ratio-by-version.json`: The 0a305bc version has a 5xx ratio of 0 for long stretches after deploy and a 5xx ratio of 1 from about 1790422384 onward (last two points, at the end of the window). It also has short earlier 5xx bursts at the start of the window and around 1790419534-1790419654. Those bursts and the NaN gaps could not be explained from the evidence I read.
  - `changes-versions.json`: Running version is 0a305bc and its previous version is 64dddaf (dirty). The database connection error is a DNS or container-level failure, not an application exception.
- risks:
  - Escalation adds human delay while claims stay down and work stays stuck.
  - If the app's connection pool or DNS caching does not recover after Postgres returns, an app restart may still be needed. That is not shown in the evidence.
  - Restarting postgres without checking why it was stopped may repeat the outage if the stop was deliberate or caused by something else. The postgres container's own logs and volume are not in the evidence packet.
  - The earlier 5xx bursts and NaN gaps for this version are unexplained in the evidence I read. A separate app issue is unlikely but cannot be fully ruled out.
- verification plan: Check the cause of the postgres shutdown (docker compose logs postgres, shell history, or a compose down/stop) and restart it if it was not deliberate. Confirm the container shows Up in docker compose ps. Then confirm /ready returns 200 and the 'failed to resolve host postgres' errors stop in Loki. Check that the 5xx ratio for /api/v1/tasks/claim drops to 0 and the RelayClaimCompleteErrorRatioHigh alert resolves. Watch relay_tasks_claims_total and the queue depth to confirm claims resume. If /ready stays 503 after Postgres is healthy, consider restarting the app container.

## What to do
1. Read `incident-response/incidents/INC-20260926-113352-api-v1-tasks-claim/evidence/` (start with `manifest.json`) and `policy-decision.json`.
2. Follow `incident-response/runbooks/claim-complete-5xx.md`.
3. After any manual fix: `incident-response/runbooks/verify-recovery.sh INC-20260926-113352-api-v1-tasks-claim <running version>`.
