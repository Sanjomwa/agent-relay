# Agent Relay: protocol, worker and storage

This page covers running the relay directly on your machine, the deterministic worker, and how storage and delivery behave. The full HTTP protocol, credential rules and task lifecycle are in [SPEC.md](../SPEC.md). The Docker, observability and incident-response setup is in the [README](../README.md).

## Run it without Docker

```bash
uv sync
uv run uvicorn main:app --reload
```

This serves the API on <http://127.0.0.1:8000/> with a SQLite database at `./agent-relay.db`. Set `RELAY_DATABASE_URL` to use another SQLite file or a PostgreSQL URL (`postgresql+psycopg://user:password@host:5432/db`).

In this mode:

- telemetry is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set;
- registration is open unless `RELAY_ENROLLMENT_SECRET` is exported in the shell (uvicorn does not read `.env`).

`GET /health` is a liveness check. `GET /ready` verifies database connectivity and schema by querying the real tables, so a wiped volume reports not-ready. `GET /version` returns the service name, version, git sha and environment. `/` serves a token-based local dashboard.

Register two identities:

```bash
alice=$(curl -sS -X POST http://127.0.0.1:8000/api/v1/agents \
  -H 'content-type: application/json' -d '{"name":"alice"}')
bob=$(curl -sS -X POST http://127.0.0.1:8000/api/v1/agents \
  -H 'content-type: application/json' -d '{"name":"uppercase"}')
```

Each response contains the agent's secret `token` once. Keep it out of source control. Every later call uses `Authorization: Bearer <token>`; registration is the only unauthenticated endpoint. When `RELAY_ENROLLMENT_SECRET` is set (the Compose stack requires it), registration also needs the header `X-Enrollment-Secret: <secret>`.

## Run the deterministic worker

The included worker returns `input.upper()`. It can register itself and save its credentials in a mode-0600 JSON file:

```bash
uv run python main.py worker \
  --base-url http://127.0.0.1:8000 \
  --name uppercase \
  --credentials ./uppercase-credentials.json \
  --worker-id laptop-1
```

Against the Compose stack, use `--base-url http://127.0.0.1:8010` and pass the secret with `--enrollment-secret` or `RELAY_ENROLLMENT_SECRET`. `*-credentials.json` is gitignored.

To demonstrate failure and redelivery, slow the worker down and stop the process during a task:

```bash
uv run python main.py worker --credentials ./uppercase-credentials.json \
  --slow-seconds 75 --worker-id slow-laptop
```

The worker heartbeats during long work. Killing it leaves the claim leased; after the lease expires (60 s by default), another worker can claim the task with a new claim token and an incremented attempt number.

An existing credential can be passed explicitly instead (the token is not written to disk):

```bash
uv run python main.py worker --agent-id agent_123 --token agt_… --worker-id laptop-2
```

Other worker flags: `--wait-seconds` (claim long-poll, default 30) and `--stop-after N` (exit after N completions).

## Storage and delivery behavior

| File | Responsibility |
|---|---|
| `database.py` | SQLAlchemy models, settings from the environment, SQLite WAL setup, the claim transaction helper |
| `storage.py` | task, claim, heartbeat, terminal and recovery operations |
| `main.py`, `schemas.py` | routes and request/response models |
| `worker.py` | the deterministic worker |

Claims are exclusive on both backends:

- **PostgreSQL:** `claim_one` selects the next task with `SELECT … FOR UPDATE SKIP LOCKED` (commit `64dddaf`), so concurrent claimers skip rows another transaction holds.
- **SQLite:** there is no `SKIP LOCKED`, so a `BEGIN IMMEDIATE` writer reservation serializes claims across processes.

Delivery is at-least-once. A claim is leased for `RELAY_LEASE_SECONDS` (default 60); heartbeats extend an active lease. A background recovery loop (every `RELAY_RECOVERY_INTERVAL_SECONDS`, default 5) requeues tasks whose lease expired. A queued task that has already used `RELAY_MAX_ATTEMPTS` attempts (default 5) is marked `failed` with `attempts_exhausted` when it next comes up for a claim. A completion or failure needs the recipient's bearer token and the claim token. Repeating the exact terminal request with the same claim token is idempotent; a stale token or a different result gets `409`. Request bodies are limited to `RELAY_MAX_BODY_BYTES` (default 256 KiB, checked against `Content-Length`).

Known gaps, from the [security audit triage](../security-audit/runs/20260926/triage.md), all `fix_later`:

- K-005, K-006, K-007: Postgres races between recovery and a newer attempt, heartbeats or terminal calls, and concurrent requests with the same `Idempotency-Key`. Found by code reading, not reproduced.
- M-002: a chunked request bypasses the body-size limit.

## Tests

```bash
uv run pytest -q
```

This runs every suite listed in `pyproject.toml` (`testpaths`); `security-audit/` and the incident folders are never collected. The app tests cover the protocol, sender and recipient access boundaries, hashed claim tokens, idempotent terminal retries, concurrent claims, lease expiry before and after recovery, pagination and error shape, dashboard serving, and the enrollment check. `test_observability.py` checks `/version`, which routes are traced, and that no secret reaches spans, logs or metrics.

The app tests use a scratch database at `/tmp/agent-relay-test.db` unless `RELAY_DATABASE_URL` is set. The fixture drops and recreates every table in whatever database that URL points at, so point it only at a throwaway database. Each test clears `RELAY_ENROLLMENT_SECRET` and `ENROLLMENT_SECRET`, and the enrollment tests set their own value, so a secret exported in your shell does not affect the results.

To run the app tests against PostgreSQL, start a throwaway container first:

```bash
docker run -d --name relay-pgtest -e POSTGRES_USER=relay_test -e POSTGRES_PASSWORD=relay_test \
  -e POSTGRES_DB=relay_test -p 127.0.0.1:5434:5432 postgres:16-alpine
until docker exec relay-pgtest pg_isready -U relay_test -d relay_test >/dev/null 2>&1; do sleep 1; done
RELAY_DATABASE_URL=postgresql+psycopg://relay_test:relay_test@127.0.0.1:5434/relay_test \
  uv run pytest -q test_agent_relay.py test_observability.py
docker rm -f -v relay-pgtest
```
