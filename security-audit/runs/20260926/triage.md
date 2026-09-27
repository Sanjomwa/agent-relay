# Triage: security audit 2026-09-26

**For Sam to validate.** Every row needs a human disposition (`confirmed`, `false_positive`, `accepted_risk`, `fix_now` or `fix_later`) before anything is changed. The "Suggested" column is only a suggestion; the **Disposition** column is left empty on purpose. No fixes were made in this step.

Sources: Semgrep 1.178.0 (`semgrep-findings.json`, from `semgrep.json`), the model review (`model-review.json`, claude-sonnet-5, read-only), and known pre-existing items (`known-findings.json`, source=manual). Duplicates are merged into one row, with every source that reported it listed. **Verified** means I reproduced it against a scratch instance on 2026-09-27 (not the running stack).

## Merged findings

| id | source(s) | severity | file:line | description | suggested | reason | Disposition |
|---|---|---|---|---|---|---|---|
| K-001 / M-001 | manual, model | medium | main.py:222 | Open agent enrollment: no `RELAY_ENROLLMENT_SECRET` in compose/k8s, so anyone reaching :8010 (bound on 0.0.0.0) can mint an agent token | fix_now | Real and exploitable on the LAN; one env var from an untracked .env fixes it | |
| M-002 | model | medium | main.py:149 | Body-size limit only checks `Content-Length`; a chunked request bypasses it and is read in full before auth. **Verified:** 2 MB body → 413 with Content-Length, 400 (parsed) when chunked | fix_later | Real memory-exhaustion vector for anyone reaching :8010; needs an ASGI receive wrapper, not a one-liner | |
| K-010 | manual | medium | incident-response/policy.py:238 | During a non-deploy outage an L1 rollback passes all 6 preconditions; human approval is the only gate | fix_later | By design for L1, but a deploy-correlation precondition would make the policy catch a wrong proposal itself | |
| K-005 | manual | medium | database.py:228 | Postgres race: recovery can requeue a task that already has a newer live attempt, so the work is processed twice | fix_later | From code reading, not reproduced; correctness and integrity rather than confidentiality | |
| M-003 | model | low | main.py:223 | Non-ASCII `X-Enrollment-Secret` makes `hmac.compare_digest(str, str)` raise, giving an unauthenticated 500. **Verified:** non-ASCII → 500 (TypeError), wrong ASCII → 401 | fix_now | Trivial fix (compare bytes); becomes relevant as soon as K-001 is fixed | |
| K-011 / M-004 | manual, model | low | incident-response/collect-evidence.sh:183 | Evidence secret scan misses `KEY: value` secrets; **verified:** committed evidence `INC-20260926-183037-…/evidence/changed-files/compose.yaml:6` contains `POSTGRES_PASSWORD: <dev-default>` while the manifest says the scan passed | fix_now | The value is the public dev default (nothing new exposed), but the gap would leak a real secret to the model and into git | |
| K-002 / M-007 | manual, model | low | compose.yaml:6 (also :28, k8s/secret.yaml:8/:13, .github/workflows/ci.yml:34/:52) | Plaintext default DB credentials in tracked files | fix_later | Dev-only default and Postgres isn't published to the host; move to untracked config with the K-001 fix | |
| K-003 | manual | low | main.py:129 | `/docs`, `/redoc`, `/openapi.json` public. **Verified:** all 200 without auth | fix_later | Information disclosure only; one constructor argument per environment | |
| K-004 | manual | low | logging_config.py:43 | Postgres `DETAIL: Failing row contains (…)` can put task payloads into logs and span exception events | fix_later | No credentials can appear (tokens stored hashed), but user content can | |
| K-006 | manual | low | storage.py:215 | Postgres race: recovery vs heartbeat/terminal (lost updates) | fix_later | Narrow window; code reading only | |
| K-007 | manual | low | storage.py:114 | Postgres race: concurrent same Idempotency-Key → 500 instead of the existing task | fix_later | Wrong status code under a race; no data loss | |
| K-008 / M-006 | manual, model | low | incident-response/respond.py:268 | User-level Claude settings reach headless runs (the advisorModel leak is neutralised; other user settings/hooks would still load) | fix_now | One flag (`--setting-sources ""`) closes the whole class for the responder and the model review | |
| K-009 | manual | low | incident-response/runbooks/verify-recovery.sh:39 | verify-recovery passed while 746 tasks were stranded; it doesn't check backlog drain | fix_later | Verification gap, not an exploitable vulnerability | |
| M-005 | model | low | incident-response/collect-evidence.sh:124 | Attacker-chosen text (URL path, exception text) can reach the responder prompt via traces/logs | accepted_risk | The responder has only Read/Grep/Glob, output is schema-validated, and every action needs policy + human approval; keep it that way | |
| S-003 / M-008 | semgrep, model | medium (semgrep) / low (model) | Dockerfile:34 | Container runs as root; API is plain HTTP on all interfaces | fix_later | Defense in depth; no known exploit path in the app today | |
| S-002 / M-009 | semgrep, model | medium (semgrep) / low (model) | .github/workflows/ci.yml:26 | CI installs uv via `curl … \| sh`; CI Postgres published on all interfaces with the default password | fix_later | Manual-dispatch, local `act` workflow; supply-chain hygiene | |
| S-001 | semgrep | low | .github/workflows/ci.yml:15 | `actions/checkout@v4` pinned by mutable tag | fix_later | Pin to a commit SHA when CI is touched next | |
| S-004, S-006 | semgrep | info | k8s/app.yaml:14, k8s/postgres.yaml:33 | Pods lack `runAsNonRoot` | fix_later | Pairs with S-003; the kind deployment is a local lab | |
| S-005, S-007 | semgrep | low | k8s/app.yaml:16, k8s/postgres.yaml:35 | Writable root filesystem | accepted_risk | Local kind lab; postgres needs writable data dir anyway (would need emptyDir/volume layout) | |
| M-010 | model | low | storage.py:80 | No rate limit or quota; every authenticated request writes `last_seen_at` | fix_later | Abuse/DoS hardening; only matters once :8010 is reachable by untrusted clients | |
| S-008 | semgrep | low | worker.py:171 | "Logger credential disclosure" | false_positive | The line logs the agent id and the credentials *file path*, not the token (checked) | |

## What each tool caught

| Known / expected item | Semgrep | Model | Notes |
|---|---|---|---|
| Open enrollment (K-001) | missed | **found** (M-001) | |
| Plaintext DB creds (K-002) | **missed** (p/secrets flagged nothing) | **found** (M-007) | Semgrep's secrets rules target high-entropy/API-key shapes, not `POSTGRES_PASSWORD: <dev-default>` |
| Public /docs, /redoc, /openapi.json (K-003) | missed | missed | |
| Postgres DETAIL echo into logs/spans (K-004) | missed | missed | |
| 3 Postgres races (K-005, K-006, K-007) | missed | missed | |
| advisorModel settings leak (K-008) | missed | partly (M-006: settings/HOME inherited; didn't name advisorModel) | |
| verify-recovery ignores backlog drain (K-009) | missed | missed | |
| L1 rollback gate during non-deploy outage (K-010) | missed | missed | |
| Evidence secret-scan gap (K-011) | missed | **found** (M-004, with the committed example) | new: not previously known |
| Root container / CI supply chain / k8s hardening | **found** (S-001..S-007) | found in part (M-008, M-009, M-007) | |
| Chunked body-size bypass, non-ASCII enrollment 500 | missed | **found** (M-002, M-003) | both new; both verified |

Takeaway: Semgrep covered configuration hygiene (Dockerfile, CI, k8s) well and nothing in the app's logic; the model found the logic and automation issues (including 3 not previously known: M-002, M-003, M-004) but none of the concurrency, telemetry-leak or autonomy-policy issues from earlier steps. Neither tool replaces the manual list.
