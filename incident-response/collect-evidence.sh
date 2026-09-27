#!/usr/bin/env bash
# Collect a bounded, repeatable, READ-ONLY evidence packet for one incident.
#
#   incident-response/collect-evidence.sh <INCIDENT_ID> <ALERT_JSON_FILE>
#
# Writes incident-response/incidents/<ID>/evidence/. Every query below is a fixed
# template in this script; the only inputs are the validated incident id and a time
# window derived from the alert's activeAt. No database access, no `docker exec`,
# nothing that changes state (GETs, `docker compose ps`, read-only git, file reads).
# manifest.json lists every query/command with its timestamp and the sha256 of its
# output. Before finishing, the whole packet is scanned for secrets; on any hit the
# packet is moved to deploy/quarantine/ (gitignored, outside the tracked tree) and the script
# exits 3 (the responder must not be run on it).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() { echo "usage: $0 <INCIDENT_ID> <ALERT_JSON_FILE>" >&2; exit 2; }
[ $# -eq 2 ] || usage
ID="$1"
ALERT_FILE="$2"
[[ "$ID" =~ ^INC-[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,40}$ ]] || { echo "invalid incident id: $ID" >&2; exit 2; }
[ -f "$ALERT_FILE" ] || { echo "alert file not found" >&2; exit 2; }
command -v jq >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null || { echo "jq, curl and python3 are required" >&2; exit 2; }
REDACTOR="$ROOT/incident-response/redact_secrets.py"

# ---- fixed endpoints (localhost only) ------------------------------------------------
PROM="http://localhost:9090"
LOKI="http://localhost:3100"
TEMPO="http://localhost:3200"
APP="http://localhost:8010"

# ---- validated alert -> time window ---------------------------------------------------
jq -e '.labels.alertname and .activeAt and .state' "$ALERT_FILE" >/dev/null || { echo "alert JSON lacks labels.alertname/activeAt/state" >&2; exit 2; }
ACTIVE_AT="$(jq -r '.activeAt' "$ALERT_FILE")"
[[ "$ACTIVE_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$ ]] || { echo "invalid activeAt: $ACTIVE_AT" >&2; exit 2; }
T_ACTIVE="$(date -u -d "$ACTIVE_AT" +%s)"
END="$(date -u +%s)"
LOG_START=$((T_ACTIVE - 900))      # logs/traces: activeAt - 15m -> now
METRIC_START=$((T_ACTIVE - 3600))  # metrics: activeAt - 60m -> now (shows whether the current version was healthy before)
[ "$LOG_START" -lt "$END" ] || { echo "activeAt is in the future" >&2; exit 2; }

OUT="incident-response/incidents/$ID/evidence"
case "$OUT" in incident-response/incidents/INC-*/evidence) ;; *) echo "refusing unexpected output path" >&2; exit 2;; esac
rm -rf "$OUT"
mkdir -p "$OUT"
MANIFEST_TMP="$(mktemp)"
trap 'rm -f "$MANIFEST_TMP" "$OUT/.body" "$OUT/.logs-raw.json"' EXIT

record() { # <file> <kind> <what>
  jq -cn --arg file "$1" --arg kind "$2" --arg what "$3" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg sha "$(sha256sum "$OUT/$1" | cut -d' ' -f1)" --argjson bytes "$(stat -c%s "$OUT/$1")" \
    '{file:$file, kind:$kind, query:$what, timestamp:$ts, bytes:$bytes, sha256:$sha}' >> "$MANIFEST_TMP"
}

# Redact secrets from copied source BEFORE it is written (the scan below is the backstop):
# credentials in database URLs, and values of key-like settings (PASSWORD / SECRET / TOKEN /
# API_KEY / PRIVATE_KEY, `KEY: value` and `KEY=value`, placeholders kept) via redact_secrets.py.
redact_urls() { sed -E 's#(postgres(ql)?(\+[a-z0-9]+)?://)[^[:space:]/@:]+:[^[:space:]/@]+@#\1[REDACTED]@#g'; }
redact() { redact_urls | python3 "$REDACTOR" filter "$1"; }          # <path-hint> selects code vs config rules
redact_diff() { redact_urls | python3 "$REDACTOR" filter-diff; }

get() { # <file> <description> <curl args...>
  local file="$1" what="$2"; shift 2
  curl -sS --max-time 25 "$@" -o "$OUT/$file" 2>"$OUT/.err" || printf '{"error":"request failed: %s"}\n' "$(tr -d '"\n' < "$OUT/.err" | cut -c1-150)" > "$OUT/$file"
  rm -f "$OUT/.err"
  record "$file" http_get "$what"
}
prom_range() { # <file> <promql>
  get "$1" "GET $PROM/api/v1/query_range query=[$2] start=$METRIC_START end=$END step=30" \
    -G "$PROM/api/v1/query_range" --data-urlencode "query=$2" --data-urlencode "start=$METRIC_START" \
    --data-urlencode "end=$END" --data-urlencode "step=30"
}

# ---- 1. the alert and the app's own view of itself ------------------------------------
jq . "$ALERT_FILE" > "$OUT/alert.json"; record alert.json file_copy "copy of the alert JSON given to this script"
get app-version.json "GET $APP/version" "$APP/version"
code="$(curl -sS --max-time 10 -o "$OUT/.body" -w '%{http_code}' "$APP/ready" 2>/dev/null || echo 000)"
jq -n --arg code "$code" --rawfile body "$OUT/.body" '{http_status: ($code|tonumber), body: $body}' > "$OUT/app-ready.json" 2>/dev/null \
  || echo '{"http_status":0,"body":"unreachable"}' > "$OUT/app-ready.json"
record app-ready.json http_get "GET $APP/ready (http status + body)"
code="$(curl -sS --max-time 10 -o "$OUT/.body" -w '%{http_code}' "$APP/health" 2>/dev/null || echo 000)"
jq -n --arg code "$code" --rawfile body "$OUT/.body" '{http_status: ($code|tonumber), body: $body}' > "$OUT/app-health.json" 2>/dev/null \
  || echo '{"http_status":0,"body":"unreachable"}' > "$OUT/app-health.json"
record app-health.json http_get "GET $APP/health (http status + body)"
get prometheus-alerts-now.json "GET $PROM/api/v1/alerts" "$PROM/api/v1/alerts"

# ---- 2. what is running, and what was deployed -----------------------------------------
{ echo "### docker compose ps -a (app project)"; docker compose ps -a 2>&1 | cut -c1-260 \
  ; echo; echo "### docker compose -f observability/compose.yaml ps -a (observability project)"; docker compose -f observability/compose.yaml ps -a 2>&1 | cut -c1-260; } > "$OUT/docker-compose-ps.txt" || true
record docker-compose-ps.txt command "docker compose ps -a; docker compose -f observability/compose.yaml ps -a"
if [ -f deploy/history.jsonl ]; then tail -n 5 deploy/history.jsonl > "$OUT/deploy-history-last5.jsonl"; else echo '{"error":"deploy/history.jsonl not found"}' > "$OUT/deploy-history-last5.jsonl"; fi
record deploy-history-last5.jsonl file_read "tail -n 5 deploy/history.jsonl (release records have timestamp/version/git_sha/previous_version; rollbacks have action/from/to)"

# ---- 3. metrics (Prometheus query_range, window: activeAt-60m -> now) ---------------------
HTTPC='http_server_request_duration_seconds_count'
prom_range metrics-request-rate-by-route.json "sum by (http_route) (rate(${HTTPC}[1m]))"
prom_range metrics-5xx-ratio-by-route.json "sum by (http_route) (rate(${HTTPC}{http_response_status_code=~\"5..\"}[1m])) / sum by (http_route) (rate(${HTTPC}[1m]))"
prom_range metrics-p95-latency-by-route.json "histogram_quantile(0.95, sum by (le, http_route) (rate(http_server_request_duration_seconds_bucket[1m])))"
prom_range metrics-request-rate-by-version.json "sum by (service_version) (rate(${HTTPC}[1m]))"
prom_range metrics-5xx-ratio-by-version.json "sum by (service_version) (rate(${HTTPC}{http_response_status_code=~\"5..\"}[1m])) / sum by (service_version) (rate(${HTTPC}[1m]))"
prom_range metrics-tasks-created-by-outcome.json "sum by (outcome) (rate(relay_tasks_created_total[1m]))"
prom_range metrics-tasks-claims-by-outcome.json "sum by (outcome) (rate(relay_tasks_claims_total[1m]))"
prom_range metrics-tasks-terminal-by-action-outcome.json "sum by (action, outcome) (rate(relay_tasks_terminal_total[1m]))"
prom_range metrics-claim-duration-p95.json "histogram_quantile(0.95, sum by (le, outcome) (rate(relay_claim_duration_seconds_bucket[5m])))"
prom_range metrics-queue-depth.json "sum(relay_queue_depth)"
prom_range metrics-queue-oldest-age-seconds.json "max(relay_queue_oldest_age_seconds)"

# ---- 4. logs (Loki, WARNING and above, limit 200, window: activeAt-15m -> now) -------------
LOGQ='{service_name="agent-relay"} | detected_level=~"(?i)warn|warning|error|fatal|critical"'
curl -sS --max-time 25 -G "$LOKI/loki/api/v1/query_range" --data-urlencode "query=$LOGQ" --data-urlencode "limit=200" \
  --data-urlencode "direction=backward" --data-urlencode "start=${LOG_START}000000000" --data-urlencode "end=${END}000000000" \
  -o "$OUT/.logs-raw.json" 2>/dev/null || echo '{"error":"loki request failed"}' > "$OUT/.logs-raw.json"
# Keep only the useful fields, bounded (the raw response is megabytes of structured metadata).
jq -c 'if .data then [.data.result[]? | .stream as $s | .values[] | {time:(.[0]|tonumber/1000000000|floor|todate), level:$s.detected_level, logger:$s.scope_name,
        version:$s.service_version, trace_id:$s.trace_id, message:(.[1]|.[0:500]), exception_type:$s.exception_type,
        exception_message:(($s.exception_message // "")|.[0:500]), exception_stacktrace:(($s.exception_stacktrace // "")|.[0:1500])}]
      | sort_by(.time) | reverse | .[0:200] else . end' "$OUT/.logs-raw.json" > "$OUT/logs-warn-error.json" || echo '{"error":"could not parse loki response"}' > "$OUT/logs-warn-error.json"
rm -f "$OUT/.logs-raw.json"
record logs-warn-error.json http_get "GET $LOKI/loki/api/v1/query_range query=[$LOGQ] limit=200 direction=backward start=$LOG_START end=$END; compacted with jq to key fields (message<=500, stacktrace<=1500 chars)"
jq -r 'if type=="array" then .[] | "\(.time) \(.level) \(.logger) v=\(.version) trace=\(.trace_id // "-") \(.message) \(if .exception_type then "exception=" + .exception_type + ": " + .exception_message else "" end)" else tostring end' \
  "$OUT/logs-warn-error.json" > "$OUT/logs-warn-error.txt" 2>/dev/null || echo "(could not summarise logs)" > "$OUT/logs-warn-error.txt"
record logs-warn-error.txt derived "one-line-per-entry summary of logs-warn-error.json (jq)"

# ---- 5. traces (Tempo: up to 20 error traces, full detail for 3) ---------------------------
TRACEQL='{ resource.service.name = "agent-relay" && (status = error || span.http.response.status_code >= 500) }'
get tempo-error-traces-search.json "GET $TEMPO/api/search q=[$TRACEQL] limit=20 start=$LOG_START end=$END" \
  -G "$TEMPO/api/search" --data-urlencode "q=$TRACEQL" --data-urlencode "limit=20" \
  --data-urlencode "start=$LOG_START" --data-urlencode "end=$END"
n=0
for tid in $(jq -r '.traces[]?.traceID' "$OUT/tempo-error-traces-search.json" 2>/dev/null | head -n 3); do
  [[ "$tid" =~ ^[0-9a-f]{1,32}$ ]] || continue
  n=$((n + 1))
  get "tempo-trace-$n.json" "GET $TEMPO/api/traces/$tid (full detail)" "$TEMPO/api/traces/$tid"
done

# ---- 6. recent changes -----------------------------------------------------------------
git log --oneline -10 > "$OUT/git-log.txt" 2>&1 || true
record git-log.txt command "git log --oneline -10"

RUNNING="$(jq -r '.version // empty' "$OUT/app-version.json" 2>/dev/null || true)"
if [ -z "$RUNNING" ] && [ -f deploy/history.jsonl ]; then RUNNING="$(jq -rs '[.[]|select(.version)]|last|.version // empty' deploy/history.jsonl)"; fi
CUR_SHA=""; PREV_VER=""; PREV_SHA=""
if [ -n "$RUNNING" ] && [ -f deploy/history.jsonl ]; then
  CUR_SHA="$(jq -rs --arg v "$RUNNING" '[.[]|select(.version==$v)]|last|.git_sha // empty' deploy/history.jsonl)"
  PREV_VER="$(jq -rs --arg v "$RUNNING" '[.[]|select(.version==$v)]|last|.previous_version // empty' deploy/history.jsonl)"
  [ -n "$PREV_VER" ] && PREV_SHA="$(jq -rs --arg v "$PREV_VER" '[.[]|select(.version==$v)]|last|.git_sha // empty' deploy/history.jsonl)"
fi
jq -n --arg running "$RUNNING" --arg cur_sha "$CUR_SHA" --arg prev "$PREV_VER" --arg prev_sha "$PREV_SHA" \
  '{running_version:$running, running_git_sha:$cur_sha, previous_version:$prev, previous_git_sha:$prev_sha, source:"/version and deploy/history.jsonl"}' > "$OUT/changes-versions.json"
record changes-versions.json derived "running version, previous_version and git shas from /version + deploy/history.jsonl"

sha_ok() { [[ "$1" =~ ^[0-9a-f]{7,40}$ ]] && git cat-file -e "$1^{commit}" 2>/dev/null; }
if sha_ok "$CUR_SHA" && sha_ok "$PREV_SHA" && [ "$CUR_SHA" != "$PREV_SHA" ]; then
  git diff --stat "$PREV_SHA..$CUR_SHA" 2>&1 | redact_urls | head -n 60 > "$OUT/changes-diff-stat.txt" || true
  record changes-diff-stat.txt command "git diff --stat $PREV_SHA..$CUR_SHA (head -60)"
  git diff "$PREV_SHA..$CUR_SHA" -- . ':(exclude)uv.lock' 2>&1 | redact_diff | head -n 400 > "$OUT/changes-diff.patch" || true
  record changes-diff.patch command "git diff $PREV_SHA..$CUR_SHA -- . ':(exclude)uv.lock' (secret values redacted; head -400 lines)"
  mkdir -p "$OUT/changed-files"
  total=0; files=0
  # Python sources first, then other text sources; never lockfiles or tests; max 5 files / 1500 lines.
  for path in $( { git diff --name-only "$PREV_SHA..$CUR_SHA" | grep -E '\.py$' | grep -v -E '(^|/)test_'; \
                   git diff --name-only "$PREV_SHA..$CUR_SHA" | grep -v -E '\.py$|\.lock$|\.json$|(^|/)test_' ; } | grep -E '^[A-Za-z0-9._/-]+$' ); do
    [ "$files" -lt 5 ] || break
    git cat-file -e "$CUR_SHA:$path" 2>/dev/null || continue
    lines="$(git show "$CUR_SHA:$path" | wc -l)"
    [ $((total + lines)) -le 1500 ] || continue
    safe="$(echo "$path" | tr '/' '_')"
    git show "$CUR_SHA:$path" | redact "$path" > "$OUT/changed-files/$safe"
    record "changed-files/$safe" command "git show $CUR_SHA:$path (redacted; file contents at the running version)"
    total=$((total + lines)); files=$((files + 1))
  done
else
  echo "no diff available: running=$RUNNING previous=$PREV_VER current_sha=${CUR_SHA:-none} previous_sha=${PREV_SHA:-none} (missing, unknown, or the same commit)" > "$OUT/changes-diff.patch"
  record changes-diff.patch derived "diff unavailable (see content)"
fi

# ---- 7. secret scan over the whole packet ----------------------------------------------------
scan_fail=0
report_hit() { echo "SECRET SCAN: $1 matched in: $2" >&2; scan_fail=1; }
scan_regex() { # <label> <ERE>
  local hits; hits="$(grep -r -l -E -e "$2" "$OUT" 2>/dev/null || true)"
  [ -z "$hits" ] || report_hit "$1" "$(echo "$hits" | tr '\n' ' ')"
}
scan_regex "agent bearer token pattern (agt_...)" 'agt_[A-Za-z0-9_-]{16,}'
scan_regex "claim token pattern (clm_...)" 'clm_[A-Za-z0-9_-]{16,}'
scan_regex "bearer credential" '[Bb]earer[[:space:]]+[A-Za-z0-9_.~+/=-]{20,}'
scan_regex "database URL with credentials" 'postgres(ql)?(\+[a-z0-9]+)?://[^[:space:]/@:]+:[^[:space:]/@]+@'
# Backstop for key-like secret values that escaped redaction (same rules as redact_secrets.py).
kv_hits="$(python3 "$REDACTOR" scan "$OUT" 2>/dev/null | head -n 5 | tr '\n' ' ' || true)"
[ -z "$kv_hits" ] || report_hit "key-like secret value (PASSWORD/SECRET/TOKEN/API_KEY/PRIVATE_KEY)" "$kv_hits"
# The actual enrollment secret from the untracked root .env, whatever shape it appears in.
if [ -f .env ]; then
  ENROLL="$(sed -n 's/^[[:space:]]*RELAY_ENROLLMENT_SECRET[[:space:]]*=[[:space:]]*//p' .env | head -n 1 | tr -d "\"'")"
  if [ -n "$ENROLL" ]; then
    hits="$(grep -r -l -F -e "$ENROLL" "$OUT" 2>/dev/null || true)"
    [ -z "$hits" ] || report_hit "enrollment secret value" "$(echo "$hits" | tr '\n' ' ')"
  fi
fi
if [ -f observability/.env ]; then
  GRAFANA_PW="$(grep -E '^GRAFANA_ADMIN_PASSWORD=' observability/.env | head -n 1 | cut -d= -f2-)"
  if [ -n "$GRAFANA_PW" ]; then
    hits="$(grep -r -l -F -e "$GRAFANA_PW" "$OUT" 2>/dev/null || true)"
    [ -z "$hits" ] || report_hit "Grafana admin password" "$(echo "$hits" | tr '\n' ' ')"
  fi
fi
if [ "$scan_fail" -ne 0 ]; then
  # Quarantine OUTSIDE the tracked tree: deploy/ is gitignored, so a packet that contains a
  # credential can never be staged by a later `git add incident-response`.
  QDIR="deploy/quarantine/$ID-$(date -u +%s)"
  mkdir -p deploy/quarantine
  mv "$OUT" "$QDIR"
  # Don't leave an empty incidents/<ID>/ behind. rmdir only succeeds on an empty directory, so
  # an incident folder that already holds a record (respond.py's alert.json, timeline) is kept.
  rmdir "incident-response/incidents/$ID" 2>/dev/null || true
  echo "collect-evidence: SECRET SCAN FAILED; packet quarantined at $QDIR (gitignored); do not hand it to the responder" >&2
  exit 3
fi

# ---- 8. manifest -----------------------------------------------------------------------------------
jq -s --arg id "$ID" --arg active "$ACTIVE_AT" --argjson log_start "$LOG_START" --argjson metric_start "$METRIC_START" --argjson end "$END" \
   --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{incident_id:$id, generated_at:$generated, alert_active_at:$active,
    windows:{logs_and_traces:{from:($log_start|todate), to:($end|todate)}, metrics:{from:($metric_start|todate), to:($end|todate)}},
    read_only:true, secret_scan:"passed (agt_/clm_ tokens, bearer credentials, database URLs with credentials, key-like secret values, Grafana admin password, enrollment secret)",
    entries:.}' "$MANIFEST_TMP" > "$OUT/manifest.json"
echo "collect-evidence: $(jq '.entries|length' "$OUT/manifest.json") entries written to $OUT (secret scan passed)"
