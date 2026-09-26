#!/usr/bin/env bash
# Verify recovery after an action (or after a manual fix).
#
#   incident-response/runbooks/verify-recovery.sh <INCIDENT_ID> <expected_version>
#
# Checks: /ready 200; /version == expected; a 60s low-rate traffic probe with 0 errors;
# per-route 5xx ratio back to 0 in Prometheus; the alert no longer firing (waits up to ~4
# minutes because of the rate windows). Writes incidents/<ID>/verification.json and exits
# 0 on pass, 1 on fail.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ID="${1:-}"; EXPECTED="${2:-}"
[[ "$ID" =~ ^INC-[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,40}$ ]] || { echo "invalid incident id" >&2; exit 2; }
[[ "$EXPECTED" =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{7}(-dirty)?$ ]] || { echo "invalid expected version" >&2; exit 2; }
PORT="${RELAY_HOST_PORT:-8010}"; APP="http://localhost:${PORT}"; PROM="http://localhost:9090"
OUTDIR="incident-response/incidents/$ID"; mkdir -p "$OUTDIR"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CHECKS="$(mktemp)"; trap 'rm -f "$CHECKS"' EXIT
add() { jq -cn --arg name "$1" --argjson passed "$2" --arg detail "$3" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{name:$name, passed:$passed, detail:$detail, at:$ts}' >> "$CHECKS"; echo "verify: $1 -> $([ "$2" = true ] && echo PASS || echo FAIL): $3"; }

# 1. /ready 200 (retry up to 60s)
code=000; for _ in $(seq 1 30); do code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$APP/ready" || echo 000)"; [ "$code" = 200 ] && break; sleep 2; done
[ "$code" = 200 ] && add ready true "GET /ready -> 200" || add ready false "GET /ready -> $code"

# 2. /version == expected
got="$(curl -s --max-time 5 "$APP/version" | jq -r '.version // empty' 2>/dev/null || true)"
[ "$got" = "$EXPECTED" ] && add version true "/version = $got" || add version false "/version = '${got:-unreachable}', expected $EXPECTED"

# 3. 60s low-rate traffic probe with 0 errors (only if the app is ready; otherwise it cannot pass)
if [ "$code" = 200 ]; then
  probe="$(uv run scripts/traffic.py --rate 2 --duration 60 --senders 1 --workers 1 --wait-seconds 2 --drain-seconds 20 2>&1 | grep -E '^\[final' | tail -n 1)"
  errors="$(echo "$probe" | sed -n 's/.*errors=\([0-9]*\).*/\1/p')"; completed="$(echo "$probe" | sed -n 's/.*completed=\([0-9]*\).*/\1/p')"
  if [ -n "$errors" ] && [ "$errors" = 0 ] && [ "${completed:-0}" -gt 0 ]; then add traffic_probe true "$probe"; else add traffic_probe false "${probe:-no result from traffic.py}"; fi
else
  add traffic_probe false "skipped: /ready was not 200"
fi

# 4. per-route 5xx ratio back to 0 (poll up to 150s: the 1m rate window must clear)
Q='sum by (http_route) (rate(http_server_request_duration_seconds_count{http_route=~"/api/v1/tasks/claim|/api/v1/tasks/\\{task_id\\}/complete", http_response_status_code=~"5.."}[1m]))'
worst="unknown"; ok=false
for _ in $(seq 1 15); do
  worst="$(curl -s --max-time 10 -G "$PROM/api/v1/query" --data-urlencode "query=$Q" | jq -r '[.data.result[]?.value[1]|tonumber]|max // 0' 2>/dev/null || echo unknown)"
  if [ "$worst" != unknown ] && awk "BEGIN{exit !($worst == 0)}"; then ok=true; break; fi
  sleep 10
done
$ok && add error_ratio_zero true "5xx rate on claim/complete routes = 0" || add error_ratio_zero false "5xx rate still $worst"

# 5. alert no longer firing or pending (poll up to 240s)
state="unknown"; ok=false
for _ in $(seq 1 24); do
  state="$(curl -s --max-time 10 "$PROM/api/v1/alerts" | jq -r '[.data.alerts[]?|select(.labels.alertname=="RelayClaimCompleteErrorRatioHigh")|.state]|first // "none"' 2>/dev/null || echo unknown)"
  if [ "$state" = none ]; then ok=true; break; fi
  sleep 10
done
$ok && add alert_resolved true "RelayClaimCompleteErrorRatioHigh is not firing or pending" || add alert_resolved false "alert state: $state"

PASSED="$(jq -s 'all(.[]; .passed)' "$CHECKS")"
jq -s --arg id "$ID" --arg exp "$EXPECTED" --arg started "$STARTED" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson passed "$PASSED" \
  '{incident_id:$id, expected_version:$exp, started_at:$started, finished_at:$finished, passed:$passed, checks:.}' "$CHECKS" > "$OUTDIR/verification.json"
echo "verify: overall $([ "$PASSED" = true ] && echo PASS || echo FAIL) -> $OUTDIR/verification.json"
[ "$PASSED" = true ]
