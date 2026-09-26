#!/usr/bin/env bash
# Roll the app back to an already-built, retained image. NEVER builds.
#
#   INCIDENT_ID=<INC-...> incident-response/runbooks/rollback.sh <version>
#
# Validates the version format, that it is a release recorded in deploy/history.jsonl,
# and that agent-relay:<version> exists locally; then `APP_VERSION=<v> docker compose up
# -d --no-build app`, waits for /version == v and /ready == 200, and appends
# {action, from, to, timestamp, incident_id} to deploy/history.jsonl.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
die() { echo "rollback: $*" >&2; exit 1; }

V="${1:-}"
[[ "$V" =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{7}(-dirty)?$ ]] || die "invalid version format: '${V:0:60}'"
INCIDENT_ID="${INCIDENT_ID:-manual}"
[[ "$INCIDENT_ID" =~ ^(manual|INC-[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,40})$ ]] || die "invalid INCIDENT_ID"
PORT="${RELAY_HOST_PORT:-8010}"
HISTORY="deploy/history.jsonl"
[ -s "$HISTORY" ] || die "$HISTORY missing or empty"

jq -e --arg v "$V" 'select(.version == $v)' "$HISTORY" >/dev/null || die "version $V is not a release in $HISTORY"
docker image inspect "agent-relay:$V" >/dev/null 2>&1 || die "image agent-relay:$V does not exist locally (a rollback never builds)"
FROM="$(curl -s --max-time 5 "http://localhost:${PORT}/version" | jq -r '.version // empty' || true)"
[ "$FROM" != "$V" ] || die "version $V is already running"
echo "rollback: ${FROM:-unknown} -> $V (no build) [incident $INCIDENT_ID]"

APP_VERSION="$V" docker compose up -d --no-build app

deadline=$((SECONDS + 90))
until [ "$(curl -s --max-time 3 "http://localhost:${PORT}/version" | jq -r '.version // empty' 2>/dev/null || true)" = "$V" ] \
  && [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:${PORT}/ready" || true)" = "200" ]; do
  [ "$SECONDS" -lt "$deadline" ] || die "FAILED: /version did not become $V with /ready=200 within 90s (history not written)"
  sleep 2
done

jq -cn --arg from "${FROM:-unknown}" --arg to "$V" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg id "$INCIDENT_ID" \
  '{action:"rollback", from:$from, to:$to, timestamp:$ts, incident_id:$id}' >> "$HISTORY"
echo "rollback: done; /version=$V /ready=200; history appended"
