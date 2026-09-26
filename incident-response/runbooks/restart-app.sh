#!/usr/bin/env bash
# Restart the app container (same image, same version). No arguments, no build.
#
#   INCIDENT_ID=<INC-...> incident-response/runbooks/restart-app.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
die() { echo "restart-app: $*" >&2; exit 1; }
[ $# -eq 0 ] || die "takes no arguments"
INCIDENT_ID="${INCIDENT_ID:-manual}"
[[ "$INCIDENT_ID" =~ ^(manual|INC-[0-9]{8}-[0-9]{6}-[a-z0-9-]{1,40})$ ]] || die "invalid INCIDENT_ID"
PORT="${RELAY_HOST_PORT:-8010}"

echo "restart-app: restarting app [incident $INCIDENT_ID]"
docker compose restart app
deadline=$((SECONDS + 90))
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:${PORT}/ready" || true)" = "200" ]; do
  [ "$SECONDS" -lt "$deadline" ] || die "FAILED: /ready did not return 200 within 90s"
  sleep 2
done
echo "restart-app: done; /ready=200 version=$(curl -s --max-time 3 "http://localhost:${PORT}/version" | jq -r '.version')"
