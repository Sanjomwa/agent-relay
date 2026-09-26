#!/usr/bin/env bash
# Build and deploy the app service as a uniquely versioned, retained image.
#
#   scripts/release.sh
#
# Version format: YYYYMMDD-HHMMSS-<git short sha 7> (UTC), plus "-dirty" when the
# working tree has uncommitted changes. Appends one JSON line per successful
# release to deploy/history.jsonl (gitignored). Rollback never rebuilds:
#   APP_VERSION=<previous_version> docker compose up -d app
set -euo pipefail

cd "$(dirname "$0")/.."
command -v jq >/dev/null || { echo "release.sh: jq is required" >&2; exit 1; }

PORT="${RELAY_HOST_PORT:-8010}"
HISTORY="deploy/history.jsonl"
mkdir -p deploy

previous_version=""
if [ -s "$HISTORY" ]; then
  previous_version="$(tail -n 1 "$HISTORY" | jq -r '.version')"
fi

compute_version() {
  local sha stamp version
  sha="$(git rev-parse --short=7 HEAD)"
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  version="${stamp}-${sha}"
  if [ -n "$(git status --porcelain)" ]; then
    version="${version}-dirty"
  fi
  echo "$sha $version"
}

read -r GIT_SHA APP_VERSION < <(compute_version)
if [ "$APP_VERSION" = "$previous_version" ]; then
  sleep 1 # same-second re-release: keep versions distinct
  read -r GIT_SHA APP_VERSION < <(compute_version)
fi
export GIT_SHA APP_VERSION

echo "release: building agent-relay:${APP_VERSION} (previous: ${previous_version:-none})"
docker compose build app

echo "release: starting app"
docker compose up -d app

echo "release: waiting for /ready on :${PORT}"
deadline=$((SECONDS + 90))
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:${PORT}/ready" || true)" = "200" ] \
  && [ "$(curl -s --max-time 3 "http://localhost:${PORT}/version" | jq -r '.version' 2>/dev/null || true)" = "$APP_VERSION" ]; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "release: FAILED, /ready did not return 200 with version ${APP_VERSION} within 90s" >&2
    docker compose logs app --tail 20 >&2 || true
    echo "release: roll back with: APP_VERSION=${previous_version:-<previous>} docker compose up -d app" >&2
    exit 1
  fi
  sleep 2
done

image_id="$(docker image inspect "agent-relay:${APP_VERSION}" --format '{{.Id}}')"
jq -cn \
  --arg version "$APP_VERSION" \
  --arg git_sha "$GIT_SHA" \
  --arg image_id "$image_id" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg previous "$previous_version" \
  '{version:$version, git_sha:$git_sha, image_id:$image_id, timestamp:$timestamp,
    previous_version:(if $previous == "" then null else $previous end)}' >> "$HISTORY"

echo "release: deployed ${APP_VERSION}"
tail -n 1 "$HISTORY"
