#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ${COMPOSE_ARGS:-} up -d --wait db >/dev/null 2>&1
output="${1:-artifacts/mcp_sentinel.dump}"
ai_output="${output%.dump}_ai.dump"
mkdir -p "$(dirname "$output")"
dump() {
  out="$1"
  shift
  docker compose ${COMPOSE_ARGS:-} exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=zstd:19 --no-owner --no-privileges "$@"' sh "$@" > "$out.partial"
  mv "$out.partial" "$out"
  if command -v sha256sum >/dev/null; then sha256sum "$out"; else shasum -a 256 "$out"; fi > "$out.sha256"
  ls -lh "$out"
  cat "$out.sha256"
}
dump "$output" --exclude-table-data=ai_chunks
dump "$ai_output" --data-only --table=ai_chunks
