#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ${COMPOSE_ARGS:-} up -d --wait db >/dev/null 2>&1
output="${1:-artifacts/mcp_sentinel.dump}"
mkdir -p "$(dirname "$output")"
docker compose ${COMPOSE_ARGS:-} exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=zstd:19 --no-owner --no-privileges' > "$output.partial"
mv "$output.partial" "$output"
if command -v sha256sum >/dev/null; then sha256sum "$output"; else shasum -a 256 "$output"; fi > "$output.sha256"
docker compose ${COMPOSE_ARGS:-} exec -T db sh -c 'pg_restore --list' < "$output" | grep -c "TABLE DATA" | xargs -I{} echo "table data entries in dump: {}"
ls -lh "$output"
cat "$output.sha256"
