#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dump="${1:?usage: scripts/restore_database.sh path/to/mcp_sentinel.dump [--replace]}"
replace="${2:-}"
compose=(docker compose ${COMPOSE_ARGS:-})
[ -f "$dump" ] || { echo "dump not found: $dump" >&2; exit 1; }
if [ -f "$dump.sha256" ]; then
  expected="$(cut -d' ' -f1 "$dump.sha256")"
  actual="$( (command -v sha256sum >/dev/null && sha256sum "$dump" || shasum -a 256 "$dump") | cut -d' ' -f1)"
  [ "$expected" = "$actual" ] || { echo "checksum mismatch for $dump" >&2; exit 1; }
  echo "checksum ok"
fi
"${compose[@]}" up -d --wait db
servers="$("${compose[@]}" exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT CASE WHEN to_regclass('"'"'public.servers'"'"') IS NULL THEN 0 ELSE (SELECT count(*) FROM servers) END"')"
if [ "$servers" != "0" ] && [ "$replace" != "--replace" ]; then
  echo "the target database already holds $servers servers; rerun with --replace to overwrite it" >&2
  exit 1
fi
"${compose[@]}" stop backend frontend >/dev/null 2>&1 || true
"${compose[@]}" exec -T db sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
"${compose[@]}" exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges --exit-on-error' < "$dump"
"${compose[@]}" exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT registry_status, count(*) FROM servers GROUP BY 1 ORDER BY 1"'
echo "restore complete; start the application with: docker compose up -d"
