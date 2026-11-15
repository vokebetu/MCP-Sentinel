#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dump="${1:?usage: scripts/restore_database.sh path/to/mcp_sentinel.dump [--replace]}"
replace="${2:-}"
ai_dump="${dump%.dump}_ai.dump"
compose=(docker compose ${COMPOSE_ARGS:-})
[ -f "$dump" ] || { echo "dump not found: $dump" >&2; exit 1; }
verify() {
  [ -f "$1.sha256" ] || return 0
  expected="$(cut -d' ' -f1 "$1.sha256")"
  actual="$( (command -v sha256sum >/dev/null && sha256sum "$1" || shasum -a 256 "$1") | cut -d' ' -f1)"
  [ "$expected" = "$actual" ] || { echo "checksum mismatch for $1" >&2; exit 1; }
  echo "checksum ok: $1"
}
verify "$dump"
[ -f "$ai_dump" ] && verify "$ai_dump"
"${compose[@]}" up -d --wait db
servers="$("${compose[@]}" exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT CASE WHEN to_regclass('"'"'public.servers'"'"') IS NULL THEN 0 ELSE (SELECT count(*) FROM servers) END"')"
if [ "$servers" != "0" ] && [ "$replace" != "--replace" ]; then
  echo "the target database already holds $servers servers; rerun with --replace to overwrite it" >&2
  exit 1
fi
"${compose[@]}" stop backend frontend >/dev/null 2>&1 || true
"${compose[@]}" exec -T db sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
"${compose[@]}" exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges --exit-on-error' < "$dump"
if [ -f "$ai_dump" ]; then
  "${compose[@]}" exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges --exit-on-error' < "$ai_dump"
  echo "AI index restored"
else
  echo "no AI index file next to the dump; build it with: docker compose exec backend python -m app.ai index"
fi
"${compose[@]}" exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT registry_status, count(*) FROM servers GROUP BY 1 ORDER BY 1"'
echo "restore complete; start the application with: docker compose up -d"
