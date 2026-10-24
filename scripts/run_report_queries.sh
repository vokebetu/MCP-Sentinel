#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ${COMPOSE_ARGS:-} up -d --wait db >/dev/null 2>&1
output="${1:-artifacts/report_query_results.txt}"
mkdir -p "$(dirname "$output")"
{
  echo "MCP Sentinel report queries, executed $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker compose ${COMPOSE_ARGS:-} exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 --echo-queries --pset=pager=off -c "\timing on" -f -' \
    < database/queries/report_queries.sql
} > "$output"
echo "wrote $output"
