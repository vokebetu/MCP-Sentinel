#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ' || echo unknown)
docker compose run --rm --no-deps -T --user "$(id -u):$(id -g)" \
  -e APP_GIT_COMMIT="$commit" -e APP_GIT_DIRTY="$dirty" \
  -v "$PWD/docs/benchmark:/srv/benchmark" backend python -m app.benchmark "$@"
