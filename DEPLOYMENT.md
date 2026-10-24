# Deployment

## You need

- Docker Desktop (Windows, macOS) or Docker Engine with Compose v2 (Linux).
- Git.
- Windows only: run the `.sh` scripts in Git Bash or WSL.

## Start the app

1. Download the project:
   ```bash
   git clone https://github.com/vokebetu/MCP-Sentinel.git
   cd MCP-Sentinel
   ```
2. Create the settings file:
   ```bash
   cp .env.example .env
   ```
3. Open `.env` and replace `replace-with-a-local-password` with any password.
4. Start:
   ```bash
   docker compose up --build -d
   ```
5. Check. All three services must say `healthy` (about 1 minute):
   ```bash
   docker compose ps
   ```
6. The database starts empty. Load demo data (131 servers):
   ```bash
   docker compose run --rm importer seed
   ```
7. Open <http://localhost:8501>.

## Stop and start again

| Command | What it does |
|---|---|
| `docker compose stop` | Stop. Data is kept. |
| `docker compose up -d` | Start again. |
| `docker compose down -v` | Stop and **delete all data**. |

## 1. Architecture

```mermaid
flowchart LR
    user([Browser]) -->|:8501 only public port| fe[frontend<br/>Streamlit]
    fe -->|backend:8000 internal| be[backend<br/>FastAPI]
    be -->|db:5432 internal, read-only| db[(db<br/>PostgreSQL 17)]
    db --- vol[(volume<br/>postgres_data)]
    imp[importer<br/>run on demand] -->|db:5432| db
    seed[[data/seed]] --> imp
    bundle[[data/bundle]] --> imp
    dump[[artifacts/mcp_sentinel.dump]] -->|restore_database.sh| db
```

- The browser talks only to the frontend.
- Only the backend reads the database.
- The importer runs only when you start it.

## 2. Services and ports

| Service | Image | Port | Public? | Job |
|---|---|---|---|---|
| `frontend` | python:3.12-slim + Streamlit 1.66 | 8501 | yes | web app |
| `backend` | python:3.12-slim + FastAPI 0.162 | 8000 | no | API |
| `db` | postgres:17.11-alpine | 5432 | no | database |
| `importer` | python:3.12-slim | none | no | load and check data |

Health checks:

| Service | Check | Starts after |
|---|---|---|
| `db` | `pg_isready -h 127.0.0.1` | |
| `backend` | `GET /health` | `db` healthy |
| `frontend` | `GET /_stcore/health` | `backend` healthy |

## 3. Data and storage

| What | Where | Kept after `docker compose down`? |
|---|---|---|
| Database (about 280 MB when full) | Docker volume `mcp-sentinel_postgres_data` | yes (deleted only by `down -v`) |
| Table definitions | `database/schema/*.sql` (run once, on an empty volume) | file |
| Demo data | `data/seed/` | file, in Git |
| Full data bundle | `data/bundle/` | file, not in Git |
| Database backup | `artifacts/mcp_sentinel.dump` + `.sha256` | file, not in Git |

## 4. Configuration (`.env`)

| Variable | Used by | Purpose |
|---|---|---|
| `POSTGRES_DB` | db, backend, importer | database name |
| `POSTGRES_USER` | db, backend, importer | database user |
| `POSTGRES_PASSWORD` | db, backend, importer | password (required) |
| `FRONTEND_PORT` | compose | public port, default 8501 |
| `DB_POOL_SIZE` | backend | optional, default 5 |

## 5. Commands

A new install starts with an **empty** database. Load demo data or restore the dump (below).

| Task | Command |
|---|---|
| Build and start | `docker compose up --build -d` |
| Check status | `docker compose ps` |
| Check the API | `docker compose exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read().decode())"` |
| Open the app | <http://localhost:8501> |
| Load demo data | `docker compose run --rm importer seed` |
| Load full data | `docker compose run --rm importer full` (needs `data/bundle/`) |
| Check the data | `docker compose run --rm importer validate` (needs `data/bundle/`) |
| Run report queries | `./scripts/run_report_queries.sh` |
| Open SQL shell | `docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'` |
| Stop, keep data | `docker compose stop` or `docker compose down` |
| Stop, delete data | `docker compose down -v` |
| Back up | `./scripts/export_database.sh` |
| Restore into empty database | `./scripts/restore_database.sh artifacts/mcp_sentinel.dump` |
| Restore over existing data | `./scripts/restore_database.sh artifacts/mcp_sentinel.dump --replace` |

`restore_database.sh` does these steps:

1. Checks the `.sha256`.
2. Refuses to overwrite data unless `--replace` is given.
3. Stops backend and frontend.
4. Recreates the database.
5. Runs `pg_restore`.

After it finishes, run `docker compose up -d`.

**Restore without Docker** (any PostgreSQL 17):

```bash
createdb mcp_sentinel
pg_restore --no-owner --no-privileges -d mcp_sentinel mcp_sentinel.dump
```

**Test a restore on a separate copy** (port 8502):

```bash
COMPOSE_ARGS="-p mcp-sentinel-restoretest" ./scripts/restore_database.sh artifacts/mcp_sentinel.dump
docker compose -p mcp-sentinel-restoretest run --rm importer validate
FRONTEND_PORT=8502 docker compose -p mcp-sentinel-restoretest up -d --wait
docker compose -p mcp-sentinel-restoretest down -v
```

## 6. Known issues

- Vulnerabilities were checked only for 400 sample servers. 48,269 of 48,673 non-deleted servers show "not assessed".
- Endpoint status is from 2026-10-22, not live.
- Full rebuild needs research files that are not in Git (`research/cache/`, `research/registry_study/data/`, `research/registry_study/results/`).
- The importer loads the whole bundle into memory (about 115 MB).
