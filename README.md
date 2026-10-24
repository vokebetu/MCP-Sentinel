# MCP Sentinel

Security search for the 50,019 servers in the Official MCP Registry.

**Team #2:** Sana Shaik, Shreem Dixit, Sahir Shaik, Dias Utebekov

## What it shows

- What each server declares: packages, repository, endpoints.
- Known vulnerabilities in those exact package versions.
- Which checks were done, and which were **not** done. "Not checked" never means "safe".

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

## Load the full database (50,019 servers)

Use this instead of step 6.

1. Get `mcp_sentinel.dump` and `mcp_sentinel.dump.sha256` from a team member.
2. Put both files in a folder named `artifacts` inside the project.
3. Restore. Add `--replace` at the end if the database already has data:
   ```bash
   ./scripts/restore_database.sh artifacts/mcp_sentinel.dump
   ```
4. Start the app again:
   ```bash
   docker compose up -d
   ```

## Rebuild the full database from research data (team only)

1. Copy these folders from a team member into `research/`: `cache/`, `registry_study/data/`, `registry_study/results/`. They are not in Git and cannot be downloaded again exactly.
2. Install Python packages:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements-dev.txt
   ```
3. Build the data bundle:
   ```bash
   .venv/bin/python -I scripts/build_bundle.py --out data/bundle
   ```
4. Load it:
   ```bash
   docker compose run --rm importer full
   ```

## Run the tests

1. Install (once):
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements-dev.txt
   .venv/bin/python -m playwright install chromium
   ```
2. Start a test database:
   ```bash
   docker run -d --name mcp-sentinel-testdb -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17.11-alpine
   ```
3. Run:
   ```bash
   TEST_DATABASE_ADMIN_URL="postgresql://sentinel:test@localhost:55432/postgres" .venv/bin/python -m pytest -q
   ```
4. Remove the test database:
   ```bash
   docker rm -f mcp-sentinel-testdb
   ```

The browser tests need the app running at <http://localhost:8501>. They are skipped otherwise.

## App pages

| Page | Shows |
|---|---|
| Dashboard | Totals, deployment types, package ecosystems, coverage |
| Server search | Search and filters |
| Server profile | One server: software, vulnerabilities, checks, tools |
| Compare | Two servers side by side |

## Folders

| Folder | Contents |
|---|---|
| `backend/` | FastAPI API |
| `frontend/` | Streamlit web app |
| `database/` | Tables and views (`schema/`), report queries (`queries/`) |
| `scripts/` | Import, check, backup, restore |
| `data/seed/` | Demo data (131 real servers) |
| `tests/` | Automated tests |
| `docs/` | Project report and screenshots |
| `research/` | Raw data for rebuilding (local only, not in Git) |

More: `DEPLOYMENT.md` (ports, settings, backup, all commands) and `docs/PROJECT_REPORT.md` (design and results).

## Known limits

- Data is from one registry snapshot: 2026-10-23.
- Vulnerabilities were checked only for 400 sample servers (181 of them had a package to check). The rest show "not assessed".
- Remote-only servers have no package to check. Endpoints are never contacted.
- Endpoint status comes from Agora (2026-10-22). It is not live.

## Data sources

Official MCP Registry, GitHub, npm, PyPI, deps.dev, OSV.dev, GitHub Advisory Database, CVE.org, FIRST EPSS, CISA KEV, Agora (openforallofus.com), PolicyLayer, ToolHive. This product uses data from the NVD API but is not endorsed or certified by the NVD.
