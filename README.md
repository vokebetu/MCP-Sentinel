# MCP Sentinel

Security search for the 50,019 servers in the Official MCP Registry.

**Team #2:** Sana Shaik, Shreem Dixit, Sahir Shaik, Dias Utebekov

## What it shows

- What each server declares: packages, repository, endpoints.
- Known vulnerabilities in those exact package versions.
- Which checks were done, and which were **not** done. "Not checked" never means "safe".
- An AI assistant that answers questions from the stored data and shows its sources.

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
3. Open `.env` and replace `replace-with-a-local-password` with any password. For the AI assistant, also set `OPENAI_API_KEY`. Never commit `.env`.
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
7. Build the AI search index (needs `OPENAI_API_KEY`, about 10 seconds):
   ```bash
   docker compose exec backend python -m app.ai index
   ```
8. Open <http://localhost:8501>. All pages except **AI assistant** work without an OpenAI key.

## Stop and start again

| Command | What it does |
|---|---|
| `docker compose stop` | Stop. Data is kept. |
| `docker compose up -d` | Start again. |
| `docker compose down -v` | Stop and **delete all data**. |

## Load the full database (50,019 servers)

Use this instead of steps 6 and 7. Pick one.

**A. Restore the dump** (includes the AI index):

1. Restore. Add `--replace` at the end if the database already has data:
   ```bash
   ./scripts/restore_database.sh data/dump/mcp_sentinel.dump
   ```
2. Start the app again:
   ```bash
   docker compose up -d
   ```

The dump contains (84 MB file, 657 MB once restored):

| Area | What it holds |
|---|---|
| Servers | all 50,019 registry records: 48,056 active, 617 deprecated, 1,346 deleted |
| Software | 20,456 package declarations, 27,323 code repositories, 33,965 hosted URLs |
| Endpoint status | 31,485 servers, from Agora |
| Tools | 16,055 tool records |
| Vulnerabilities | 280 advisories, 777 CVE records, 204 findings on 22 servers |
| Coverage | 148,923 records of what was checked for each server and what was not |
| AI index | 48,878 entries: one per non-deleted server, one per finding, one note on how the data was collected |
| Structure | 24 tables, 4 views, the pgvector and pg_trgm extensions |

**B. Import the data bundle** (about 2 minutes):

1. Import and check:
   ```bash
   docker compose run --rm importer full
   ```
2. Build the AI index (uses your OpenAI key: about 10 minutes, 12.5 million embedding tokens):
   ```bash
   docker compose exec backend python -m app.ai index
   ```

## Rebuild the data bundle from research data

`data/research/` holds the saved source data. Rows from sources that do not allow redistribution are removed.

1. Install Python packages:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements-dev.txt
   ```
2. Build:
   ```bash
   .venv/bin/python -I scripts/build_bundle.py --out data/bundle
   ```
   The result is identical to the files already in `data/bundle/`.

## Run the tests

1. Install (once):
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements-dev.txt
   .venv/bin/python -m playwright install chromium
   ```
2. Start a test database:
   ```bash
   docker compose build db
   docker run -d --name mcp-sentinel-testdb -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 mcp-sentinel-db:pg17-vector
   ```
3. Run:
   ```bash
   TEST_DATABASE_ADMIN_URL="postgresql://sentinel:test@localhost:55432/postgres" .venv/bin/python -m pytest -q
   ```
4. Remove the test database:
   ```bash
   docker rm -f mcp-sentinel-testdb
   ```

- The browser tests need the app running at <http://localhost:8501> (or set `FRONTEND_URL`). They are skipped otherwise.
- AI tests use fake model answers. The live AI browser test runs only with `RUN_LIVE_AI_TESTS=1`. It needs an OpenAI key and the AI index, and makes 2 OpenAI requests.

## App pages

| Page | Shows |
|---|---|
| Dashboard | Totals, deployment types, package ecosystems, coverage |
| Server search | Search and filters |
| Server profile | One server: software, vulnerabilities, checks, tools |
| Compare | Two servers side by side |
| AI assistant | Questions and answers with sources and limits |

## Folders

| Folder | Contents |
|---|---|
| `backend/` | FastAPI API |
| `frontend/` | Streamlit web app |
| `database/` | Tables and views (`schema/`), report queries (`queries/`), database image (`Dockerfile`) |
| `scripts/` | Import, check, backup, restore |
| `data/seed/` | Demo data (131 real servers) |
| `data/bundle/` | Full data (50,019 servers) |
| `data/dump/` | Full database backup with AI index |
| `data/research/` | Saved source data used to build `data/bundle/` |
| `tests/` | Automated tests |
| `docs/` | Project report, AI evaluation, screenshots |

More: `DEPLOYMENT.md` (ports, settings, backup, all commands) and `docs/PROJECT_REPORT.md` (design and results).

## Known limits

- Data is from one registry snapshot: 2026-10-23.
- Vulnerabilities were checked only for 400 sample servers (181 of them had a package to check). The rest show "not assessed".
- Remote-only servers have no package to check. Endpoints are never contacted.
- Endpoint status comes from Agora (2026-10-22). It is not live.
- AI answers use only indexed data. Sources are checked to be real retrieved records; each sentence is not checked automatically.
- Each AI question and its retrieved public records are sent to OpenAI.

## Data sources

Official MCP Registry, GitHub, npm, PyPI, deps.dev, OSV.dev, GitHub Advisory Database, CVE.org, FIRST EPSS, CISA KEV, Agora (openforallofus.com), PolicyLayer, ToolHive. This product uses data from the NVD API but is not endorsed or certified by the NVD.
