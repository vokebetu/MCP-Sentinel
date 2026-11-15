# MCP Sentinel

Security search for the 50,019 servers in the Official MCP Registry.

**Team #2:** Sana Shaik, Shreem Dixit, Sahir Shaik, Dias Utebekov

## What it shows

- What each server declares: packages, repository, endpoints.
- Known vulnerabilities in those exact package versions.
- Which checks were done, and which were **not** done. "Not checked" never means "safe".
- An AI assistant that answers questions from the stored data and shows its sources.
- A review checklist per server: the evidence a bank's third-party risk review asks for, with an SBOM download.
- Spark analytics: Bronze/Silver/Gold Parquet files, SQL reports and K-Means clustering.

## You need

- Docker Desktop (Windows, macOS) or Docker Engine with Compose v2 (Linux).
- Git.
- Windows only: run the `.sh` scripts in Git Bash or WSL.

## Quick start: full database (50,019 servers)

1. Download the project and create the settings file:
   ```bash
   git clone https://github.com/vokebetu/MCP-Sentinel.git
   cd MCP-Sentinel
   cp .env.example .env
   ```
2. Open `.env` and replace `replace-with-a-local-password` with any password. For the AI assistant, also paste an OpenAI key after `OPENAI_API_KEY=`.
3. Build, load the full database (data and AI index, about 3 minutes), start:
   ```bash
   docker compose build
   ./scripts/restore_database.sh data/dump/mcp_sentinel.dump
   docker compose up -d --wait
   ```
4. Open <http://localhost:8501>.
5. Optional check (42 database checks must pass):
   ```bash
   docker compose run --rm importer validate
   ```

Without an OpenAI key every page works except **AI assistant**. To add a key later, put it in `.env` and run `docker compose up -d`.

## Start with demo data (131 servers)

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
   Upgrading a database made by an older version of MCP Sentinel? Run `docker compose run --rm importer migrate` once. It adds new tables and keeps your data.
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

**A. Restore the dump** (includes the AI index, about 3 minutes):

1. Restore. Add `--replace` at the end if the database already has data:
   ```bash
   ./scripts/restore_database.sh data/dump/mcp_sentinel.dump
   ```
   The script also loads `data/dump/mcp_sentinel_ai.dump` (the AI index) and checks both checksums.
2. Start the app again:
   ```bash
   docker compose up -d
   ```

The dump is two files: `mcp_sentinel.dump` (37 MB, data) and `mcp_sentinel_ai.dump` (77 MB, AI index). Restored size: about 1.1 GB.

| Area | What it holds |
|---|---|
| Servers | all 50,019 registry records: 48,056 active, 617 deprecated, 1,346 deleted |
| Software | 20,456 package declarations, 27,323 code repositories, 33,965 hosted URLs |
| Endpoint status | 31,485 servers, from Agora |
| Tools | 16,055 tool records |
| Vulnerability checks | 16,514 servers checked; 30,150 remote-only servers have no package to check |
| Vulnerabilities | 19,406 findings on 6,048 servers, 1,363 advisories, 4,204 CVE records |
| Dependencies | 16,263 dependency lists, 2,158,770 dependency links |
| Coverage | 317,347 records of what was checked for each server and what was not |
| AI index | 55,477 entries: one per non-deleted server, the findings of each server, one note on how the data was collected |
| Structure | 24 tables, 5 views, the pgvector and pg_trgm extensions |

**B. Import the data bundle** (about 8 minutes):

1. Import and check:
   ```bash
   docker compose run --rm importer full
   ```
2. Build the AI index (uses your OpenAI key: about 13 minutes, 17 million embedding tokens, about $0.35):
   ```bash
   docker compose exec backend python -m app.ai index
   ```

## Rebuild the data bundle from research data

`data/research/` holds the saved source data. Rows from sources that do not allow redistribution are removed. It includes the package lookup of 2026-11-14 (deps.dev, OSV, CVE.org, EPSS for every declared npm, PyPI, NuGet and Cargo package).

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

To repeat the package lookup itself (about 35,400 requests to free public APIs, about 8 minutes):

```bash
.venv/bin/python -I scripts/enrich_packages.py
```

Answers are cached in `research/cache/http_full/`, so a second run sends no requests.

## Spark analytics

```bash
docker compose run --rm analytics
```

Exports four database views (read-only), builds Bronze/Silver/Gold Parquet files, runs four Spark SQL reports and K-Means clustering. Results go to `data/analytics/output/` (not in Git). About 40 seconds. Details: `DEPLOYMENT.md`, section 9.

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
5. Spark tests (they need Java, so they run in the analytics container):
   ```bash
   docker compose run --rm --entrypoint python analytics -m pytest -q tests/test_analytics.py
   ```

- The browser tests need the app running at <http://localhost:8501> (or set `FRONTEND_URL`). They are skipped otherwise.
- AI tests use fake model answers. The live AI browser test runs only with `RUN_LIVE_AI_TESTS=1`. It needs an OpenAI key and the AI index, and makes 2 OpenAI requests.

## App pages

| Page | Shows |
|---|---|
| Dashboard | Totals, deployment types, package ecosystems, coverage |
| Server search | Search and filters, including "Tool review hints" |
| Server profile | One server: review checklist (with JSON, Markdown and SBOM downloads), software, vulnerabilities, checks, tools |
| Compare | Two servers side by side |
| AI assistant | Questions and answers with sources and limits |

## Folders

| Folder | Contents |
|---|---|
| `backend/` | FastAPI API |
| `frontend/` | Streamlit web app |
| `database/` | Tables and views (`schema/`), report queries (`queries/`), database image (`Dockerfile`) |
| `scripts/` | Import, check, backup, restore, package lookup |
| `analytics/` | Spark pipeline, SQL reports, K-Means |
| `data/seed/` | Demo data (131 real servers) |
| `data/bundle/` | Full data (50,019 servers) |
| `data/dump/` | Full database backup: data and AI index |
| `data/research/` | Saved source data used to build `data/bundle/` |
| `tests/` | Automated tests |
| `docs/` | Project report, AI evaluation, screenshots |

More: `DEPLOYMENT.md` (ports, settings, backup, all commands) and `docs/PROJECT_REPORT.md` (design and results).

## Known limits

- Data is from one registry snapshot: 2026-10-23.
- Vulnerability lookups cover npm, PyPI, NuGet and Cargo packages with an exact version: 16,514 servers. Docker images and MCPB files are not covered.
- Remote-only servers (30,150) have no package to check. Endpoints are never contacted.
- Package lookups ran on 2026-11-14; NVD scores exist only for CVEs from the earlier research sample.
- Tool review hints are text patterns. Most of them are harmless and need a human to read them.
- Endpoint status comes from Agora (2026-10-22). It is not live.
- AI answers use only indexed data. Sources are checked to be real retrieved records; each sentence is not checked automatically.
- Each AI question and its retrieved public records are sent to OpenAI.

## Data sources and licences

The database and the files in `data/` are built from these sources. Records were normalized into tables, linked and summarized.

| Source | Used for | Licence or terms |
|---|---|---|
| [Official MCP Registry](https://registry.modelcontextprotocol.io) | server records | publisher metadata, attribution |
| [GitHub REST API](https://docs.github.com/en/rest) | repository activity | GitHub Terms of Service |
| [npm](https://www.npmjs.com), [PyPI](https://pypi.org) | package metadata, PyPI attestations | registry terms, attribution |
| [deps.dev](https://deps.dev) | dependency lists, provenance | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| [OSV.dev](https://osv.dev), [GitHub Advisory Database](https://github.com/advisories) | vulnerability records | CC BY 4.0 (OSV records keep their upstream licence) |
| [CVE.org](https://www.cve.org) | CVE records | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse); CVE records © The MITRE Corporation |
| [NVD](https://nvd.nist.gov) | CVSS scores | US government work |
| [FIRST EPSS](https://www.first.org/epss) | exploit probability per CVE | free use, attribution |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known exploited CVEs | CC0 |
| [Agora](https://openforallofus.com/data) | endpoint status | CC BY 4.0 |
| [PolicyLayer](https://huggingface.co/datasets/PolicyLayer/mcp-server-catalogue) | tool risk labels | CC BY 4.0 |
| [ToolHive](https://github.com/stacklok/toolhive-catalog) | tool catalog | Apache-2.0 |

Not included, because their terms do not allow redistribution or state no licence: RMCP.dev, SecureChain KG, Vulnerable MCP Project, MCP CVE Project, Glama.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
