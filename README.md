# MCP Sentinel — AI-Powered Security Intelligence for MCP Servers

**Project Team #2:** Sana Shaik, Shreem Dixit, Sahir Shaik, Dias Utebekov

MCP (Model Context Protocol) is the standard way AI agents connect to outside tools. Anyone can publish an MCP server, and most are written by individual developers without a security review. MCP Sentinel is our semester project to build a system that finds MCP servers, collects security-relevant information about them (repository maintenance, packages, dependencies, known vulnerabilities), and eventually produces explainable risk scores in a dashboard for developers, security teams, and compliance teams.

This repository currently contains **Sprint 1: Data Exploration and Wrangling**.

---

## 1. Sprint 1 scope

Our original Sprint 1 report described the data sources and a planned wrangling pipeline, but the profiling tables still said "To be measured". Based on the instructor's feedback, this sprint now delivers an **implemented and executed** pipeline:

1. **ETL scripts** that acquire, parse, flatten, clean, standardize, and join real data from every source our Sprint 1 report lists: the DeepNLP MCP Servers dataset, the Official MCP Registry, the MCPCorpus research dataset, the GitHub REST API, the PyPI and npm registries, deps.dev, and the OSV.dev vulnerability API.
2. **Real data profiling** with missing-value counts and percentages, duplicate checks, format inconsistencies, invalid values, and API enrichment coverage, measured before and after cleaning.
3. **Exported datasets** in `data/staging/` (normalized, PostgreSQL-ready) and `data/processed/` (one enriched row per server).

Out of scope for Sprint 1 (planned for later sprints): PostgreSQL deployment, the FastAPI backend, the dashboard, the risk-scoring engine, and AI/ML models.

## 2. Data sources

| Source | Used for | Access | Credential |
|---|---|---|---|
| [DeepNLP MCP Servers](https://huggingface.co/datasets/DeepNLP/mcp-servers) (Hugging Face) | Initial MCP server inventory (name, publisher id, website, description, category, Bing rank, month) | HF Hub API + file download | `HF_TOKEN` (optional — the dataset is public) |
| [Official MCP Registry](https://registry.modelcontextprotocol.io) | Second inventory; declared packages, versions, repository and subfolder for each server | `/v0/servers?version=latest` (paginated) | none |
| [MCPCorpus](https://github.com/Snakinya/MCPCorpus) (research dataset) | Large research inventory with categories, tags, and tool definitions | Raw file from GitHub at a pinned commit | none |
| GitHub REST API | Repository metadata (stars, forks, archived, issues, dates, language, license) and read-only manifest files | `/repos/{owner}/{repo}`, `/repos/{owner}/{repo}/contents/...` | `GITHUB_TOKEN` |
| PyPI JSON API | Python package metadata, versions, project URLs, dependencies | `https://pypi.org/pypi/<name>/json` | none |
| npm registry | JavaScript/TypeScript package metadata, versions, repository link, dependencies | `https://registry.npmjs.org/<name>` | none |
| deps.dev | Resolved dependency graph (direct and indirect, exact versions) of a package version | `/v3/systems/<eco>/packages/<name>/versions/<v>:dependencies` | none |
| OSV.dev | Known vulnerabilities for a specific package version | `/v1/querybatch`, `/v1/vulns/<id>` | none |

The GitHub token is only ever sent to `api.github.com`, and the Hugging Face token only to `huggingface.co`. No repository code is executed (including the MCPCorpus crawler scripts) and nothing is installed from the MCP servers. README files, issues, release notes, repository descriptions, and manifests are downloaded and cleaned as untrusted text; nothing in them is followed or run.

## 3. Repository layout

```text
MCP-Sentinel/
├── data/
│   ├── raw/                 Source snapshots (DeepNLP file, MCP Registry and MCPCorpus as .json.gz) + metadata
│   ├── staging/             Normalized PostgreSQL-ready tables (14 CSV files)
│   ├── processed/           mcp_servers_enriched.csv (one row per server)
│   ├── cache/               Cached API responses (git-ignored, safe to delete)
│   └── limit_runs/          Output of --limit test runs (git-ignored)
├── docs/
│   └── data_dictionary.md   Schemas, keys, status vocabularies
├── notebooks/
│   └── 01_sprint1_data_exploration.ipynb
├── reports/                 Generated profiling report and CSV summaries
├── scripts/
│   └── run_sprint1.py       Single command that runs the whole pipeline
├── src/
│   ├── etl.py               DeepNLP, GitHub, PyPI/npm, deps.dev, OSV, documents, joins
│   ├── sources.py           Official MCP Registry and MCPCorpus, schema extraction, entity resolution
│   └── profiling.py         Data profiling and report generation
├── tests/
│   └── test_etl.py          Deterministic unit tests (no network)
├── .env.example
├── pytest.ini
└── requirements.txt
```

## 4. Setup

### 4.1 Virtual environment (Linux/macOS)

Python 3.11 or newer is required (`tomllib` is part of the standard library from 3.11). We used Python 3.12.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows, activate with `.venv\Scripts\activate` instead.

### 4.2 Jupyter kernel

Register the virtual environment as a Jupyter kernel so the notebook runs with the same packages:

```bash
python -m ipykernel install --user --name mcp-sentinel-venv --display-name "MCP Sentinel (.venv)"
```

### 4.3 API credentials

Copy the template and fill in your own tokens. The `.env` file is git-ignored and must never be committed.

```bash
cp .env.example .env
```

```dotenv
GITHUB_TOKEN=
HF_TOKEN=
```

- **`GITHUB_TOKEN`** — a GitHub personal access token (a fine-grained token with public read-only access is enough). Without it GitHub allows only 60 requests per hour and most repository lookups will be recorded as `lookup_failed`; the pipeline prints a warning in this case.
- **`HF_TOKEN`** — a Hugging Face access token with read permission. The dataset is public, so this is optional.

The pipeline reports only whether each credential is present (`yes`/`no`) and never prints, logs, or stores token values.

## 5. Running the pipeline

Full run (all records):

```bash
python scripts/run_sprint1.py
```

Small test run (first 10 records):

```bash
python scripts/run_sprint1.py --limit 10
```

A limited run writes all of its outputs to `data/limit_runs/limit_<N>/` (staging, processed, and reports), so it never overwrites the full-run results.

The pipeline runs these steps:

1. **Acquire DeepNLP** — downloads the data file at a pinned dataset revision into `data/raw/` (only if it is not already there) and records the revision, download time, and SHA-256 checksum. Parses JSON arrays, JSON Lines, or concatenated JSON objects, counts malformed records, flattens nested JSON (`statistic` → `statistic_bing_rank`), and cleans it: column names, whitespace, placeholders to nulls, description list markers and quality flags, URL normalization and validation, GitHub owner/repository/branch/subdirectory, month to date, exact duplicates removed, semantic duplicates flagged.
2. **Acquire the Official MCP Registry** — pages through every latest-version entry, saves the snapshot, flattens the nested `repository` and `packages` objects, and cleans and deduplicates it.
3. **Acquire MCPCorpus** — downloads the corpus file at a pinned commit, flattens the nested `github` object (counts and flags cast to nullable integer and boolean types), parses tags and tools stored as JSON or comma-separated text, and removes exact and id duplicates.
4. **GitHub enrichment** — one metadata call and three activity calls (commits, contributors, releases) per unique repository, a directory listing of each server's location, read-only downloads of `package.json`, `pyproject.toml`, `setup.cfg`, and `requirements.txt`, and the README, latest release notes, and recent issues as text documents (cleaned, with metadata, filtered for pull requests, bots, and empty text).
5. **Entity resolution** — links each DeepNLP server to the MCP Registry and MCPCorpus by normalized repository id and subdirectory.
6. **Package enrichment** — looks up declared packages on PyPI or npm. A package is accepted as the server's package when the server's MCP Registry entry lists it, or when the registry metadata links back to the same repository.
7. **Dependency resolution** — asks deps.dev for the resolved dependency graph of every verified package version.
8. **Vulnerability enrichment** — queries OSV.dev in batches for every verified package version, every exactly pinned dependency, and every resolved dependency version, then downloads each vulnerability record and groups aliases.
9. **Export and profile** — writes the staging and processed CSV files and generates the reports, including schema extraction for the three raw inventories.

**Rerunning is safe.** Every successful (200) or definitive not-found (404) API response is cached as a JSON file in `data/cache/`, so a second run does not repeat identical requests. Failed requests are not cached and are retried on the next run. Requests use a 30-second timeout, up to four attempts with exponential backoff for timeouts and 5xx errors, and respect GitHub's `Retry-After` and `X-RateLimit-Reset` headers. A single record that cannot be enriched is recorded with a status and the pipeline continues. To refresh all API data, delete `data/cache/`; to re-download the dataset, delete the files in `data/raw/`.

## 6. Running the notebook

```bash
source .venv/bin/activate
jupyter lab notebooks/01_sprint1_data_exploration.ipynb
```

Select the **MCP Sentinel (.venv)** kernel. The notebook imports the functions from `src/` and reads the files produced by `scripts/run_sprint1.py`, so run the pipeline first. To re-execute the notebook from the command line and save its outputs:

```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/01_sprint1_data_exploration.ipynb
```

## 7. Running the tests

```bash
pytest
```

The tests are deterministic and never call external APIs. They cover null normalization, GitHub URL normalization and owner/repository extraction, registry repository links, nested JSON flattening, JSON Lines parsing, duplicate detection, ecosystem and package name normalization, pinned version detection, manifest parsing, unknown version handling, package verification (including packages listed in the MCP Registry), package name and version validation, OSV status handling, alias grouping, the rule that a failed lookup never produces a vulnerability count of zero, markdown text cleaning, GitHub pagination counts, MCPCorpus tag and tool parsing, schema extraction, and cross-source entity resolution.

## 8. Output files

| File | Grain | Description |
|---|---|---|
| `data/raw/data_agent_mcp-server_202503.json` | 1 line per record | Unmodified DeepNLP source file |
| `data/raw/deepnlp_source_metadata.json` | — | Dataset revision, download time, file size and SHA-256 |
| `data/raw/mcp_registry_servers.json.gz`, `data/raw/mcpcorpus_servers.json.gz` (+ `*_source_metadata.json`) | 1 entry per record | Raw MCP Registry and MCPCorpus snapshots |
| `data/staging/mcp_servers.csv` | server | Cleaned server inventory with original values kept for traceability |
| `data/staging/repositories.csv` | repository | GitHub repository metadata |
| `data/staging/server_repository_map.csv` | server | Server → repository location, manifests found |
| `data/staging/documents.csv` | document | Cleaned README, release notes, and issue text with metadata and filter reason |
| `data/staging/mcp_registry_servers.csv`, `data/staging/mcp_registry_packages.csv` | registry entry / declared package | Cleaned Official MCP Registry inventory |
| `data/staging/mcpcorpus_servers.csv` | corpus record | Cleaned MCPCorpus inventory |
| `data/staging/server_source_map.csv` | server × linked record | Entity resolution between DeepNLP, the MCP Registry, and MCPCorpus |
| `data/staging/packages.csv` | package | PyPI/npm registry metadata |
| `data/staging/server_package_map.csv` | server × package | Declared packages with verification status, identified version, OSV status |
| `data/staging/dependencies.csv` | declared dependency | Runtime dependencies from manifests with pinned versions and OSV status |
| `data/staging/resolved_dependencies.csv` | package version × dependency | deps.dev resolved dependency graphs with OSV status |
| `data/staging/vulnerabilities.csv` | OSV record | Vulnerability details, aliases, CVE ids, severity |
| `data/staging/package_vulnerability_map.csv` | package version × vulnerability | Which package versions are affected and which versions fix them |
| `data/processed/mcp_servers_enriched.csv` | server | Denormalized analysis table joining all of the above |
| `reports/sprint1_profile.md` | — | Generated profiling report (all Sprint 1 statistics) |
| `reports/missing_values.csv` | column × stage | Missing values before and after cleaning |
| `reports/duplicate_summary.csv` | check | Duplicate analysis |
| `reports/data_quality_issues.csv` | issue | Format inconsistencies, invalid values, low-information columns |
| `reports/cleaning_log.csv` | step | Records modified, flagged, or removed by each cleaning step |
| `reports/enrichment_summary.csv` | metric | GitHub, document, source-linking, package, dependency, and OSV coverage |
| `reports/source_schemas.csv` | field path | Schema extraction for the three raw inventories |
| `reports/sprint1_report_update_notes.md` | — | Which sections of our original Sprint 1 report to update, with the measured values |

Column-level schemas, candidate primary and foreign keys, and status vocabularies are documented in [`docs/data_dictionary.md`](docs/data_dictionary.md). The measured results are in [`reports/sprint1_profile.md`](reports/sprint1_profile.md).

## 9. Important interpretation rule

**A missing vulnerability result does not mean a server is secure.** Every package and dependency row carries an explicit OSV status (`known_vulnerabilities_found`, `no_known_vulnerabilities_found`, `api_failed`, `unknown_version`, `ambiguous_mapping`, `unknown_package_identity`, `not_assessed`). Only `no_known_vulnerabilities_found` means OSV.dev was actually queried and returned nothing, and `known_vulnerability_count` is left empty (not `0`) whenever no successful lookup happened.

## 10. Known limitations

- The DeepNLP dataset is a single snapshot from March 2025, while the GitHub, registry, and OSV data was collected live, so some repository links have become stale (moved repositories, deleted monorepo subdirectories).
- Records whose website is a product page rather than a GitHub repository cannot be linked to a repository or package without guessing, so they are kept but marked `not_assessed`.
- Only `package.json`, `pyproject.toml`, `setup.cfg`, and `requirements.txt` at the server's own location are parsed. `setup.py` is not executed or parsed, lock files are not read, and Go, Rust, Java, and other ecosystems are only detected, not analysed.
- Dependencies declared with version ranges are checked only through the deps.dev graph of a verified package, which shows what a fresh install would resolve today rather than what an existing user has installed.
- The MCP Registry and MCPCorpus are profiled and linked to the DeepNLP servers, but their own servers are not enriched one by one (that would need tens of thousands of API requests).
- The first full run downloads the whole MCP Registry page by page, which takes a while; later runs use the saved snapshot.
- Description quality flags and generic-name flags are simple heuristics and can produce false positives.
- OSV.dev only covers publicly disclosed vulnerabilities in packages. MCP-specific risks (tool poisoning, excessive permissions, missing authentication) are not covered yet.
- API data changes over time; rerunning after deleting the cache can produce slightly different counts. Every row records when it was collected.

## 11. How the staging data will be used in Sprint 2

The staging tables are already normalized with stable identifiers (`server_id`, `repository_id`, `package_id`, `vulnerability_id`) and explicit mapping tables, so Sprint 2 can create matching PostgreSQL tables with primary and foreign keys and load each file with `COPY`, for example:

```sql
\copy mcp_servers FROM 'data/staging/mcp_servers.csv' WITH (FORMAT csv, HEADER true)
```

Sprint 2 can then add scan history (a scan id and timestamp on each load), compute the security features from our Sprint 1 report (`known_vulnerability_count`, `vulnerable_dependency_count`, `days_since_last_push`, `repository_archived`, `dependency_count`), and start the rule-based risk score on top of these tables.
