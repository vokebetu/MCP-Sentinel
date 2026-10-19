# Sprint 1 Report — Update Notes

These notes list the specific parts of our original *Sprint 1: Data Exploration and Wrangling* report that need to change now that the pipeline has actually been implemented and executed. The instructor's feedback was that the report contained a detailed plan but no executed data processing, and several tables still said "To be measured". The pipeline now covers every source and every Sprint 1 transformation that the report lists. All values below come from the full pipeline run on **18 October 2026** (`python scripts/run_sprint1.py`) and can be checked in `reports/sprint1_profile.md` and the CSV files in `reports/`.

Section numbers refer to the original report.

---

## 1. Sprint Overview — rewrite the Sprint Goal paragraph

The current text describes what we *intended* to find. It should now also state what was done. Suggested addition:

> In Sprint 1 we implemented and ran a Python/Pandas ETL pipeline (`scripts/run_sprint1.py`). It acquired the three MCP server inventories named in this report — the DeepNLP MCP Servers dataset (296 records), the Official MCP Registry (45,657 servers), and the MCPCorpus research dataset (13,875 records) — flattened, cleaned, and profiled them, and linked them by repository. The DeepNLP servers were enriched with GitHub repository metadata, activity, and text documents, their packages were verified on PyPI and npm, their dependency graphs were resolved with deps.dev, and 1,818 package versions were checked against OSV.dev. The results were exported as fourteen normalized staging tables and one processed table for PostgreSQL. All profiling numbers in this report were produced by that pipeline.

The statement "a dataset of 296 records" is **confirmed** by the actual download and can stay.

## 2. Data Source Inventory — correct the summary table

| Data source | Column | Change |
|---|---|---|
| DeepNLP MCP Servers | Format | Change "Dataset / JSON" to **JSON Lines** (one JSON object per line, file `data_agent_mcp-server_202503.json`, 102,820 bytes) |
| DeepNLP MCP Servers | Estimated size | Change to **296 records, 9 attributes** (measured) |
| DeepNLP MCP Servers | Update frequency | Change to **single snapshot** (every record has `month = 202503`; dataset last modified 2025-04-21) |
| MCP Ecosystem research dataset (MCPCorpus) | Estimated size / format | **13,875 records** (13,873 after removing duplicates), JSON file, commit `295fe37cd972` of 2025-09-01 |
| GitHub | Estimated size | **227 unique repositories** queried, 222 retrieved, plus 2,230 text documents |
| npm / PyPI | Estimated size | **105 npm** and **88 PyPI** package names looked up |
| deps.dev | Estimated size | **89 dependency graphs** requested, 87 found, **7,961 resolved dependencies** |
| OSV.dev | Estimated size | **1,818 package versions** queried, **292 vulnerability records** retrieved |

Add a row for the **Official MCP Registry** (it appears in the Section 5 pipeline diagram but not in the inventory table): `registry.modelcontextprotocol.io` API, JSON (paginated, 457 pages), **45,657 servers** and 19,358 declared packages, public, continuously updated.

## 3. Data Understanding and Exploration

### 3.1 Data Structure Analysis — fix the data dictionary

The attribute names in our dictionary do not match the real DeepNLP file. Replace the first eight rows with the actual source attributes:

| Real attribute | Our report said | Actual type | Note |
|---|---|---|---|
| `content_name` | `server_name` | text | Renamed to `server_name` in staging |
| `publisher_id` | `publisher_id` | text | Unique for all 296 records; used to build `server_id` |
| `website` | `url` | text | GitHub URL for 246 records, product website for 50 |
| `description` | `description` | text | Scraped text; 222 start with a markdown list marker |
| `field` | `field` | text | Constant: `AI AGENT` |
| `subfield` | `sub_field` | text | Constant: `MCP SERVER` |
| `statistic` | `statistics` | nested JSON object | Only key is `Bing Rank`; empty `{}` in 246 records |
| `month` | `month` | text `YYYYMM` | Constant: `202503`; converted to a date |
| `content` | (missing) | text | **Not in our report.** Empty in all 296 records |

Also add a sentence that the remaining dictionary rows (`repository_url`, `package_name`, `package_version`, `vulnerability_id`, `severity`, `scan_timestamp`) now exist as real columns in the staging tables, and refer to `docs/data_dictionary.md` for the full schema. Mention that `category` now comes from MCPCorpus (182 DeepNLP servers have one).

**Major Data Objects table:** add the measured row counts: MCP Server 296 (plus 45,657 MCP Registry entries and 13,873 MCPCorpus records), Repository 227, Package 193, Dependency 1,202 declared rows (471 unique) and 7,961 resolved rows, Vulnerability 292 OSV records (174 unique after alias grouping), Document 2,230 (945 kept). Update the Repository attributes to "stars, forks, commits, contributors, releases" — they are all collected now. Mark "Scan Record" as planned for Sprint 2.

**Dataset Organization checkboxes:** uncheck **Time-Series Data**. Every source is a single snapshot; time series only become possible once we store repeated scans.

### 3.2 Data Profiling — replace every "To be measured"

**Dataset Statistics table:**

| Metric | New value |
|---|---|
| Number of records | 296 DeepNLP servers; 45,657 MCP Registry entries; 13,873 MCPCorpus records |
| Number of attributes | 9 DeepNLP source attributes (8 listed in our report + `content`) |
| Number of files/tables | 3 raw snapshots → 14 staging tables + 1 processed table |
| Data types present | text, numeric, boolean, date/timestamp, nested JSON objects and arrays, JSON stored inside text fields |

**Missing Values Summary table** (replace the whole table):

| Attribute | Missing count | Missing % |
|---|---|---|
| URL (`website`) | 0 | 0.00% |
| Description — before cleaning | 1 | 0.34% |
| Description — after cleaning (punctuation-only text set to null) | 9 | 3.04% |
| Field / Sub-field | 0 | 0.00% (but constant, so no information) |
| Bing Rank (`statistic`) | 246 | 83.11% |
| `content` | 296 | 100.00% (column dropped) |
| Repository information — no repository reference in the website | 51 | 17.23% (50 non-GitHub websites + 1 GitHub organization URL) |
| Repository information — not usable (no reference, repository deleted, or subdirectory removed) | 71 | 23.99% |
| Package information — no verified PyPI/npm package | 208 | 70.27% |

**Duplicate Records section:** the current text in this section actually talks about *missing values* and the text under "Outliers and Anomalies" talks about *duplicates*; the two paragraphs appear to be swapped. Replace the duplicate text with:

> DeepNLP has no exact duplicate records (0 of 296), and `publisher_id`, `content_name`, and `website` are all unique, also after URL normalization. 19 servers share the repository `modelcontextprotocol/servers`, but they live in different subdirectories and are separate servers, so they were not merged. A name-based check flagged 2 possible semantic duplicate groups (4 records), which turned out to be independent projects. MCPCorpus contained 2 exact duplicates (removed) and lists 471 repository locations more than once (1,007 records, flagged). Across sources, the same server appears in several inventories: 18 DeepNLP servers match exactly one MCP Registry entry (3 match several) and 166 match exactly one MCPCorpus record (27 match several), using the normalized repository URL and subdirectory as the matching key.

**Outliers and Anomalies section:** replace with measured anomalies:

- Bing Rank is 50.0 in 49 of its 50 non-null values, so it has almost no variance.
- GitHub stars are extremely skewed: median 104, maximum 91,338 (`modelcontextprotocol/servers`).
- 103 of the 222 retrieved repositories (46.4%) have had no commit for more than a year, 29 have a single contributor, 19 are archived, and 21 have moved to a new owner or name.
- 8 descriptions are website boilerplate, 21 are sentence fragments, and 3 server names are link text ("here", "more", "demo video").
- One dependency version (`aiohttp` 3.8.5) alone has 42 known vulnerabilities.

## 4. Data Quality Assessment — update the issue table with measured impact

| Issue type | Measured result | Suggested impact |
|---|---|---|
| Missing values | DeepNLP identifiers complete; description 3.04% missing after cleaning; Bing Rank 83.11%; no verified package for 70.27% of servers; MCPCorpus descriptions missing in 26.75%; 30.01% of MCP Registry entries have no repository URL | High (for enrichment, not for identifiers) |
| Duplicates | DeepNLP: 0 exact duplicates; MCPCorpus: 2 exact duplicates removed, 1,007 records repeat a repository location; servers overlap across inventories | Medium |
| Inconsistent formats | DeepNLP: 222 descriptions with list markers, 250 with surrounding whitespace, 26 websites with trailing slash, 2 with fragments, 31 GitHub URLs with subdirectories, month stored as `YYYYMM` text. MCPCorpus: tags stored as JSON text in 4,850 records and as comma-separated text in 8,784; tools stored as JSON text | High |
| Invalid values | 0 syntactically invalid URLs; 43 low-quality descriptions; 3 generic names; 1 organization URL; 3 invalid and 49 unpublished declared package versions; 130 MCPCorpus tool fields that are not valid JSON | Medium |
| Outliers | Skewed stars, near-constant Bing Rank | Low |
| Data imbalance | Measured in MCPCorpus: the two largest categories (`developer-tools`, `research-and-data`) hold 86.12% of records, 7 categories have fewer than ten | **High** (was Medium) |
| Other: API data changes over time | 21 moved repositories, 5 deleted repositories, 15 removed monorepo subdirectories since the March 2025 snapshot | **High** (was Medium) |

Add one sentence to the discussion: the most critical issue turned out to be **package identity** — 78 of 193 package candidates could not be trusted because the registry does not link back to the server's repository (61 have no repository link at all, 17 point to a different repository).

## 5. Data Wrangling and Preparation

**Initial Data Wrangling Pipeline diagram:** replace it with the pipeline that actually ran:

```
DeepNLP + Official MCP Registry + MCPCorpus
  ↓  download, keep raw snapshots (data/raw)
Parse (JSON Lines / paginated JSON / JSON array) + schema extraction + flatten nested JSON
  ↓
Clean + normalize + validate (whitespace, nulls, URLs, repository ids, dates, types, tags, tools)
  ↓
Duplicate checks (exact, identifier, URL, repository location, semantic) + entity resolution across inventories
  ↓
GitHub REST API (metadata, commits, contributors, releases, manifests, README / issues / release notes)
  ↓
PyPI / npm verification (MCP Registry listing or registry link back to the repository)
  ↓
deps.dev dependency graphs → OSV.dev batch queries
  ↓
Join → export staging CSVs + processed CSV → profiling reports
```

Security feature generation, scan history, and risk scoring should be moved to "future sprints".

**Transformations Performed:** every box that is checked in our report was actually performed. Add the evidence:

- *Structured data:* missing value handling, format standardization, duplicate removal (2 MCPCorpus duplicates removed, 0 in DeepNLP), data validation (URLs, package names, versions), data type conversion (dates, nullable integers and booleans).
- *Semi-structured data:* JSON flattening (DeepNLP `statistic`, GitHub `owner`/`license`, MCP Registry `repository`/`packages`, MCPCorpus `github`), metadata extraction, and **schema extraction** (`reports/source_schemas.csv`: 10, 7,646, and 178 field paths for DeepNLP, the MCP Registry, and MCPCorpus).
- *Unstructured data:* text cleaning, metadata generation, and document filtering of 2,230 GitHub documents (225 READMEs, 100 release notes, 1,905 issue-endpoint items); 945 documents were kept after removing 1,258 pull requests, 4 bot-authored issues, 1 missing README, and 22 empty or too-short texts.

**Describe the transformations — change "will" to past tense and add counts** (from `reports/cleaning_log.csv`):

- DeepNLP: whitespace normalized in 267 descriptions; 1 empty description and the empty `content` column converted to nulls; `content` dropped; leading list markers or punctuation removed from 236 descriptions; 43 descriptions flagged; 37 website URLs normalized; 245 GitHub references parsed; `month` converted to a date for all 296 records; 3 generic names and 4 possible semantic duplicates flagged; 0 records removed.
- MCP Registry: whitespace normalized in 177 descriptions; 31,870 GitHub repository references parsed; 5,517 entries flagged as sharing a repository location.
- MCPCorpus: 2 exact duplicates removed; 3,129 empty descriptions set to null; tags parsed in 13,637 records; tools parsed in 55 records; 13,866 repository references parsed; 1,007 records flagged as sharing a repository location.

**Planned Future Transformations:** move **Dataset integration and joins** from "future" to "completed".

## 6. AI-Enabled Data System Thinking

**6.1 Data Ingestion Thinking:** add that batch ingestion (DeepNLP, MCPCorpus) and API ingestion (MCP Registry, GitHub, PyPI, npm, deps.dev, OSV.dev) are now implemented, with authenticated GitHub requests, retries, rate-limit handling, and a local response cache so repeated runs do not repeat identical requests. Streaming, file uploads, and scheduled collection remain future work.

**AI Readiness Reflection table:**

| Consideration | Updated assessment |
|---|---|
| Input features available? | Partially, now measured: repository and activity features for 222 repositories (240 servers), a verified package for 88 servers, and an OSV assessment for 119 servers (40.20%) |
| Labels available? | Still no ground-truth risk labels |
| Text corpus available? | Yes: 945 cleaned and filtered documents (224 READMEs, 93 release notes, 628 issues) with metadata |
| Data volume sufficient? | 296 servers enriched in depth, but only 119 could be assessed for vulnerabilities; MCPCorpus and the MCP Registry add almost 60,000 inventory records for later sprints |

**6.3 Updated Architecture:** add the storage layers that now exist: `data/raw` (source snapshots), `data/staging` (normalized tables), `data/processed` (analysis table), and `data/cache` (API responses).

## 7. Team Contributions

The "Tasks Completed" column only describes research and planning. Each member's row should be updated to describe their part in implementing, running, testing, or documenting the pipeline. The team needs to fill this in; it is not something the pipeline can measure.

**Challenges Encountered:** add the measured challenges: 78 of 193 package candidates were ambiguous; 1,000 of 1,202 declared dependencies use version ranges; the three inventories overlap far less than expected (only 29 MCP Registry entries point to any DeepNLP repository); the March 2025 snapshot is partly stale; downloading the whole MCP Registry takes 457 API pages.

**Lessons Learned:** add that a shared repository does not mean a duplicate server (monorepos), that most known vulnerabilities come from dependencies rather than the server's own package (56 of 57 vulnerable servers), and that the share of servers that **could not be assessed** (177, 59.80%) is larger than the share with known vulnerabilities (57, 19.26%), so missing evidence must stay visible in the risk score.

## 8. Sprint Reflection

**Sprint Accomplishments:** add that the ETL pipeline was implemented, executed on the full data, tested (61 unit tests), and that its outputs were exported and profiled.

**Remaining Risks:** the sentence "The number of missing values, duplicates, and matches obtained from each of the sources are not yet determined" is no longer true. Replace it with the measured coverage: 222 of 227 repositories retrieved (97.8%), 18 DeepNLP servers matched in the MCP Registry and 166 in MCPCorpus, 89 of 193 package candidates verified (46.11%), 1,818 of 1,818 OSV queries completed, and 177 of 296 servers (59.80%) not assessable for vulnerabilities with the current sources.

## 9. Sprint Exit Checklist

"Data sources identified and acquired" and "Initial data wrangling completed" are now actually true for every listed source. We suggest adding the evidence next to the existing rows and adding three new rows:

| Requirement | Completed | Evidence |
|---|---|---|
| ETL scripts implemented and executed | x | `src/etl.py`, `src/sources.py`, `scripts/run_sprint1.py` |
| Real data profiling performed | x | `reports/sprint1_profile.md`, `reports/missing_values.csv`, `reports/duplicate_summary.csv`, `reports/source_schemas.csv` |
| Cleaned and normalized data exported for PostgreSQL | x | `data/staging/*.csv`, `data/processed/mcp_servers_enriched.csv` |

## Appendix

**Example Normalized Record:** the current example uses made-up values (`example-mcp-server`, `risk_score: 42`). Replace it with a real record from `data/processed/mcp_servers_enriched.csv`, for example:

```
server_id: deepnlp:pub-chroma
server_name: Chroma
publisher_id: pub-chroma
repository_id: github:chroma-core/chroma-mcp
corpus_category: research-and-data
stars: 600
archived: False
days_since_last_commit: 395
contributor_count: 6
package_ids: PyPI:chroma-mcp
package_mapping_status: verified
identified_versions: 0.2.6
declared_dependency_count: 9
pinned_dependency_count: 1
resolved_dependency_count: 108
vulnerable_dependency_count: 2
package_vulnerability_status: no_known_vulnerabilities_found
vulnerability_assessment_status: known_vulnerabilities_found
known_vulnerability_count: 9
enriched_at: 2026-10-18T07:31:36Z
```

`risk_score` and `risk_level` should be removed from the example, because they will only exist after the scoring work in a later sprint. `enriched_at` changes on every pipeline run.

**Proposed Security Feature Dictionary:** add a column showing which features already exist in the processed data:

| Feature | Status after Sprint 1 |
|---|---|
| `known_vulnerability_count` | Available (`known_vulnerability_count`, alias-grouped) |
| `critical_vulnerability_count` | Derivable from `vulnerabilities.severity_label` (7 critical vulnerabilities found) |
| `vulnerable_dependency_count` | Available (pinned and deps.dev-resolved dependencies) |
| `days_since_last_commit` | Available |
| `repository_archived` | Available as `archived` |
| `dependency_count` | Available as `declared_dependency_count` and `resolved_dependency_count` |
| `package_version` | Available as `identified_versions` |
| `tool_definition_changed` | Not yet; MCPCorpus has tool definitions for only 55 servers and there is no scan history |
| `authentication_present` | Not available; the MCP Registry's secret environment variables (7,069 packages) are a first related signal |
| `risk_score`, `risk_level` | Later sprint |
| `scan_timestamp` | Available as `collected_at` / `enriched_at` |

Also add references to the scripts, the data dictionary (`docs/data_dictionary.md`), and the notebook (`notebooks/01_sprint1_data_exploration.ipynb`) to the appendix.
