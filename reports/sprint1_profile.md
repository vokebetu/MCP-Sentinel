# MCP Sentinel — Sprint 1 Data Profiling Report

*Generated automatically by `scripts/run_sprint1.py` on 2026-10-18T07:31:39Z (UTC). Run mode: **full run**. Every number in this report was calculated from the downloaded data and the live API responses collected during this run; nothing was typed in by hand.*

## 1. Sprint Overview

The goal of Sprint 1 was to turn the data plan from our original report into a working ETL pipeline. The pipeline acquires the three MCP server inventories named in our report (DeepNLP, the Official MCP Registry, and the MCPCorpus research dataset), flattens and cleans them, links them by repository, enriches the DeepNLP servers with GitHub repository metadata and documents, verifies their packages on PyPI and npm, resolves dependency graphs with deps.dev, and checks every identified package version against OSV.dev. The cleaned and normalized results are exported as PostgreSQL-ready CSV files.

- MCP server records processed (DeepNLP inventory): **296**, retained **296** (removed: 0)
- Official MCP Registry entries profiled: **45657**; MCPCorpus records profiled: **13873**
- DeepNLP servers found in the MCP Registry: **18 (6.08%)**, in MCPCorpus: **166 (56.08%)**
- Unique GitHub repositories identified: **227**
- Servers with a verified PyPI/npm package: **88 (29.73%)**
- Package/dependency versions checked against OSV.dev: **1818**
- Unique known vulnerabilities found (after alias grouping): **174**

## 2. Data Source Inventory

| source | role | format | records_used | authentication |
|---|---|---|---|---|
| DeepNLP MCP Servers (Hugging Face) | initial server inventory | JSON Lines | 296 | HF_TOKEN (optional) |
| Official MCP Registry | server inventory, declared packages | JSON API (paginated) | 45657 | none |
| MCPCorpus (research dataset) | server inventory, categories, tools | JSON file | 13875 | none |
| GitHub REST API | repository metadata, activity, manifests, documents | JSON API | 227 | GITHUB_TOKEN |
| PyPI JSON API | Python package metadata | JSON API | 88 | none |
| npm registry | JavaScript package metadata | JSON API | 105 | none |
| deps.dev API | resolved dependency graphs | JSON API | 89 | none |
| OSV.dev API | vulnerability intelligence | JSON API | 1818 | none |

- **DeepNLP** was downloaded from `https://huggingface.co/datasets/DeepNLP/mcp-servers` at revision `f1bb6287a9e200f8cdcc0079718573515a74754e` (last modified 2025-04-21T02:27:43.000Z). Source file(s): `data_agent_mcp-server_202503.json` (102820 bytes, sha256 `7afdae8d397d…`). Malformed JSON records: 0.
- **Official MCP Registry** was read from `https://registry.modelcontextprotocol.io/v0/servers` (`version=latest`, 457 pages) on 2026-10-18T07:22:01Z and saved as `data/raw/mcp_registry_servers.json.gz`.
- **MCPCorpus** was downloaded from `https://github.com/Snakinya/MCPCorpus` (`Website/mcpso_servers_cleaned.json`, commit `295fe37cd972` of 2025-09-01T16:46:19Z) and saved as `data/raw/mcpcorpus_servers.json.gz`. None of the repository's crawler code was run.

## 3. Data Understanding and Exploration

### 3.1 DeepNLP raw structure

The source file is in JSON Lines format (one JSON object per line). After flattening, the raw table has **296 records** and **11 attributes** (including the two provenance columns `source_file` and `source_record_number` that the pipeline adds). The nested `statistic` object was flattened with `pandas.json_normalize`, which turned the key `Bing Rank` into the column `statistic_bing_rank`.

| column | dtype | example |
|---|---|---|
| content_name | str | AgentRPC |
| publisher_id | str | pub-agentrpc |
| website | str | https://www.agentrpc.com/ |
| subfield | str | MCP SERVER |
| field | str | AI AGENT |
| description | str | ↗ Toggle menu Node.js Go Python OpenAI Anthropic Groq Cerebr |
| month | str | 202503 |
| content | str |  |
| source_file | str | data_agent_mcp-server_202503.json |
| source_record_number | int64 | 1 |
| statistic_bing_rank | float64 | 50.0 |

### 3.2 Dataset statistics

| metric | value |
|---|---|
| DeepNLP records | 296 |
| DeepNLP source attributes (excluding provenance columns) | 9 |
| Official MCP Registry entries (latest versions) | 45657 |
| Official MCP Registry declared packages | 19358 |
| MCPCorpus records (raw / retained) | 13875 / 13873 |
| Staging tables produced | 14 |
| DeepNLP records whose website is a GitHub URL | 246 |
| DeepNLP records with a non-empty `statistic` object | 50 |

### 3.3 DeepNLP description quality

Descriptions were scraped by the dataset publisher and many contain markdown list markers or website boilerplate. The pipeline keeps the original text in `description_original` and assigns each cleaned description a quality flag:

| description_quality | servers |
|---|---|
| ok | 253 |
| fragment | 21 |
| missing | 9 |
| web_boilerplate | 8 |
| too_short | 5 |

### 3.4 Additional MCP inventories

The Official MCP Registry returned 45657 latest-version entries. 31870 (69.8%) point to a GitHub repository. They declare 19358 packages, distributed over these registry types:

| registry_type | packages |
|---|---|
| npm | 11669 |
| pypi | 4552 |
| mcpb | 1719 |
| oci | 1175 |
| nuget | 156 |
| cargo | 87 |

MCPCorpus contains 13875 records (13873 after removing exact and identifier duplicates). Unlike DeepNLP it has a real category attribute, which makes **category imbalance** measurable. The ten largest categories:

| category | records | pct |
|---|---|---|
| developer-tools | 7709 | 55.57 |
| research-and-data | 4239 | 30.56 |
| (missing) | 635 | 4.58 |
| cloud-platforms | 572 | 4.12 |
| communication | 89 | 0.64 |
| browser-automation | 69 | 0.5 |
| finance | 67 | 0.48 |
| security | 63 | 0.45 |
| os-automation | 59 | 0.43 |
| cloud-storage | 51 | 0.37 |

The two largest categories hold 86.12% of all records, while 7 categories have fewer than ten records. A model trained on these categories would be dominated by developer tools and data/research servers.

### 3.5 Schema extraction

The pipeline walks every raw JSON record and records each field path, the value types seen, and how many records contain it (`reports/source_schemas.csv`). Paths with more than one value type point to format inconsistencies.

| source | field_paths | mixed_type_paths | nested_paths |
|---|---|---|---|
| deepnlp | 10 | 0 | 1 |
| mcpcorpus | 178 | 13 | 164 |
| official_mcp_registry | 7646 | 127 | 7644 |

| source | field_path | value_types | record_coverage_pct |
|---|---|---|---|
| mcpcorpus | author_name | null; str | 100.0 |
| mcpcorpus | category | null; str | 100.0 |
| mcpcorpus | description | null; str | 100.0 |
| mcpcorpus | github | dict; null | 100.0 |
| mcpcorpus | server_command | null; str | 100.0 |
| mcpcorpus | server_config | null; str | 100.0 |
| mcpcorpus | sse_url | null; str | 100.0 |
| mcpcorpus | tags | null; str | 100.0 |
| mcpcorpus | tools | null; str | 100.0 |
| mcpcorpus | type | null; str | 100.0 |
| mcpcorpus | github.language | null; str | 93.72 |
| mcpcorpus | github.last_commit | null; str | 93.72 |
| mcpcorpus | github.license | null; str | 93.72 |
| official_mcp_registry | server._meta.io.modelcontextprotocol.registry/publisher-provided.categories[] | dict; str | 0.55 |
| official_mcp_registry | server._meta.io.modelcontextprotocol.registry/publisher-provided.tools | dict; int; list; str | 0.54 |

## 4. Data Quality Assessment

### 4.1 Missing values

DeepNLP before and after cleaning. "Before" counts both true nulls and blank/placeholder strings in the flattened raw table; "after" counts nulls in the staged `mcp_servers` table, where every placeholder has been converted to a real null.

| source_column | staging_column | missing_before | missing_before_pct | missing_after | missing_after_pct |
|---|---|---|---|---|---|
| content_name | server_name | 0 | 0.0 | 0 | 0.0 |
| publisher_id | publisher_id | 0 | 0.0 | 0 | 0.0 |
| website | website_url | 0 | 0.0 | 0 | 0.0 |
| subfield | sub_field | 0 | 0.0 | 0 | 0.0 |
| field | field | 0 | 0.0 | 0 | 0.0 |
| description | description | 1 | 0.34 | 9 | 3.04 |
| month | snapshot_month | 0 | 0.0 | 0 | 0.0 |
| content | (dropped) | 296 | 100.0 |  |  |
| source_file | source_file | 0 | 0.0 | 0 | 0.0 |
| source_record_number | source_record_number | 0 | 0.0 | 0 | 0.0 |
| statistic_bing_rank | bing_rank | 246 | 83.11 | 246 | 83.11 |

The attribute with the highest missing share after cleaning is `bing_rank` (83.11%). Missing values were not imputed, because inventing names, descriptions, or ranks would introduce false information into a security dataset.

Columns with the most missing values in the other inventories (after cleaning):

| dataset | column | missing_count | missing_pct |
|---|---|---|---|
| mcpcorpus | tool_count | 13818 | 99.6 |
| mcpcorpus | tool_names | 13818 | 99.6 |
| mcpcorpus | github_subpath | 13794 | 99.43 |
| mcpcorpus | record_type | 12975 | 93.53 |
| mcpcorpus | license | 7010 | 50.53 |
| mcpcorpus | tags | 5089 | 36.68 |
| mcpcorpus | description | 3711 | 26.75 |
| mcpcorpus | primary_language | 1725 | 12.43 |
| official_mcp_registry | repository_subfolder | 42676 | 93.47 |
| official_mcp_registry | website_url | 19226 | 42.11 |
| official_mcp_registry | title | 14526 | 31.82 |
| official_mcp_registry | repository_id | 13787 | 30.2 |
| official_mcp_registry | repository_url | 13703 | 30.01 |
| official_mcp_registry | repository_source | 13703 | 30.01 |
| official_mcp_registry_packages | ecosystem | 3137 | 16.21 |
| official_mcp_registry_packages | package_name | 3137 | 16.21 |
| official_mcp_registry_packages | version | 2032 | 10.5 |

### 4.2 Duplicate analysis

| dataset | check | count | description |
|---|---|---|---|
| deepnlp | exact_duplicate_records | 0 | Raw records identical to an earlier record in every source field |
| deepnlp | duplicate_publisher_id | 0 | Records repeating an earlier publisher_id |
| deepnlp | duplicate_server_name | 0 | Records repeating an earlier content_name exactly |
| deepnlp | duplicate_server_name_case_insensitive | 0 | Records repeating an earlier content_name after trimming and lowercasing |
| deepnlp | duplicate_website_raw | 0 | Records repeating an earlier website string exactly |
| deepnlp | duplicate_website_normalized | 0 | Records repeating an earlier website after URL normalization |
| deepnlp | duplicate_server_id | 0 | Staged records repeating a server_id (must be 0) |
| deepnlp | duplicate_repository_location | 0 | Servers pointing to the same repository and the same subdirectory |
| deepnlp | servers_sharing_a_repository | 19 | Servers whose GitHub repository is shared with at least one other server (monorepo pattern, not duplicates) |
| deepnlp | repositories_shared_by_multiple_servers | 1 | Distinct repositories referenced by more than one server |
| deepnlp | possible_semantic_duplicate_records | 4 | Records flagged because their normalized name or normalized website matches another record |
| deepnlp | possible_semantic_duplicate_groups | 2 | Distinct groups of possible semantic duplicates |
| official_mcp_registry | duplicate_registry_name | 0 | Staged registry entries repeating a server name (latest versions only, must be 0) |
| official_mcp_registry | entries_sharing_repository_location | 5517 | Registry entries that point to the same repository and subfolder as another entry |
| mcpcorpus | exact_duplicate_records | 2 | Raw corpus records identical to an earlier record |
| mcpcorpus | duplicate_id | 2 | Raw corpus records repeating an earlier id |
| mcpcorpus | records_sharing_repository_location | 1007 | Corpus records that point to the same repository and subdirectory as another record (listed more than once) |
| mcpcorpus | repository_locations_listed_more_than_once | 471 | Distinct repository locations that appear in more than one corpus record |
| cross_source | deepnlp_servers_in_mcp_registry | 18 | DeepNLP servers matched to exactly one MCP Registry entry by repository and subfolder |
| cross_source | deepnlp_servers_with_multiple_registry_matches | 3 | DeepNLP servers matched to several MCP Registry entries (ambiguous, not used for package identity) |
| cross_source | deepnlp_servers_in_mcpcorpus | 166 | DeepNLP servers matched to exactly one MCPCorpus record |
| cross_source | deepnlp_servers_with_multiple_corpus_matches | 27 | DeepNLP servers matched to several MCPCorpus records (the corpus lists the same repository more than once) |

Servers that share a repository were **not** merged. In a monorepo such as `modelcontextprotocol/servers`, each subdirectory is a separate MCP server with its own package, so merging them would be an entity-resolution error. Cross-source matches use the normalized repository identifier (including renamed repositories) and the subdirectory; a server that matches several records in another source is marked `multiple_matches` and is not used to infer anything.

### 4.3 Data quality issues

| dataset | issue | affected_records | pct_of_records | issue_type | handling |
|---|---|---|---|---|---|
| deepnlp | website_trailing_slash | 26 | 8.78 | Format inconsistency | Trailing slash removed in website_normalized |
| deepnlp | website_http_not_https | 1 | 0.34 | Format inconsistency | Flagged; original scheme kept because an HTTPS upgrade was not verified |
| deepnlp | website_url_fragment | 2 | 0.68 | Format inconsistency | Fragment removed in website_normalized |
| deepnlp | website_invalid_url | 0 | 0.0 | Invalid value | Flagged in website_is_valid; record retained |
| deepnlp | website_not_github | 50 | 16.89 | Missing repository reference | No repository identified; record retained and marked not_assessed |
| deepnlp | github_url_with_subdirectory | 31 | 10.47 | Format inconsistency | Owner, repository, ref and subpath parsed into separate columns |
| deepnlp | github_owner_only_url | 1 | 0.34 | Ambiguous reference | Not mapped to any repository |
| deepnlp | description_starts_with_list_marker | 222 | 75.0 | Format inconsistency | Stripped together with other leading punctuation (see strip_leading_list_markers in the cleaning log) |
| deepnlp | description_surrounding_whitespace | 250 | 84.46 | Format inconsistency | Whitespace trimmed |
| deepnlp | description_repeated_internal_whitespace | 23 | 7.77 | Format inconsistency | Repeated whitespace collapsed |
| deepnlp | description_missing_after_cleaning | 9 | 3.04 | Missing value | Empty or punctuation-only descriptions set to null |
| deepnlp | description_web_boilerplate | 8 | 2.7 | Invalid value | Flagged as web_boilerplate (scraped navigation or cookie text) |
| deepnlp | description_fragment | 21 | 7.09 | Invalid value | Flagged as fragment (text cut mid-sentence by the source scraper) |
| deepnlp | description_too_short | 5 | 1.69 | Invalid value | Flagged as too_short (fewer than three words) |
| deepnlp | server_name_generic_link_text | 3 | 1.01 | Invalid value | Flagged; name looks like link text such as 'here' or 'more' |
| deepnlp | month_stored_as_yyyymm_text | 296 | 100.0 | Format inconsistency | Converted to ISO date (first day of month) |
| deepnlp | statistic_empty_nested_object | 246 | 83.11 | Missing value | Flattened into a null bing_rank |
| deepnlp | bing_rank_dominant_value | 49 | 16.55 | Low information | Most common non-null Bing rank is 50.0; kept but not used for scoring |
| official_mcp_registry | entry_without_repository_url | 13703 | 30.01 | Missing value | Cannot be linked to a repository; kept |
| official_mcp_registry | repository_not_on_github | 84 | 0.18 | Missing repository reference | Repository host is not GitHub; kept, not linked |
| official_mcp_registry | entry_without_packages_or_remotes | 505 | 1.11 | Missing value | Entry does not say how the server is installed or reached |
| official_mcp_registry | package_outside_pypi_npm | 3137 | 16.21 | Out of scope | Registry types such as oci, nuget, or mcpb are kept but not checked in Sprint 1 |
| official_mcp_registry | package_with_secret_environment_variable | 7069 | 36.52 | Security metadata | Package expects at least one secret (API key or token) in the environment |
| mcpcorpus | description_missing | 3711 | 26.75 | Missing value | Empty descriptions set to null |
| mcpcorpus | category_missing | 635 | 4.58 | Missing value | Kept as null |
| mcpcorpus | github_metadata_missing | 871 | 6.28 | Missing value | Nested github object is null; repository statistics unavailable |
| mcpcorpus | languages_as_open_ended_object | 13004 | 93.72 | Schema inconsistency | Nested object whose keys are language names (one field path per language); not flattened, primary language kept |
| mcpcorpus | tags_as_json_array_text | 4850 | 34.96 | Format inconsistency | Parsed from JSON text into a '; '-joined list |
| mcpcorpus | tags_as_comma_separated_text | 8784 | 63.32 | Format inconsistency | Split on commas into a '; '-joined list |
| mcpcorpus | tools_missing | 13688 | 98.67 | Missing value | No tool definitions recorded |
| mcpcorpus | tools_invalid_json | 130 | 0.94 | Invalid value | Tool text is not valid JSON; tool_count left null |
| mcpcorpus | url_not_github_repository | 7 | 0.05 | Missing repository reference | Cannot be linked by repository |
| packages | declared_name_invalid | 0 | 0.0 | Invalid value | Declared package name breaks PyPI/npm naming rules |
| packages | declared_version_invalid | 3 | 1.55 | Invalid value | Missing or not a valid PEP 440 / semantic version |
| packages | declared_version_not_published | 49 | 25.39 | Invalid value | Declared version does not exist on the registry; latest version used when the package is verified |
| deepnlp | constant_column_subfield | 296 | 100.0 | Low information | Every record has the value 'MCP SERVER' |
| deepnlp | constant_column_field | 296 | 100.0 | Low information | Every record has the value 'AI AGENT' |
| deepnlp | constant_column_month | 296 | 100.0 | Low information | Every record has the value '202503' |

## 5. Data Wrangling and Preparation

### 5.1 Structured and semi-structured data

The cleaning steps below were applied in order for each inventory. `records_affected` is the number of records changed, flagged, or removed by each step.

| dataset | step | column | records_affected | action |
|---|---|---|---|---|
| deepnlp | normalize_whitespace | server_name | 0 | modified |
| deepnlp | placeholder_to_null | server_name | 0 | modified |
| deepnlp | normalize_whitespace | publisher_id | 0 | modified |
| deepnlp | placeholder_to_null | publisher_id | 0 | modified |
| deepnlp | normalize_whitespace | website_url | 0 | modified |
| deepnlp | placeholder_to_null | website_url | 0 | modified |
| deepnlp | normalize_whitespace | field | 0 | modified |
| deepnlp | placeholder_to_null | field | 0 | modified |
| deepnlp | normalize_whitespace | sub_field | 0 | modified |
| deepnlp | placeholder_to_null | sub_field | 0 | modified |
| deepnlp | normalize_whitespace | snapshot_month | 0 | modified |
| deepnlp | placeholder_to_null | snapshot_month | 0 | modified |
| deepnlp | normalize_whitespace | description | 267 | modified |
| deepnlp | placeholder_to_null | description | 1 | modified |
| deepnlp | normalize_whitespace | content | 0 | modified |
| deepnlp | placeholder_to_null | content | 296 | modified |
| deepnlp | strip_leading_list_markers | description | 236 | modified |
| deepnlp | flag_low_quality_description | description | 43 | flagged |
| deepnlp | drop_empty_column | content | 296 | removed_column |
| deepnlp | normalize_url | website_url | 37 | modified |
| deepnlp | flag_invalid_url | website_url | 0 | flagged |
| deepnlp | extract_github_reference | website_url | 245 | modified |
| deepnlp | flag_ambiguous_github_reference | website_url | 1 | flagged |
| deepnlp | convert_to_date | snapshot_month | 296 | modified |
| deepnlp | flag_invalid_date | snapshot_month | 0 | flagged |
| deepnlp | flag_generic_link_text_name | server_name | 3 | flagged |
| deepnlp | flag_possible_semantic_duplicate | server_name | 4 | flagged |
| deepnlp | remove_exact_duplicate | all | 0 | removed |
| deepnlp | remove_duplicate_server_id | server_id | 0 | removed |
| official_mcp_registry | remove_exact_duplicate | all | 0 | removed |
| official_mcp_registry | remove_duplicate_registry_name | registry_name | 0 | removed |
| official_mcp_registry | normalize_whitespace | title | 2 | modified |
| official_mcp_registry | placeholder_to_null | title | 1 | modified |
| official_mcp_registry | normalize_whitespace | description | 177 | modified |
| official_mcp_registry | placeholder_to_null | description | 0 | modified |
| official_mcp_registry | normalize_whitespace | version | 0 | modified |
| official_mcp_registry | placeholder_to_null | version | 0 | modified |
| official_mcp_registry | normalize_whitespace | website_url | 0 | modified |
| official_mcp_registry | placeholder_to_null | website_url | 0 | modified |
| official_mcp_registry | normalize_whitespace | repository_url | 0 | modified |
| official_mcp_registry | placeholder_to_null | repository_url | 0 | modified |
| official_mcp_registry | extract_github_reference | repository_url | 31870 | modified |
| official_mcp_registry | flag_shared_repository_location | repository_id | 5517 | flagged |
| mcpcorpus | remove_exact_duplicate | all | 2 | removed |
| mcpcorpus | remove_duplicate_id | id | 0 | removed |
| mcpcorpus | normalize_whitespace | name | 8 | modified |
| mcpcorpus | placeholder_to_null | name | 0 | modified |
| mcpcorpus | normalize_whitespace | title | 158 | modified |
| mcpcorpus | placeholder_to_null | title | 0 | modified |
| mcpcorpus | normalize_whitespace | description | 369 | modified |
| mcpcorpus | placeholder_to_null | description | 3129 | modified |
| mcpcorpus | normalize_whitespace | author_name | 0 | modified |
| mcpcorpus | placeholder_to_null | author_name | 12 | modified |
| mcpcorpus | normalize_whitespace | category | 0 | modified |
| mcpcorpus | placeholder_to_null | category | 0 | modified |
| mcpcorpus | normalize_whitespace | type | 0 | modified |
| mcpcorpus | placeholder_to_null | type | 0 | modified |
| mcpcorpus | normalize_whitespace | url | 2 | modified |
| mcpcorpus | placeholder_to_null | url | 0 | modified |
| mcpcorpus | normalize_whitespace | server_command | 3 | modified |
| mcpcorpus | placeholder_to_null | server_command | 4 | modified |
| mcpcorpus | normalize_whitespace | sse_url | 0 | modified |
| mcpcorpus | placeholder_to_null | sse_url | 8 | modified |
| mcpcorpus | parse_mixed_format_tags | tags | 13637 | modified |
| mcpcorpus | parse_json_string_tools | tools | 55 | modified |
| mcpcorpus | cast_to_nullable_integer_and_boolean | github_* | 13002 | modified |
| mcpcorpus | extract_github_reference | url | 13866 | modified |
| mcpcorpus | flag_shared_repository_location | repository_id | 1007 | flagged |

In DeepNLP, 296 records were retained, 0 were removed, and 48 retained records carry at least one quality flag. No record was dropped just because it was incomplete; incomplete records are kept and labelled so that later sprints can decide how to use them.

### 5.2 Unstructured text

For every mapped server location the pipeline collected the README; for every retrieved repository it collected the latest release notes and the 10 most recently updated issues. Text cleaning removed HTML, badges, image and link markup, markdown syntax, and extra whitespace while keeping code and configuration text. Metadata generation stored the server or repository id, document type, source URL, publication date, collection time, and character/word counts with each document. Document filtering removed pull requests (the GitHub issues endpoint also returns them), bot-authored issues, and documents that were empty or shorter than 20 characters after cleaning.

| document_type | filter_reason | documents |
|---|---|---|
| issue | bot_author | 4 |
| issue | empty_or_too_short | 15 |
| issue | kept | 628 |
| issue | pull_request | 1258 |
| readme | kept | 224 |
| readme | not_available | 1 |
| release_notes | empty_or_too_short | 7 |
| release_notes | kept | 93 |

Median length of kept documents (raw characters → cleaned characters, and words):

| document_type | raw_char_count | cleaned_char_count | word_count |
|---|---|---|---|
| issue | 863 | 679 | 104 |
| readme | 5688 | 4486 | 610 |
| release_notes | 604 | 554 | 49 |

## 6. API Enrichment Results

### 6.1 GitHub

| github_status | servers |
|---|---|
| mapped | 225 |
| not_github | 50 |
| subpath_not_found | 15 |
| repository_not_found | 5 |
| ambiguous_owner_only_url | 1 |

Of the 227 unique repositories, 222 (97.8%) were retrieved successfully, 5 returned 404 (deleted, renamed without redirect, or private) and 0 failed. 21 repositories now live under a different owner/name than the URL in the dataset, and 19 are archived. 15 servers point to a subdirectory that no longer exists in the repository, which shows that the March 2025 snapshot has become partly stale.

Activity data (commits, contributors, releases) was collected for the retrieved repositories. The median repository has 104 stars, 45 commits, 4 contributors and 0 releases; the median time since the last commit is 310 days.

| metric | value | denominator | pct |
|---|---|---|---|
| servers_with_github_repository_url | 245 | 296 | 82.77 |
| servers_with_owner_only_github_url | 1 | 296 | 0.34 |
| servers_without_github_url | 50 | 296 | 16.89 |
| unique_repositories_identified | 227 |  |  |
| repository_lookups_succeeded | 222 | 227 | 97.8 |
| repository_lookups_not_found | 5 | 227 | 2.2 |
| repository_lookups_failed | 0 | 227 | 0.0 |
| repositories_moved_or_renamed | 21 | 227 | 9.25 |
| repositories_archived | 19 | 227 | 8.37 |
| repositories_with_commit_history | 222 | 222 | 100.0 |
| repositories_with_contributor_count | 222 | 222 | 100.0 |
| repositories_with_at_least_one_release | 100 | 222 | 45.05 |
| repositories_without_commit_in_last_year | 103 | 222 | 46.4 |
| repositories_with_single_contributor | 29 | 222 | 13.06 |
| servers_mapped_to_repository_location | 225 | 296 | 76.01 |
| servers_subpath_not_found | 15 | 296 | 5.07 |
| servers_repository_not_found | 5 | 296 | 1.69 |
| servers_with_supported_manifest | 201 | 225 | 89.33 |
| servers_with_only_unsupported_manifests | 12 | 225 | 5.33 |

Most common primary languages:

| primary_language | repositories |
|---|---|
| Python | 89 |
| TypeScript | 71 |
| JavaScript | 37 |
| Go | 9 |
| Rust | 4 |
| Java | 3 |
| (not reported) | 3 |
| C# | 2 |

### 6.2 Linking the inventories

| metric | value | denominator | pct |
|---|---|---|---|
| mcp_registry_servers | 45657 |  |  |
| mcp_registry_servers_with_github_repository | 31870 | 45657 | 69.8 |
| mcp_registry_packages | 19358 |  |  |
| mcp_registry_packages_npm | 11669 | 19358 | 60.28 |
| mcp_registry_packages_pypi | 4552 | 19358 | 23.51 |
| mcpcorpus_records_retained | 13873 |  |  |
| mcpcorpus_records_with_github_repository | 13866 | 13873 | 99.95 |
| mcpcorpus_records_with_category | 13238 | 13873 | 95.42 |
| servers_matched_in_mcp_registry | 18 | 296 | 6.08 |
| servers_matched_in_mcpcorpus | 166 | 296 | 56.08 |
| servers_with_corpus_category | 182 | 296 | 61.49 |

Categories of the DeepNLP servers that were found in MCPCorpus:

| corpus_category | servers |
|---|---|
| developer-tools | 101 |
| research-and-data | 61 |
| browser-automation | 3 |
| knowledge-and-memory | 3 |
| cloud-platforms | 3 |
| databases | 2 |
| location-services | 1 |
| monitoring | 1 |
| ai-chatbot | 1 |
| finance | 1 |
| communication | 1 |
| os-automation | 1 |
| cloud-storage | 1 |
| file-systems | 1 |
| travel-and-transportation | 1 |

### 6.3 PyPI and npm

A package is linked to a server only when its identity is backed by evidence: either the server's Official MCP Registry entry lists the package (the registry checks that the publisher controls it), or a manifest in the server's repository location declares the name and the registry metadata links back to the same GitHub repository. Packages that exist but do not link back are recorded as `ambiguous` and are not treated as the server's package.

| metric | value | denominator | pct |
|---|---|---|---|
| python_package_candidates | 88 |  |  |
| npm_package_candidates | 105 |  |  |
| candidates_from_repository_manifests | 180 | 193 | 93.26 |
| candidates_from_mcp_registry | 13 | 193 | 6.74 |
| unique_python_packages_looked_up | 88 |  |  |
| unique_npm_packages_looked_up | 105 |  |  |
| registry_lookups_found | 167 | 193 | 86.53 |
| registry_lookups_not_found | 26 | 193 | 13.47 |
| registry_lookups_failed | 0 | 193 | 0.0 |
| mappings_verified | 89 | 193 | 46.11 |
| mappings_verified_by_mcp_registry | 13 | 89 | 14.61 |
| mappings_verified_python | 33 | 193 | 17.1 |
| mappings_verified_npm | 56 | 193 | 29.02 |
| mappings_ambiguous | 78 | 193 | 40.41 |
| mappings_not_published | 26 | 193 | 13.47 |
| mappings_lookup_failed | 0 | 193 | 0.0 |
| verified_versions_from_declaration | 84 | 89 | 94.38 |
| verified_versions_from_registry_latest | 5 | 89 | 5.62 |
| servers_with_verified_package | 88 | 296 | 29.73 |
| mapped_servers_with_verified_package | 88 | 225 | 39.11 |

### 6.4 Dependency analysis (manifests and deps.dev)

Declared dependencies come from the manifests. Most use version ranges, so the installed version is unknown. For every verified package version, deps.dev returned the resolved dependency graph (direct and indirect dependencies with exact versions), which can be checked against OSV.dev.

| metric | value | denominator | pct |
|---|---|---|---|
| declared_dependency_rows | 1202 |  |  |
| unparseable_dependency_rows | 0 | 1202 | 0.0 |
| unique_declared_dependencies | 471 |  |  |
| pinned_dependency_rows | 202 | 1202 | 16.81 |
| unique_pinned_dependency_versions | 163 |  |  |
| servers_with_declared_dependencies | 194 | 225 | 86.22 |
| deps_dev_graph_lookups | 89 |  |  |
| deps_dev_graphs_found | 87 | 89 | 97.75 |
| deps_dev_graphs_not_found | 2 | 89 | 2.25 |
| deps_dev_graphs_failed | 0 | 89 | 0.0 |
| resolved_dependency_rows | 7961 |  |  |
| resolved_direct_dependency_rows | 488 | 7961 | 6.13 |
| resolved_indirect_dependency_rows | 7473 | 7961 | 93.87 |
| unique_resolved_dependency_versions | 1626 |  |  |

### 6.5 OSV.dev vulnerability intelligence

OSV.dev was queried for every verified server package (at its identified version), every dependency pinned to an exact version in a manifest, and every dependency version resolved by deps.dev.

| metric | value | denominator | pct |
|---|---|---|---|
| osv_targets_queried | 1818 |  |  |
| osv_queries_completed | 1818 | 1818 | 100.0 |
| osv_queries_failed | 0 | 1818 | 0.0 |
| osv_targets_with_known_vulnerabilities | 80 | 1818 | 4.4 |
| osv_targets_with_no_known_vulnerabilities | 1738 | 1818 | 95.6 |
| package_rows_skipped | 104 | 193 | 53.89 |
| dependency_rows_skipped_unknown_version | 1000 | 1202 | 83.19 |
| resolved_dependency_rows_with_known_vulnerabilities | 68 | 7961 | 0.85 |
| unique_osv_vulnerability_records | 292 |  |  |
| unique_vulnerabilities_after_alias_grouping | 174 |  |  |
| osv_records_with_cve_alias | 282 | 292 | 96.58 |
| vulnerability_detail_lookups_failed | 0 | 292 | 0.0 |

Severity labels of unique vulnerabilities (from the GitHub Advisory `database_specific.severity` field where present):

| severity_label | vulnerabilities |
|---|---|
| MODERATE | 69 |
| HIGH | 58 |
| LOW | 27 |
| (not provided) | 13 |
| CRITICAL | 7 |

Package versions with the most known vulnerabilities:

| ecosystem | package_name | package_version | unique_vulnerabilities |
|---|---|---|---|
| PyPI | aiohttp | 3.8.5 | 42 |
| PyPI | aiohttp | 3.11.11 | 33 |
| PyPI | aiohttp | 3.11.15 | 33 |
| PyPI | pillow | 10.4.0 | 17 |
| PyPI | transformers | 4.53.3 | 13 |
| npm | undici | 5.29.0 | 13 |
| PyPI | urllib3 | 2.4.0 | 8 |
| PyPI | fastmcp | 2.8.0 | 8 |
| PyPI | starlette | 0.45.2 | 7 |
| PyPI | starlette | 0.46.2 | 7 |

### 6.6 Server-level assessment status

Each server gets two statuses. `package_vulnerability_status` looks only at the server's own PyPI/npm package. `vulnerability_assessment_status` combines the package and its dependencies and reports the most informative status in this order: `known_vulnerabilities_found` > `api_failed` > `no_known_vulnerabilities_found` > `unknown_version` > `ambiguous_mapping` > `unknown_package_identity` > `not_assessed`. For example, a server whose package is ambiguous and whose dependencies only use version ranges has the package status `ambiguous_mapping` but the overall status `unknown_version`.

Status of the server's own package:

| package_vulnerability_status | servers |
|---|---|
| no_known_vulnerabilities_found | 87 |
| ambiguous_mapping | 76 |
| not_assessed | 71 |
| unknown_package_identity | 61 |
| known_vulnerabilities_found | 1 |

Overall status (package and dependencies):

| vulnerability_assessment_status | servers |
|---|---|
| unknown_version | 79 |
| not_assessed | 71 |
| no_known_vulnerabilities_found | 62 |
| known_vulnerabilities_found | 57 |
| unknown_package_identity | 26 |
| ambiguous_mapping | 1 |

What was actually checked against OSV.dev:

| assessment_scope | servers |
|---|---|
| none | 177 |
| package_and_dependencies | 83 |
| dependencies_only | 31 |
| package_only | 5 |

**A missing vulnerability result does not mean a server is secure.** Only `no_known_vulnerabilities_found` means that OSV.dev was actually queried and returned nothing; every other non-vulnerable status means the assessment could not be completed. `known_vulnerability_count` is left null (not zero) for servers that were never successfully assessed.

## 7. Processed Data Summary

| layer | file | rows | columns |
|---|---|---|---|
| staging | data/staging/mcp_servers.csv | 296 | 29 |
| staging | data/staging/repositories.csv | 227 | 32 |
| staging | data/staging/server_repository_map.csv | 245 | 11 |
| staging | data/staging/documents.csv | 2230 | 14 |
| staging | data/staging/packages.csv | 193 | 13 |
| staging | data/staging/server_package_map.csv | 193 | 21 |
| staging | data/staging/dependencies.csv | 1202 | 13 |
| staging | data/staging/resolved_dependencies.csv | 7961 | 12 |
| staging | data/staging/vulnerabilities.csv | 292 | 14 |
| staging | data/staging/package_vulnerability_map.csv | 532 | 8 |
| staging | data/staging/mcp_registry_servers.csv | 45657 | 17 |
| staging | data/staging/mcp_registry_packages.csv | 19358 | 12 |
| staging | data/staging/mcpcorpus_servers.csv | 13873 | 34 |
| staging | data/staging/server_source_map.csv | 251 | 7 |
| processed | data/processed/mcp_servers_enriched.csv | 296 | 70 |

## 8. Challenges and Limitations

- 50 DeepNLP records only provide a marketing website, so no repository, package, or vulnerability information could be derived for them.
- 12 mapped servers only contain manifests for ecosystems outside the Sprint 1 scope (for example Go, Rust, or Java).
- 78 declared packages exist on a registry but do not link back to the server repository, so they were not trusted.
- 1000 declared dependencies use version ranges. deps.dev resolves them only for verified packages, and its resolution reflects a fresh install today, not necessarily what an existing user has installed.
- The Official MCP Registry and the GitHub, registry, and OSV data are live, while DeepNLP and MCPCorpus are snapshots; their contents differ in time.
- MCPCorpus and the MCP Registry were profiled and linked, but their servers were not enriched one by one; that would need far more API requests than Sprint 1 allows.
- OSV.dev only covers publicly disclosed vulnerabilities. MCP-specific risks such as tool poisoning or excessive permissions are not covered.

## 9. Sprint 2 Preparation

The staging CSV files are designed to be loaded with PostgreSQL `COPY`. Candidate keys are documented in `docs/data_dictionary.md`: `mcp_servers.server_id`, `repositories.repository_id`, `packages.package_id`, `vulnerabilities.vulnerability_id`, `documents.document_id`, `mcp_registry_servers.registry_name`, and `mcpcorpus_servers.corpus_id` are primary keys, while the `*_map` tables, `dependencies`, and `resolved_dependencies` hold the foreign keys that connect them.
