import pandas as pd

from src.etl import ASSESSED_STATUSES, ISSUES_PER_REPOSITORY, NULL_PLACEHOLDERS, SERVER_COLUMNS, utc_now

SKIPPED_STATUSES = ["unknown_version", "ambiguous_mapping", "unknown_package_identity", "not_assessed"]


def percent(value, denominator):
    return round(100 * value / denominator, 2) if denominator else None


def profile_columns(frame, dataset, stage):
    rows = []
    for column in frame.columns:
        values = frame[column]
        nulls = int(values.isna().sum())
        blanks = int(values.map(lambda value: isinstance(value, str) and value.strip().lower() in NULL_PLACEHOLDERS).sum())
        rows.append({
            "dataset": dataset, "stage": stage, "column": column, "dtype": str(values.dtype), "records": len(frame),
            "null_count": nulls, "blank_or_placeholder_count": blanks, "missing_count": nulls + blanks,
            "missing_pct": percent(nulls + blanks, len(frame)),
            "distinct_values": int(values.astype(str).where(values.notna()).nunique()),
        })
    return pd.DataFrame(rows)


def missing_comparison(before, after):
    after_by_column = after.set_index("column")
    rows = []
    for row in before.itertuples(index=False):
        cleaned = SERVER_COLUMNS.get(row.column, row.column)
        present = cleaned in after_by_column.index
        rows.append({
            "source_column": row.column, "staging_column": cleaned if present else "(dropped)",
            "missing_before": row.missing_count, "missing_before_pct": row.missing_pct,
            "missing_after": int(after_by_column.loc[cleaned, "missing_count"]) if present else None,
            "missing_after_pct": after_by_column.loc[cleaned, "missing_pct"] if present else None,
        })
    frame = pd.DataFrame(rows)
    frame["missing_after"] = frame["missing_after"].astype("Int64")
    return frame


def combine_logs(logs):
    columns = ["dataset", "step", "column", "records_affected", "action"]
    return pd.concat([log.assign(dataset=name)[columns] for name, log in logs.items()], ignore_index=True)


def combine_schemas(frames):
    return pd.concat(frames, ignore_index=True)


def duplicate_summary(raw_frame, corpus_records, tables):
    servers, registry, corpus, links = tables["mcp_servers"], tables["mcp_registry_servers"], tables["mcpcorpus_servers"], tables["server_source_map"]
    content = raw_frame.drop(columns=["source_file", "source_record_number"], errors="ignore").astype(str)
    located = servers.dropna(subset=["repository_id"])
    shared = located["repository_id"].duplicated(keep=False)
    corpus_raw = pd.Series([str(sorted(record.items())) for record in corpus_records])
    corpus_ids = pd.Series([record.get("id") for record in corpus_records])

    def matched(source, status):
        return links[(links["linked_source"] == source) & (links["match_status"] == status)]["server_id"].nunique()

    checks = [
        ("deepnlp", "exact_duplicate_records", content.duplicated().sum(), "Raw records identical to an earlier record in every source field"),
        ("deepnlp", "duplicate_publisher_id", raw_frame["publisher_id"].duplicated().sum(), "Records repeating an earlier publisher_id"),
        ("deepnlp", "duplicate_server_name", raw_frame["content_name"].duplicated().sum(), "Records repeating an earlier content_name exactly"),
        ("deepnlp", "duplicate_server_name_case_insensitive", raw_frame["content_name"].str.strip().str.lower().duplicated().sum(), "Records repeating an earlier content_name after trimming and lowercasing"),
        ("deepnlp", "duplicate_website_raw", raw_frame["website"].duplicated().sum(), "Records repeating an earlier website string exactly"),
        ("deepnlp", "duplicate_website_normalized", servers["website_normalized"].dropna().duplicated().sum(), "Records repeating an earlier website after URL normalization"),
        ("deepnlp", "duplicate_server_id", servers["server_id"].duplicated().sum(), "Staged records repeating a server_id (must be 0)"),
        ("deepnlp", "duplicate_repository_location", located.duplicated(["repository_id", "github_subpath"]).sum(), "Servers pointing to the same repository and the same subdirectory"),
        ("deepnlp", "servers_sharing_a_repository", shared.sum(), "Servers whose GitHub repository is shared with at least one other server (monorepo pattern, not duplicates)"),
        ("deepnlp", "repositories_shared_by_multiple_servers", located.loc[shared, "repository_id"].nunique(), "Distinct repositories referenced by more than one server"),
        ("deepnlp", "possible_semantic_duplicate_records", servers["possible_duplicate_group"].notna().sum(), "Records flagged because their normalized name or normalized website matches another record"),
        ("deepnlp", "possible_semantic_duplicate_groups", servers["possible_duplicate_group"].nunique(), "Distinct groups of possible semantic duplicates"),
        ("official_mcp_registry", "duplicate_registry_name", registry["registry_name"].duplicated().sum(), "Staged registry entries repeating a server name (latest versions only, must be 0)"),
        ("official_mcp_registry", "entries_sharing_repository_location", registry["shares_repository_location"].sum(), "Registry entries that point to the same repository and subfolder as another entry"),
        ("mcpcorpus", "exact_duplicate_records", corpus_raw.duplicated().sum(), "Raw corpus records identical to an earlier record"),
        ("mcpcorpus", "duplicate_id", corpus_ids.duplicated().sum(), "Raw corpus records repeating an earlier id"),
        ("mcpcorpus", "records_sharing_repository_location", corpus["shares_repository_location"].sum(), "Corpus records that point to the same repository and subdirectory as another record (listed more than once)"),
        ("mcpcorpus", "repository_locations_listed_more_than_once", corpus.loc[corpus["shares_repository_location"]].drop_duplicates(["repository_id", "github_subpath"]).shape[0], "Distinct repository locations that appear in more than one corpus record"),
        ("cross_source", "deepnlp_servers_in_mcp_registry", matched("official_mcp_registry", "matched"), "DeepNLP servers matched to exactly one MCP Registry entry by repository and subfolder"),
        ("cross_source", "deepnlp_servers_with_multiple_registry_matches", matched("official_mcp_registry", "multiple_matches"), "DeepNLP servers matched to several MCP Registry entries (ambiguous, not used for package identity)"),
        ("cross_source", "deepnlp_servers_in_mcpcorpus", matched("mcpcorpus", "matched"), "DeepNLP servers matched to exactly one MCPCorpus record"),
        ("cross_source", "deepnlp_servers_with_multiple_corpus_matches", matched("mcpcorpus", "multiple_matches"), "DeepNLP servers matched to several MCPCorpus records (the corpus lists the same repository more than once)"),
    ]
    return pd.DataFrame([{"dataset": s, "check": c, "count": int(v), "description": d} for s, c, v, d in checks])


def quality_issues(records, corpus_records, raw_frame, tables):
    servers, registry, registry_packages = tables["mcp_servers"], tables["mcp_registry_servers"], tables["mcp_registry_packages"]
    corpus, server_packages = tables["mcpcorpus_servers"], tables["server_package_map"]
    website = raw_frame["website"].astype(str)
    description = raw_frame["description"].astype(str)
    quality = servers["description_quality"].value_counts()
    bing = servers["bing_rank"].dropna()
    corpus_github = [record["github"] for record in corpus_records if isinstance(record.get("github"), dict)]
    tag_formats = corpus["tag_format"].value_counts()
    issues = [
        ("deepnlp", "website_trailing_slash", website.str.strip().str.endswith("/").sum(), len(raw_frame), "Format inconsistency", "Trailing slash removed in website_normalized"),
        ("deepnlp", "website_http_not_https", website.str.strip().str.startswith("http://").sum(), len(raw_frame), "Format inconsistency", "Flagged; original scheme kept because an HTTPS upgrade was not verified"),
        ("deepnlp", "website_url_fragment", website.str.contains("#", regex=False).sum(), len(raw_frame), "Format inconsistency", "Fragment removed in website_normalized"),
        ("deepnlp", "website_invalid_url", (~servers["website_is_valid"]).sum(), len(raw_frame), "Invalid value", "Flagged in website_is_valid; record retained"),
        ("deepnlp", "website_not_github", (servers["github_url_type"] == "not_github").sum(), len(raw_frame), "Missing repository reference", "No repository identified; record retained and marked not_assessed"),
        ("deepnlp", "github_url_with_subdirectory", (servers["github_url_type"] == "repository_subpath").sum(), len(raw_frame), "Format inconsistency", "Owner, repository, ref and subpath parsed into separate columns"),
        ("deepnlp", "github_owner_only_url", (servers["github_url_type"] == "owner_only").sum(), len(raw_frame), "Ambiguous reference", "Not mapped to any repository"),
        ("deepnlp", "description_starts_with_list_marker", description.str.match(r"^\s*[-–—:]").sum(), len(raw_frame), "Format inconsistency", "Stripped together with other leading punctuation (see strip_leading_list_markers in the cleaning log)"),
        ("deepnlp", "description_surrounding_whitespace", (description != description.str.strip()).sum(), len(raw_frame), "Format inconsistency", "Whitespace trimmed"),
        ("deepnlp", "description_repeated_internal_whitespace", description.str.strip().str.contains(r"\s{2,}").sum(), len(raw_frame), "Format inconsistency", "Repeated whitespace collapsed"),
        ("deepnlp", "description_missing_after_cleaning", quality.get("missing", 0), len(raw_frame), "Missing value", "Empty or punctuation-only descriptions set to null"),
        ("deepnlp", "description_web_boilerplate", quality.get("web_boilerplate", 0), len(raw_frame), "Invalid value", "Flagged as web_boilerplate (scraped navigation or cookie text)"),
        ("deepnlp", "description_fragment", quality.get("fragment", 0), len(raw_frame), "Invalid value", "Flagged as fragment (text cut mid-sentence by the source scraper)"),
        ("deepnlp", "description_too_short", quality.get("too_short", 0), len(raw_frame), "Invalid value", "Flagged as too_short (fewer than three words)"),
        ("deepnlp", "server_name_generic_link_text", servers["server_name_is_generic"].sum(), len(raw_frame), "Invalid value", "Flagged; name looks like link text such as 'here' or 'more'"),
        ("deepnlp", "month_stored_as_yyyymm_text", raw_frame["month"].astype(str).str.fullmatch(r"\d{6}").sum(), len(raw_frame), "Format inconsistency", "Converted to ISO date (first day of month)"),
        ("deepnlp", "statistic_empty_nested_object", sum(1 for record in records if record.get("statistic") == {}), len(raw_frame), "Missing value", "Flattened into a null bing_rank"),
        ("deepnlp", "bing_rank_dominant_value", int(bing.value_counts().iloc[0]) if len(bing) else 0, len(raw_frame), "Low information", f"Most common non-null Bing rank is {bing.mode().iloc[0] if len(bing) else 'n/a'}; kept but not used for scoring"),
        ("official_mcp_registry", "entry_without_repository_url", registry["repository_url"].isna().sum(), len(registry), "Missing value", "Cannot be linked to a repository; kept"),
        ("official_mcp_registry", "repository_not_on_github", (registry["repository_url"].notna() & registry["repository_id"].isna()).sum(), len(registry), "Missing repository reference", "Repository host is not GitHub; kept, not linked"),
        ("official_mcp_registry", "entry_without_packages_or_remotes", ((registry["package_count"] == 0) & (registry["remote_count"] == 0)).sum(), len(registry), "Missing value", "Entry does not say how the server is installed or reached"),
        ("official_mcp_registry", "package_outside_pypi_npm", registry_packages["ecosystem"].isna().sum(), len(registry_packages), "Out of scope", "Registry types such as oci, nuget, or mcpb are kept but not checked in Sprint 1"),
        ("official_mcp_registry", "package_with_secret_environment_variable", (registry_packages["secret_environment_variable_count"] > 0).sum(), len(registry_packages), "Security metadata", "Package expects at least one secret (API key or token) in the environment"),
        ("mcpcorpus", "description_missing", corpus["description"].isna().sum(), len(corpus), "Missing value", "Empty descriptions set to null"),
        ("mcpcorpus", "category_missing", corpus["category"].isna().sum(), len(corpus), "Missing value", "Kept as null"),
        ("mcpcorpus", "github_metadata_missing", corpus["github_full_name"].isna().sum(), len(corpus), "Missing value", "Nested github object is null; repository statistics unavailable"),
        ("mcpcorpus", "languages_as_open_ended_object", sum(isinstance(g.get("languages"), dict) for g in corpus_github), len(corpus_records), "Schema inconsistency", "Nested object whose keys are language names (one field path per language); not flattened, primary language kept"),
        ("mcpcorpus", "tags_as_json_array_text", tag_formats.get("json_array", 0), len(corpus), "Format inconsistency", "Parsed from JSON text into a '; '-joined list"),
        ("mcpcorpus", "tags_as_comma_separated_text", tag_formats.get("comma_separated", 0), len(corpus), "Format inconsistency", "Split on commas into a '; '-joined list"),
        ("mcpcorpus", "tools_missing", (corpus["tool_format"] == "missing").sum(), len(corpus), "Missing value", "No tool definitions recorded"),
        ("mcpcorpus", "tools_invalid_json", (corpus["tool_format"] == "invalid_json").sum(), len(corpus), "Invalid value", "Tool text is not valid JSON; tool_count left null"),
        ("mcpcorpus", "url_not_github_repository", corpus["repository_id"].isna().sum(), len(corpus), "Missing repository reference", "Cannot be linked by repository"),
        ("packages", "declared_name_invalid", (~server_packages["declared_name_is_valid"]).sum(), len(server_packages), "Invalid value", "Declared package name breaks PyPI/npm naming rules"),
        ("packages", "declared_version_invalid", (~server_packages["declared_version_is_valid"]).sum(), len(server_packages), "Invalid value", "Missing or not a valid PEP 440 / semantic version"),
        ("packages", "declared_version_not_published", (~server_packages["declared_version_is_published"]).sum(), len(server_packages), "Invalid value", "Declared version does not exist on the registry; latest version used when the package is verified"),
    ]
    for column in [c for c in raw_frame.columns if c not in ("source_file", "source_record_number")]:
        values = raw_frame[column].astype(str).where(raw_frame[column].notna())
        if values.nunique() == 1 and len(raw_frame) > 1 and values.dropna().iloc[0].strip():
            issues.append(("deepnlp", f"constant_column_{column}", len(raw_frame), len(raw_frame), "Low information", f"Every record has the value '{values.dropna().iloc[0]}'"))
    rows = [
        {"dataset": s, "issue": i, "affected_records": int(n), "pct_of_records": percent(int(n), total), "issue_type": t, "handling": h}
        for s, i, n, total, t, h in issues
    ]
    return pd.DataFrame(rows)


def enrichment_summary(tables, osv_results):
    servers, repositories = tables["mcp_servers_enriched"], tables["repositories"]
    links, packages, dependencies = tables["server_package_map"], tables["packages"], tables["dependencies"]
    resolved, vulnerabilities, documents = tables["resolved_dependencies"], tables["vulnerabilities"], tables["documents"]
    registry, registry_packages, corpus, source_map = tables["mcp_registry_servers"], tables["mcp_registry_packages"], tables["mcpcorpus_servers"], tables["server_source_map"]
    total = len(servers)
    mapped = int((servers["github_status"] == "mapped").sum())
    found = repositories[repositories["lookup_status"] == "found"]
    target_statuses = pd.Series([value["osv_status"] for value in osv_results.values()], dtype="object")
    verified = links[links["mapping_status"] == "verified"]
    pinned = dependencies.dropna(subset=["pinned_version", "dependency_name"])
    graphs = links.dropna(subset=["dependency_graph_status"]).drop_duplicates(["ecosystem", "package_name", "identified_version"])
    kept = documents[documents["filter_reason"].isna()]

    def matched(source):
        return source_map[(source_map["linked_source"] == source) & (source_map["match_status"] == "matched")]["server_id"].nunique()

    metrics = [
        ("dataset", "mcp_server_records", total, None),
        ("github", "servers_with_github_repository_url", servers["repository_id"].notna().sum(), total),
        ("github", "servers_with_owner_only_github_url", (servers["github_url_type"] == "owner_only").sum(), total),
        ("github", "servers_without_github_url", (servers["github_url_type"] == "not_github").sum(), total),
        ("github", "unique_repositories_identified", len(repositories), None),
        ("github", "repository_lookups_succeeded", len(found), len(repositories)),
        ("github", "repository_lookups_not_found", (repositories["lookup_status"] == "not_found").sum(), len(repositories)),
        ("github", "repository_lookups_failed", (repositories["lookup_status"] == "lookup_failed").sum(), len(repositories)),
        ("github", "repositories_moved_or_renamed", int(repositories["repository_moved"].sum()), len(repositories)),
        ("github", "repositories_archived", int(repositories["archived"].sum()), len(repositories)),
        ("github", "repositories_with_commit_history", found["commit_count"].notna().sum(), len(found)),
        ("github", "repositories_with_contributor_count", found["contributor_count"].notna().sum(), len(found)),
        ("github", "repositories_with_at_least_one_release", (found["release_count"].fillna(0) > 0).sum(), len(found)),
        ("github", "repositories_without_commit_in_last_year", (found["days_since_last_commit"] > 365).sum(), len(found)),
        ("github", "repositories_with_single_contributor", (found["contributor_count"] == 1).sum(), len(found)),
        ("github", "servers_mapped_to_repository_location", mapped, total),
        ("github", "servers_subpath_not_found", (servers["github_status"] == "subpath_not_found").sum(), total),
        ("github", "servers_repository_not_found", (servers["github_status"] == "repository_not_found").sum(), total),
        ("github", "servers_with_supported_manifest", servers["manifest_files"].notna().sum(), mapped),
        ("github", "servers_with_only_unsupported_manifests", (servers["manifest_files"].isna() & servers["unsupported_manifest_files"].notna()).sum(), mapped),
        ("documents", "documents_collected", len(documents), None),
        ("documents", "readme_documents", (documents["document_type"] == "readme").sum(), mapped),
        ("documents", "readmes_not_available", (documents["filter_reason"] == "not_available").sum(), mapped),
        ("documents", "release_note_documents", (documents["document_type"] == "release_notes").sum(), None),
        ("documents", "issue_documents", (documents["document_type"] == "issue").sum(), None),
        ("documents", "filtered_pull_requests", (documents["filter_reason"] == "pull_request").sum(), len(documents)),
        ("documents", "filtered_bot_authored", (documents["filter_reason"] == "bot_author").sum(), len(documents)),
        ("documents", "filtered_empty_or_too_short", (documents["filter_reason"] == "empty_or_too_short").sum(), len(documents)),
        ("documents", "documents_kept_after_filtering", len(kept), len(documents)),
        ("documents", "words_in_kept_documents", int(kept["word_count"].sum()), None),
        ("sources", "mcp_registry_servers", len(registry), None),
        ("sources", "mcp_registry_servers_with_github_repository", registry["repository_id"].notna().sum(), len(registry)),
        ("sources", "mcp_registry_packages", len(registry_packages), None),
        ("sources", "mcp_registry_packages_npm", (registry_packages["ecosystem"] == "npm").sum(), len(registry_packages)),
        ("sources", "mcp_registry_packages_pypi", (registry_packages["ecosystem"] == "PyPI").sum(), len(registry_packages)),
        ("sources", "mcpcorpus_records_retained", len(corpus), None),
        ("sources", "mcpcorpus_records_with_github_repository", corpus["repository_id"].notna().sum(), len(corpus)),
        ("sources", "mcpcorpus_records_with_category", corpus["category"].notna().sum(), len(corpus)),
        ("sources", "servers_matched_in_mcp_registry", matched("official_mcp_registry"), total),
        ("sources", "servers_matched_in_mcpcorpus", matched("mcpcorpus"), total),
        ("sources", "servers_with_corpus_category", servers["corpus_category"].notna().sum(), total),
        ("packages", "python_package_candidates", (links["ecosystem"] == "PyPI").sum(), None),
        ("packages", "npm_package_candidates", (links["ecosystem"] == "npm").sum(), None),
        ("packages", "candidates_from_repository_manifests", (links["candidate_source"] == "repository_manifest").sum(), len(links)),
        ("packages", "candidates_from_mcp_registry", (links["candidate_source"] == "official_mcp_registry").sum(), len(links)),
        ("packages", "unique_python_packages_looked_up", (packages["ecosystem"] == "PyPI").sum(), None),
        ("packages", "unique_npm_packages_looked_up", (packages["ecosystem"] == "npm").sum(), None),
        ("packages", "registry_lookups_found", (packages["registry_status"] == "found").sum(), len(packages)),
        ("packages", "registry_lookups_not_found", (packages["registry_status"] == "not_found").sum(), len(packages)),
        ("packages", "registry_lookups_failed", (packages["registry_status"] == "lookup_failed").sum(), len(packages)),
        ("packages", "mappings_verified", len(verified), len(links)),
        ("packages", "mappings_verified_by_mcp_registry", (verified["mapping_evidence"] == "official_mcp_registry_lists_package").sum(), len(verified)),
        ("packages", "mappings_verified_python", (verified["ecosystem"] == "PyPI").sum(), len(links)),
        ("packages", "mappings_verified_npm", (verified["ecosystem"] == "npm").sum(), len(links)),
        ("packages", "mappings_ambiguous", (links["mapping_status"] == "ambiguous").sum(), len(links)),
        ("packages", "mappings_not_published", (links["mapping_status"] == "not_published").sum(), len(links)),
        ("packages", "mappings_lookup_failed", (links["mapping_status"] == "lookup_failed").sum(), len(links)),
        ("packages", "verified_versions_from_declaration", verified["version_source"].isin(["repository_manifest", "official_mcp_registry"]).sum(), len(verified)),
        ("packages", "verified_versions_from_registry_latest", (verified["version_source"] == "registry_latest").sum(), len(verified)),
        ("packages", "servers_with_verified_package", verified["server_id"].nunique(), total),
        ("packages", "mapped_servers_with_verified_package", verified["server_id"].nunique(), mapped),
        ("dependencies", "declared_dependency_rows", len(dependencies), None),
        ("dependencies", "unparseable_dependency_rows", dependencies["dependency_name"].isna().sum(), len(dependencies)),
        ("dependencies", "unique_declared_dependencies", dependencies.dropna(subset=["dependency_name"]).drop_duplicates(["ecosystem", "dependency_name"]).shape[0], None),
        ("dependencies", "pinned_dependency_rows", len(pinned), len(dependencies)),
        ("dependencies", "unique_pinned_dependency_versions", pinned.drop_duplicates(["ecosystem", "dependency_name", "pinned_version"]).shape[0], None),
        ("dependencies", "servers_with_declared_dependencies", dependencies["server_id"].nunique(), mapped),
        ("dependencies", "deps_dev_graph_lookups", len(graphs), None),
        ("dependencies", "deps_dev_graphs_found", (graphs["dependency_graph_status"] == "found").sum(), len(graphs)),
        ("dependencies", "deps_dev_graphs_not_found", (graphs["dependency_graph_status"] == "not_found").sum(), len(graphs)),
        ("dependencies", "deps_dev_graphs_failed", (graphs["dependency_graph_status"] == "lookup_failed").sum(), len(graphs)),
        ("dependencies", "resolved_dependency_rows", len(resolved), None),
        ("dependencies", "resolved_direct_dependency_rows", (resolved["relation"] == "direct").sum(), len(resolved)),
        ("dependencies", "resolved_indirect_dependency_rows", (resolved["relation"] == "indirect").sum(), len(resolved)),
        ("dependencies", "unique_resolved_dependency_versions", resolved.drop_duplicates(["dependency_ecosystem", "dependency_name", "dependency_version"]).shape[0], None),
        ("osv", "osv_targets_queried", len(target_statuses), None),
        ("osv", "osv_queries_completed", target_statuses.isin(ASSESSED_STATUSES).sum(), len(target_statuses)),
        ("osv", "osv_queries_failed", (target_statuses == "api_failed").sum(), len(target_statuses)),
        ("osv", "osv_targets_with_known_vulnerabilities", (target_statuses == "known_vulnerabilities_found").sum(), len(target_statuses)),
        ("osv", "osv_targets_with_no_known_vulnerabilities", (target_statuses == "no_known_vulnerabilities_found").sum(), len(target_statuses)),
        ("osv", "package_rows_skipped", links["osv_status"].isin(SKIPPED_STATUSES).sum(), len(links)),
        ("osv", "dependency_rows_skipped_unknown_version", (dependencies["osv_status"] == "unknown_version").sum(), len(dependencies)),
        ("osv", "resolved_dependency_rows_with_known_vulnerabilities", (resolved["osv_status"] == "known_vulnerabilities_found").sum(), len(resolved)),
        ("osv", "unique_osv_vulnerability_records", len(vulnerabilities), None),
        ("osv", "unique_vulnerabilities_after_alias_grouping", vulnerabilities["vulnerability_group_id"].nunique(), None),
        ("osv", "osv_records_with_cve_alias", vulnerabilities["cve_ids"].notna().sum(), len(vulnerabilities)),
        ("osv", "vulnerability_detail_lookups_failed", (vulnerabilities["lookup_status"] != "found").sum(), len(vulnerabilities)),
        ("assessment", "servers_with_known_vulnerabilities", (servers["known_vulnerability_count"].fillna(0) > 0).sum(), total),
        ("assessment", "servers_with_successful_osv_assessment", (servers["assessment_scope"] != "none").sum(), total),
        ("assessment", "servers_not_assessed_for_vulnerabilities", (servers["assessment_scope"] == "none").sum(), total),
    ]
    for status, count in servers["vulnerability_assessment_status"].value_counts().items():
        metrics.append(("assessment", f"servers_status_{status}", count, total))
    frame = pd.DataFrame([{"area": a, "metric": m, "value": int(v), "denominator": d, "pct": percent(int(v), d)} for a, m, v, d in metrics])
    frame["denominator"] = frame["denominator"].astype("Int64")
    return frame


def build_profile(context):
    tables = context["tables"]
    before = profile_columns(context["raw_frame"], "deepnlp", "before_cleaning")
    after = profile_columns(tables["mcp_servers"], "deepnlp", "after_cleaning")
    profile = pd.concat([
        before, after,
        profile_columns(tables["mcp_registry_servers"], "official_mcp_registry", "after_cleaning"),
        profile_columns(tables["mcp_registry_packages"], "official_mcp_registry_packages", "after_cleaning"),
        profile_columns(tables["mcpcorpus_servers"], "mcpcorpus", "after_cleaning"),
    ], ignore_index=True)
    return {
        **context, "profile": profile, "missing_comparison": missing_comparison(before, after),
        "duplicates": duplicate_summary(context["raw_frame"], context["corpus_records"], tables),
        "issues": quality_issues(context["records"], context["corpus_records"], context["raw_frame"], tables),
        "enrichment": enrichment_summary(tables, context["osv_results"]),
    }


def markdown_table(frame):
    def cell(value):
        return "" if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)) else str(value).replace("|", "\\|")
    lines = ["| " + " | ".join(str(column) for column in frame.columns) + " |", "|" + "---|" * len(frame.columns)]
    lines += ["| " + " | ".join(cell(value) for value in row) + " |" for row in frame.itertuples(index=False)]
    return "\n".join(lines)


def counts_table(series, label, name="records"):
    return markdown_table(series.value_counts(dropna=False).rename_axis(label).reset_index(name=name).fillna("(missing)"))


def render_report(context, finished_at):
    summary, missing, duplicates, issues = context["enrichment"], context["missing_comparison"], context["duplicates"], context["issues"]
    tables, raw_frame, log, schemas = context["tables"], context["raw_frame"], context["cleaning_log"], context["schemas"]
    servers, enriched, repositories = tables["mcp_servers"], tables["mcp_servers_enriched"], tables["repositories"]
    vulnerabilities, documents, corpus = tables["vulnerabilities"], tables["documents"], tables["mcpcorpus_servers"]
    registry_packages, profile = tables["mcp_registry_packages"], context["profile"]
    metadata, registry_metadata, corpus_metadata, run = context["metadata"], context["registry_metadata"], context["corpus_metadata"], context["run"]
    values = summary.set_index("metric")

    def value(name):
        return int(values.loc[name, "value"])

    def share(name):
        pct = values.loc[name, "pct"]
        return f"{value(name)} ({pct}%)" if pd.notna(pct) else str(value(name))

    def area(name):
        return markdown_table(summary[summary["area"] == name].drop(columns="area"))

    found = repositories[repositories["lookup_status"] == "found"]
    languages = found["primary_language"].fillna("(not reported)").value_counts().head(8)
    pvm = tables["package_vulnerability_map"]
    top_vulnerable = (
        pvm.groupby(["ecosystem", "package_name", "package_version"])["vulnerability_group_id"]
        .nunique().sort_values(ascending=False).head(10).rename("unique_vulnerabilities").reset_index()
    )
    categories = corpus["category"].fillna("(missing)").value_counts()
    category_table = categories.head(10).rename_axis("category").reset_index(name="records")
    category_table["pct"] = (100 * category_table["records"] / len(corpus)).round(2)
    schema_summary = schemas.groupby("source").agg(
        field_paths=("field_path", "size"), mixed_type_paths=("value_types", lambda v: v.str.contains(";").sum()),
        nested_paths=("field_path", lambda v: v.str.contains(r"\.|\[\]").sum()),
    ).reset_index()
    mixed = schemas[schemas["value_types"].str.contains(";")].sort_values(["source", "record_coverage_pct"], ascending=[True, False])
    removed = int(log.loc[(log["dataset"] == "deepnlp") & (log["action"] == "removed"), "records_affected"].sum())
    flagged_records = int(((servers["description_quality"] != "ok") | servers["possible_duplicate_group"].notna() | ~servers["website_is_valid"] | servers["server_name_is_generic"] | (servers["github_url_type"] == "owner_only")).sum())
    schema = pd.DataFrame({"column": raw_frame.columns, "dtype": [str(t) for t in raw_frame.dtypes], "example": [str(raw_frame[c].dropna().iloc[0])[:60] if raw_frame[c].notna().any() else "" for c in raw_frame.columns]})
    source_files = ", ".join("`{file_name}` ({bytes} bytes, sha256 `{sha256:.12}…`)".format(**item) for item in metadata["files"])
    most_missing = missing.dropna(subset=["missing_after_pct"]).sort_values("missing_after_pct", ascending=False).iloc[0]
    other_missing = profile[(profile["dataset"] != "deepnlp") & (profile["missing_count"] > 0)].sort_values(["dataset", "missing_pct"], ascending=[True, False])
    other_missing = other_missing.groupby("dataset").head(8)[["dataset", "column", "missing_count", "missing_pct"]]
    document_table = documents.assign(filter_reason=documents["filter_reason"].fillna("kept")).groupby(["document_type", "filter_reason"]).size().rename("documents").reset_index()
    kept = documents[documents["filter_reason"].isna()]
    document_lengths = kept.groupby("document_type")[["raw_char_count", "cleaned_char_count", "word_count"]].median().round(0).astype(int).reset_index()
    outputs = pd.DataFrame(context["outputs"])

    sections = [
        "# MCP Sentinel — Sprint 1 Data Profiling Report",
        "",
        f"*Generated automatically by `scripts/run_sprint1.py` on {finished_at} (UTC). Run mode: **{run['mode']}**. "
        "Every number in this report was calculated from the downloaded data and the live API responses collected during this run; nothing was typed in by hand.*",
        "",
        "## 1. Sprint Overview",
        "",
        "The goal of Sprint 1 was to turn the data plan from our original report into a working ETL pipeline. The pipeline acquires the three MCP "
        "server inventories named in our report (DeepNLP, the Official MCP Registry, and the MCPCorpus research dataset), flattens and cleans them, "
        "links them by repository, enriches the DeepNLP servers with GitHub repository metadata and documents, verifies their packages on PyPI and npm, "
        "resolves dependency graphs with deps.dev, and checks every identified package version against OSV.dev. The cleaned and normalized results are "
        "exported as PostgreSQL-ready CSV files.",
        "",
        f"- MCP server records processed (DeepNLP inventory): **{len(raw_frame)}**, retained **{len(servers)}** (removed: {removed})",
        f"- Official MCP Registry entries profiled: **{value('mcp_registry_servers')}**; MCPCorpus records profiled: **{value('mcpcorpus_records_retained')}**",
        f"- DeepNLP servers found in the MCP Registry: **{share('servers_matched_in_mcp_registry')}**, in MCPCorpus: **{share('servers_matched_in_mcpcorpus')}**",
        f"- Unique GitHub repositories identified: **{value('unique_repositories_identified')}**",
        f"- Servers with a verified PyPI/npm package: **{share('servers_with_verified_package')}**",
        f"- Package/dependency versions checked against OSV.dev: **{value('osv_queries_completed')}**",
        f"- Unique known vulnerabilities found (after alias grouping): **{value('unique_vulnerabilities_after_alias_grouping')}**",
        "",
        "## 2. Data Source Inventory",
        "",
        markdown_table(pd.DataFrame([
            {"source": "DeepNLP MCP Servers (Hugging Face)", "role": "initial server inventory", "format": "JSON Lines", "records_used": len(raw_frame), "authentication": "HF_TOKEN (optional)"},
            {"source": "Official MCP Registry", "role": "server inventory, declared packages", "format": "JSON API (paginated)", "records_used": value("mcp_registry_servers"), "authentication": "none"},
            {"source": "MCPCorpus (research dataset)", "role": "server inventory, categories, tools", "format": "JSON file", "records_used": len(context["corpus_records"]), "authentication": "none"},
            {"source": "GitHub REST API", "role": "repository metadata, activity, manifests, documents", "format": "JSON API", "records_used": len(repositories), "authentication": "GITHUB_TOKEN"},
            {"source": "PyPI JSON API", "role": "Python package metadata", "format": "JSON API", "records_used": value("unique_python_packages_looked_up"), "authentication": "none"},
            {"source": "npm registry", "role": "JavaScript package metadata", "format": "JSON API", "records_used": value("unique_npm_packages_looked_up"), "authentication": "none"},
            {"source": "deps.dev API", "role": "resolved dependency graphs", "format": "JSON API", "records_used": value("deps_dev_graph_lookups"), "authentication": "none"},
            {"source": "OSV.dev API", "role": "vulnerability intelligence", "format": "JSON API", "records_used": value("osv_targets_queried"), "authentication": "none"},
        ])),
        "",
        f"- **DeepNLP** was downloaded from `{metadata['source_url']}` at revision `{metadata['revision']}` (last modified {metadata['last_modified']}). "
        f"Source file(s): {source_files}. Malformed JSON records: {context['malformed']}.",
        f"- **Official MCP Registry** was read from `{registry_metadata['source_url']}` (`{registry_metadata['query']}`, {registry_metadata['pages']} pages) on "
        f"{registry_metadata['downloaded_at']} and saved as `data/raw/{registry_metadata['file_name']}`.",
        f"- **MCPCorpus** was downloaded from `{corpus_metadata['source_url']}` (`{corpus_metadata['path']}`, commit `{corpus_metadata['commit'][:12]}` of "
        f"{corpus_metadata['commit_date']}) and saved as `data/raw/{corpus_metadata['file_name']}`. None of the repository's crawler code was run.",
        "",
        "## 3. Data Understanding and Exploration",
        "",
        "### 3.1 DeepNLP raw structure",
        "",
        f"The source file is in JSON Lines format (one JSON object per line). After flattening, the raw table has **{len(raw_frame)} records** and "
        f"**{raw_frame.shape[1]} attributes** (including the two provenance columns `source_file` and `source_record_number` that the pipeline adds). "
        "The nested `statistic` object was flattened with `pandas.json_normalize`, which turned the key `Bing Rank` into the column `statistic_bing_rank`.",
        "",
        markdown_table(schema),
        "",
        "### 3.2 Dataset statistics",
        "",
        markdown_table(pd.DataFrame([
            {"metric": "DeepNLP records", "value": len(raw_frame)},
            {"metric": "DeepNLP source attributes (excluding provenance columns)", "value": raw_frame.shape[1] - 2},
            {"metric": "Official MCP Registry entries (latest versions)", "value": value("mcp_registry_servers")},
            {"metric": "Official MCP Registry declared packages", "value": value("mcp_registry_packages")},
            {"metric": "MCPCorpus records (raw / retained)", "value": f"{len(context['corpus_records'])} / {len(corpus)}"},
            {"metric": "Staging tables produced", "value": len([o for o in context["outputs"] if o["layer"] == "staging"])},
            {"metric": "DeepNLP records whose website is a GitHub URL", "value": int(servers["website_is_github"].sum())},
            {"metric": "DeepNLP records with a non-empty `statistic` object", "value": int(servers["bing_rank"].notna().sum())},
        ])),
        "",
        "### 3.3 DeepNLP description quality",
        "",
        "Descriptions were scraped by the dataset publisher and many contain markdown list markers or website boilerplate. The pipeline keeps the "
        "original text in `description_original` and assigns each cleaned description a quality flag:",
        "",
        counts_table(servers["description_quality"], "description_quality", "servers"),
        "",
        "### 3.4 Additional MCP inventories",
        "",
        f"The Official MCP Registry returned {value('mcp_registry_servers')} latest-version entries. {share('mcp_registry_servers_with_github_repository')} point to a "
        f"GitHub repository. They declare {value('mcp_registry_packages')} packages, distributed over these registry types:",
        "",
        counts_table(registry_packages["registry_type"], "registry_type", "packages"),
        "",
        f"MCPCorpus contains {len(context['corpus_records'])} records ({len(corpus)} after removing exact and identifier duplicates). Unlike DeepNLP it has a real "
        "category attribute, which makes **category imbalance** measurable. The ten largest categories:",
        "",
        markdown_table(category_table),
        "",
        f"The two largest categories hold {round(100 * categories.head(2).sum() / len(corpus), 2)}% of all records, while {int((categories < 10).sum())} categories have "
        "fewer than ten records. A model trained on these categories would be dominated by developer tools and data/research servers.",
        "",
        "### 3.5 Schema extraction",
        "",
        "The pipeline walks every raw JSON record and records each field path, the value types seen, and how many records contain it "
        "(`reports/source_schemas.csv`). Paths with more than one value type point to format inconsistencies.",
        "",
        markdown_table(schema_summary),
        "",
        markdown_table(mixed.head(15)[["source", "field_path", "value_types", "record_coverage_pct"]]),
        "",
        "## 4. Data Quality Assessment",
        "",
        "### 4.1 Missing values",
        "",
        "DeepNLP before and after cleaning. \"Before\" counts both true nulls and blank/placeholder strings in the flattened raw table; \"after\" counts nulls "
        "in the staged `mcp_servers` table, where every placeholder has been converted to a real null.",
        "",
        markdown_table(missing),
        "",
        f"The attribute with the highest missing share after cleaning is `{most_missing['staging_column']}` ({most_missing['missing_after_pct']}%). "
        "Missing values were not imputed, because inventing names, descriptions, or ranks would introduce false information into a security dataset.",
        "",
        "Columns with the most missing values in the other inventories (after cleaning):",
        "",
        markdown_table(other_missing),
        "",
        "### 4.2 Duplicate analysis",
        "",
        markdown_table(duplicates),
        "",
        "Servers that share a repository were **not** merged. In a monorepo such as `modelcontextprotocol/servers`, each subdirectory is a separate "
        "MCP server with its own package, so merging them would be an entity-resolution error. Cross-source matches use the normalized repository "
        "identifier (including renamed repositories) and the subdirectory; a server that matches several records in another source is marked "
        "`multiple_matches` and is not used to infer anything.",
        "",
        "### 4.3 Data quality issues",
        "",
        markdown_table(issues),
        "",
        "## 5. Data Wrangling and Preparation",
        "",
        "### 5.1 Structured and semi-structured data",
        "",
        "The cleaning steps below were applied in order for each inventory. `records_affected` is the number of records changed, flagged, or removed by each step.",
        "",
        markdown_table(log),
        "",
        f"In DeepNLP, {len(servers)} records were retained, {removed} were removed, and {flagged_records} retained records carry at least one quality flag. "
        "No record was dropped just because it was incomplete; incomplete records are kept and labelled so that later sprints can decide how to use them.",
        "",
        "### 5.2 Unstructured text",
        "",
        f"For every mapped server location the pipeline collected the README; for every retrieved repository it collected the latest release notes and the "
        f"{context['issues_per_repository']} most recently updated issues. Text cleaning removed HTML, badges, image and link markup, markdown syntax, and extra "
        "whitespace while keeping code and configuration text. Metadata generation stored the server or repository id, document type, source URL, "
        "publication date, collection time, and character/word counts with each document. Document filtering removed pull requests (the GitHub issues "
        "endpoint also returns them), bot-authored issues, and documents that were empty or shorter than 20 characters after cleaning.",
        "",
        markdown_table(document_table),
        "",
        "Median length of kept documents (raw characters → cleaned characters, and words):",
        "",
        markdown_table(document_lengths),
        "",
        "## 6. API Enrichment Results",
        "",
        "### 6.1 GitHub",
        "",
        counts_table(enriched["github_status"], "github_status", "servers"),
        "",
        f"Of the {value('unique_repositories_identified')} unique repositories, {share('repository_lookups_succeeded')} were retrieved successfully, "
        f"{value('repository_lookups_not_found')} returned 404 (deleted, renamed without redirect, or private) and {value('repository_lookups_failed')} failed. "
        f"{value('repositories_moved_or_renamed')} repositories now live under a different owner/name than the URL in the dataset, and "
        f"{value('repositories_archived')} are archived. {value('servers_subpath_not_found')} servers point to a subdirectory that no longer exists "
        "in the repository, which shows that the March 2025 snapshot has become partly stale.",
        "",
        f"Activity data (commits, contributors, releases) was collected for the retrieved repositories. The median repository has "
        f"{int(found['stars'].median())} stars, {int(found['commit_count'].median())} commits, {int(found['contributor_count'].median())} contributors and "
        f"{int(found['release_count'].median())} releases; the median time since the last commit is {int(found['days_since_last_commit'].median())} days.",
        "",
        area("github"),
        "",
        "Most common primary languages:",
        "",
        markdown_table(languages.rename_axis("primary_language").reset_index(name="repositories")),
        "",
        "### 6.2 Linking the inventories",
        "",
        area("sources"),
        "",
        "Categories of the DeepNLP servers that were found in MCPCorpus:",
        "",
        counts_table(enriched["corpus_category"].dropna(), "corpus_category", "servers"),
        "",
        "### 6.3 PyPI and npm",
        "",
        "A package is linked to a server only when its identity is backed by evidence: either the server's Official MCP Registry entry lists the package "
        "(the registry checks that the publisher controls it), or a manifest in the server's repository location declares the name and the registry "
        "metadata links back to the same GitHub repository. Packages that exist but do not link back are recorded as `ambiguous` and are not treated as "
        "the server's package.",
        "",
        area("packages"),
        "",
        "### 6.4 Dependency analysis (manifests and deps.dev)",
        "",
        "Declared dependencies come from the manifests. Most use version ranges, so the installed version is unknown. For every verified package version, "
        "deps.dev returned the resolved dependency graph (direct and indirect dependencies with exact versions), which can be checked against OSV.dev.",
        "",
        area("dependencies"),
        "",
        "### 6.5 OSV.dev vulnerability intelligence",
        "",
        "OSV.dev was queried for every verified server package (at its identified version), every dependency pinned to an exact version in a manifest, "
        "and every dependency version resolved by deps.dev.",
        "",
        area("osv"),
        "",
        "Severity labels of unique vulnerabilities (from the GitHub Advisory `database_specific.severity` field where present):",
        "",
        counts_table(vulnerabilities.drop_duplicates("vulnerability_group_id")["severity_label"].fillna("(not provided)"), "severity_label", "vulnerabilities"),
        "",
        "Package versions with the most known vulnerabilities:",
        "",
        markdown_table(top_vulnerable) if len(top_vulnerable) else "No vulnerable package versions were found in this run.",
        "",
        "### 6.6 Server-level assessment status",
        "",
        "Each server gets two statuses. `package_vulnerability_status` looks only at the server's own PyPI/npm package. "
        "`vulnerability_assessment_status` combines the package and its dependencies and reports the most informative status in this order: "
        "`known_vulnerabilities_found` > `api_failed` > `no_known_vulnerabilities_found` > `unknown_version` > `ambiguous_mapping` > "
        "`unknown_package_identity` > `not_assessed`. For example, a server whose package is ambiguous and whose dependencies only use "
        "version ranges has the package status `ambiguous_mapping` but the overall status `unknown_version`.",
        "",
        "Status of the server's own package:",
        "",
        counts_table(enriched["package_vulnerability_status"], "package_vulnerability_status", "servers"),
        "",
        "Overall status (package and dependencies):",
        "",
        counts_table(enriched["vulnerability_assessment_status"], "vulnerability_assessment_status", "servers"),
        "",
        "What was actually checked against OSV.dev:",
        "",
        counts_table(enriched["assessment_scope"], "assessment_scope", "servers"),
        "",
        "**A missing vulnerability result does not mean a server is secure.** Only `no_known_vulnerabilities_found` means that OSV.dev was actually "
        "queried and returned nothing; every other non-vulnerable status means the assessment could not be completed. `known_vulnerability_count` is "
        "left null (not zero) for servers that were never successfully assessed.",
        "",
        "## 7. Processed Data Summary",
        "",
        markdown_table(outputs),
        "",
        "## 8. Challenges and Limitations",
        "",
        f"- {value('servers_without_github_url')} DeepNLP records only provide a marketing website, so no repository, package, or vulnerability information could be derived for them.",
        f"- {value('servers_with_only_unsupported_manifests')} mapped servers only contain manifests for ecosystems outside the Sprint 1 scope (for example Go, Rust, or Java).",
        f"- {value('mappings_ambiguous')} declared packages exist on a registry but do not link back to the server repository, so they were not trusted.",
        f"- {value('dependency_rows_skipped_unknown_version')} declared dependencies use version ranges. deps.dev resolves them only for verified packages, and its resolution reflects a fresh install today, not necessarily what an existing user has installed.",
        "- The Official MCP Registry and the GitHub, registry, and OSV data are live, while DeepNLP and MCPCorpus are snapshots; their contents differ in time.",
        "- MCPCorpus and the MCP Registry were profiled and linked, but their servers were not enriched one by one; that would need far more API requests than Sprint 1 allows.",
        "- OSV.dev only covers publicly disclosed vulnerabilities. MCP-specific risks such as tool poisoning or excessive permissions are not covered.",
        "",
        "## 9. Sprint 2 Preparation",
        "",
        "The staging CSV files are designed to be loaded with PostgreSQL `COPY`. Candidate keys are documented in `docs/data_dictionary.md`: "
        "`mcp_servers.server_id`, `repositories.repository_id`, `packages.package_id`, `vulnerabilities.vulnerability_id`, `documents.document_id`, "
        "`mcp_registry_servers.registry_name`, and `mcpcorpus_servers.corpus_id` are primary keys, while the `*_map` tables, `dependencies`, and "
        "`resolved_dependencies` hold the foreign keys that connect them.",
        "",
    ]
    return "\n".join(sections)


def write_reports(report_dir, context):
    report_dir.mkdir(parents=True, exist_ok=True)
    context = {**context, "issues_per_repository": ISSUES_PER_REPOSITORY}
    context["profile"].to_csv(report_dir / "missing_values.csv", index=False)
    context["duplicates"].to_csv(report_dir / "duplicate_summary.csv", index=False)
    context["issues"].to_csv(report_dir / "data_quality_issues.csv", index=False)
    context["enrichment"].to_csv(report_dir / "enrichment_summary.csv", index=False)
    context["cleaning_log"].to_csv(report_dir / "cleaning_log.csv", index=False)
    context["schemas"].to_csv(report_dir / "source_schemas.csv", index=False)
    (report_dir / "sprint1_profile.md").write_text(render_report(context, utc_now()), encoding="utf-8")
