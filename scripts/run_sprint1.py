import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

from src import etl, profiling, sources


def output_directories(limit):
    if limit:
        base = PROJECT_ROOT / "data" / "limit_runs" / f"limit_{limit}"
        return base / "staging", base / "processed", base / "reports"
    return PROJECT_ROOT / "data" / "staging", PROJECT_ROOT / "data" / "processed", PROJECT_ROOT / "reports"


def main():
    parser = argparse.ArgumentParser(description="Run the MCP Sentinel Sprint 1 ETL, enrichment, and profiling pipeline.")
    parser.add_argument("--limit", type=int, help="process only the first N DeepNLP records and write outputs to data/limit_runs/limit_N/")
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be a positive integer")
    staging_dir, processed_dir, report_dir = output_directories(args.limit)
    load_dotenv(PROJECT_ROOT / ".env")
    started_at = etl.utc_now()
    credentials = etl.credential_status()
    print("Credentials configured:", ", ".join(f"{name}={'yes' if present else 'no'}" for name, present in credentials.items()))
    if not credentials["GITHUB_TOKEN"]:
        print(
            "WARNING: GITHUB_TOKEN is not set. Copy .env.example to .env and add a GitHub personal access token. "
            "Without it GitHub allows only 60 requests per hour, so most repository lookups will be recorded as lookup_failed."
        )

    print("[1/9] Acquiring the DeepNLP MCP Servers dataset")
    metadata = etl.download_deepnlp()
    records, malformed = etl.load_deepnlp_records(metadata)
    if args.limit:
        records = records[: args.limit]
    raw_frame = etl.flatten_records(records)
    servers, deepnlp_log = etl.clean_servers(raw_frame, metadata["downloaded_at"])
    print(f"  {len(raw_frame)} records, {raw_frame.shape[1]} flattened attributes, {malformed} malformed records")

    print("[2/9] Acquiring the Official MCP Registry")
    registry_entries, registry_metadata = sources.download_registry()
    registry_servers, registry_packages = sources.flatten_registry(registry_entries, registry_metadata["downloaded_at"])
    registry_servers, registry_packages, registry_log = sources.clean_registry(registry_servers, registry_packages)
    print(f"  {len(registry_entries)} registry entries, {len(registry_packages)} declared packages")

    print("[3/9] Acquiring the MCPCorpus research dataset")
    corpus_records, corpus_metadata = sources.download_mcpcorpus()
    corpus, corpus_log = sources.clean_mcpcorpus(corpus_records, corpus_metadata["downloaded_at"])
    print(f"  {len(corpus_records)} corpus records, {len(corpus)} retained")

    print("[4/9] Enriching with the GitHub REST API")
    repositories = etl.fetch_repository_activity(etl.fetch_repositories(servers))
    server_repository_map, manifests = etl.fetch_manifests(servers, repositories)
    documents = etl.fetch_documents(server_repository_map, repositories)
    candidates, dependencies, parse_errors = etl.extract_packages(manifests)
    server_repository_map = etl.attach_parse_errors(server_repository_map, parse_errors)

    print("[5/9] Linking servers across DeepNLP, the MCP Registry, and MCPCorpus")
    server_source_map = sources.link_sources(servers, repositories, registry_servers, corpus)
    candidates = sources.add_registry_candidates(candidates, server_source_map, registry_packages)

    print(f"[6/9] Verifying {candidates['package_id'].nunique()} declared packages against PyPI and npm")
    packages, server_packages = etl.enrich_packages(candidates, repositories, server_repository_map)

    print("[7/9] Resolving dependency graphs with deps.dev")
    server_packages, resolved = etl.fetch_dependency_graphs(server_packages)

    print("[8/9] Querying OSV.dev for known vulnerabilities")
    server_packages, dependencies, resolved, package_vulnerabilities, vulnerabilities, osv_results = etl.enrich_vulnerabilities(
        server_packages, dependencies, resolved,
    )

    print("[9/9] Exporting datasets and profiling data quality")
    staging = {
        "mcp_servers": servers, "repositories": repositories, "server_repository_map": server_repository_map,
        "documents": documents, "packages": packages, "server_package_map": server_packages, "dependencies": dependencies,
        "resolved_dependencies": resolved, "vulnerabilities": vulnerabilities, "package_vulnerability_map": package_vulnerabilities,
        "mcp_registry_servers": registry_servers, "mcp_registry_packages": registry_packages, "mcpcorpus_servers": corpus,
        "server_source_map": server_source_map,
    }
    enriched = etl.build_enriched(staging, osv_results)
    outputs = [{"layer": "staging", **item} for item in etl.export_tables(staging, staging_dir)]
    outputs += [{"layer": "processed", **item} for item in etl.export_tables({"mcp_servers_enriched": enriched}, processed_dir)]
    tables = {**staging, "mcp_servers_enriched": enriched}
    logs = {"deepnlp": deepnlp_log, "official_mcp_registry": registry_log, "mcpcorpus": corpus_log}
    deepnlp_records = [{key: value for key, value in record.items() if not key.startswith("source_")} for record in records]
    context = profiling.build_profile({
        "metadata": metadata, "registry_metadata": registry_metadata, "corpus_metadata": corpus_metadata,
        "malformed": malformed, "raw_frame": raw_frame, "records": records, "corpus_records": corpus_records,
        "tables": tables, "outputs": outputs,
        "cleaning_log": profiling.combine_logs(logs),
        "schemas": profiling.combine_schemas([
            sources.extract_schema(deepnlp_records, "deepnlp"),
            sources.extract_schema(registry_entries, "official_mcp_registry"),
            sources.extract_schema(corpus_records, "mcpcorpus"),
        ]),
        "osv_results": osv_results,
        "run": {"mode": f"limited test run (--limit {args.limit})" if args.limit else "full run", "started_at": started_at},
    })
    profiling.write_reports(report_dir, context)

    print("\nOutputs:")
    for item in outputs:
        print(f"  {item['file']}: {item['rows']} rows x {item['columns']} columns")
    print(f"  {report_dir.relative_to(PROJECT_ROOT)}/sprint1_profile.md")
    print("\nKey results:")
    key_metrics = [
        "mcp_server_records", "repository_lookups_succeeded", "servers_matched_in_mcp_registry", "servers_matched_in_mcpcorpus",
        "servers_with_verified_package", "osv_queries_completed", "osv_queries_failed",
        "unique_vulnerabilities_after_alias_grouping", "servers_not_assessed_for_vulnerabilities",
    ]
    print(context["enrichment"].set_index("metric").loc[key_metrics, ["value", "denominator", "pct"]].to_string())


if __name__ == "__main__":
    main()
