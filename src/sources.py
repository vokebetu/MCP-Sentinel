import gzip
import hashlib
import json
from collections import Counter
from urllib.parse import quote

import pandas as pd
import requests

from src.etl import (
    RAW_DIR, REQUEST_TIMEOUT, USER_AGENT, exact_duplicates, github_request, log_step, normalize_ecosystem,
    normalize_package_name, normalize_text_columns, normalize_url, parse_github_url, request_json, utc_now,
)

REGISTRY_API = "https://registry.modelcontextprotocol.io/v0/servers"
REGISTRY_PAGE_SIZE = 100
MCPCORPUS_REPOSITORY = "Snakinya/MCPCorpus"
MCPCORPUS_PATH = "Website/mcpso_servers_cleaned.json"


def read_raw_snapshot(name):
    metadata_path = RAW_DIR / f"{name}_source_metadata.json"
    if not metadata_path.exists():
        return None, None
    with gzip.open(RAW_DIR / f"{name}.json.gz", "rb") as handle:
        return json.loads(handle.read()), json.loads(metadata_path.read_text(encoding="utf-8"))


def save_raw_snapshot(name, content, metadata):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    with gzip.open(RAW_DIR / f"{name}.json.gz", "wb") as handle:
        handle.write(content)
    metadata = {
        **metadata, "file_name": f"{name}.json.gz", "uncompressed_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    (RAW_DIR / f"{name}_source_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def download_registry():
    entries, metadata = read_raw_snapshot("mcp_registry_servers")
    if entries is not None:
        return entries, metadata
    entries, cursor, pages = [], None, 0
    while True:
        url = f"{REGISTRY_API}?limit={REGISTRY_PAGE_SIZE}&version=latest" + (f"&cursor={quote(cursor, safe='')}" if cursor else "")
        result = request_json("GET", url)
        if result["status"] != 200 or not isinstance(result["body"], dict):
            raise RuntimeError(f"MCP Registry request failed after {pages} pages ({result['error']}); rerun to resume from the cache")
        entries += result["body"].get("servers") or []
        pages += 1
        cursor = (result["body"].get("metadata") or {}).get("nextCursor")
        if pages % 50 == 0 or not cursor:
            print(f"  MCP Registry pages: {pages} ({len(entries)} servers)")
        if not cursor:
            break
    content = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    metadata = {"source_url": REGISTRY_API, "query": "version=latest", "pages": pages, "records": len(entries), "downloaded_at": utc_now()}
    return entries, save_raw_snapshot("mcp_registry_servers", content, metadata)


def download_mcpcorpus():
    records, metadata = read_raw_snapshot("mcpcorpus_servers")
    if records is not None:
        return records, metadata
    commit = github_request(f"/repos/{MCPCORPUS_REPOSITORY}/commits?per_page=1")
    if commit["status"] != 200 or not commit["body"]:
        raise RuntimeError(f"Could not resolve the MCPCorpus commit ({commit['error']})")
    sha = commit["body"][0]["sha"]
    response = requests.get(
        f"https://raw.githubusercontent.com/{MCPCORPUS_REPOSITORY}/{sha}/{MCPCORPUS_PATH}",
        headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT * 4,
    )
    response.raise_for_status()
    metadata = {
        "source_url": f"https://github.com/{MCPCORPUS_REPOSITORY}", "path": MCPCORPUS_PATH, "commit": sha,
        "commit_date": commit["body"][0]["commit"]["committer"]["date"], "downloaded_at": utc_now(),
    }
    metadata = save_raw_snapshot("mcpcorpus_servers", response.content, metadata)
    records = json.loads(response.content)
    metadata["records"] = len(records)
    return records, metadata


def collect_paths(value, path, seen):
    if path:
        seen.setdefault(path, set()).add("null" if value is None else type(value).__name__)
    if isinstance(value, dict):
        for key, child in value.items():
            collect_paths(child, f"{path}.{key}" if path else key, seen)
    elif isinstance(value, list):
        for child in value:
            collect_paths(child, f"{path}[]", seen)


def extract_schema(records, source):
    presence, types = Counter(), {}
    for record in records:
        seen = {}
        collect_paths(record, "", seen)
        for path, kinds in seen.items():
            presence[path] += 1
            types.setdefault(path, set()).update(kinds)
    return pd.DataFrame([
        {
            "source": source, "field_path": path, "value_types": "; ".join(sorted(types[path])),
            "records_with_field": presence[path], "record_coverage_pct": round(100 * presence[path] / len(records), 2),
        }
        for path in sorted(presence)
    ])


def first_present(*values):
    return next((value for value in values if value is not None and value != "" and value != [] and value != {}), None)


def flatten_registry(entries, collected_at):
    servers, packages = [], []
    for entry in entries:
        server = entry.get("server") or {}
        official = (entry.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        repository = server.get("repository") or {}
        github = parse_github_url(repository.get("url"))
        subfolder = (repository.get("subfolder") or "").strip("/") or github["github_subpath"]
        server_packages = server.get("packages") or []
        servers.append({
            "registry_name": server.get("name"), "title": server.get("title"), "description": server.get("description"),
            "version": server.get("version"), "website_url": first_present(server.get("websiteUrl"), server.get("website_url")),
            "repository_url": repository.get("url"), "repository_source": repository.get("source"),
            "repository_id": github["repository_id"], "repository_subfolder": subfolder or None,
            "status": official.get("status"), "published_at": official.get("publishedAt"), "updated_at": official.get("updatedAt"),
            "package_count": len(server_packages), "remote_count": len(server.get("remotes") or []),
        })
        for position, package in enumerate(server_packages, start=1):
            registry_type = first_present(package.get("registryType"), package.get("registry_type"))
            ecosystem = normalize_ecosystem(registry_type)
            variables = first_present(package.get("environmentVariables"), package.get("environment_variables")) or []
            packages.append({
                "registry_name": server.get("name"), "package_position": position,
                "registry_type": registry_type, "identifier": package.get("identifier"),
                "ecosystem": ecosystem, "package_name": normalize_package_name(package.get("identifier"), ecosystem) if ecosystem else None,
                "version": package.get("version"), "transport_type": (package.get("transport") or {}).get("type"),
                "environment_variable_count": len(variables),
                "secret_environment_variable_count": sum(1 for v in variables if first_present(v.get("isSecret"), v.get("is_secret"))),
            })
    server_frame = pd.DataFrame(servers)
    package_frame = pd.DataFrame(packages, columns=[
        "registry_name", "package_position", "registry_type", "identifier", "ecosystem", "package_name", "version", "transport_type",
        "environment_variable_count", "secret_environment_variable_count",
    ])
    for frame in (server_frame, package_frame):
        frame["source"] = "official_mcp_registry"
        frame["collected_at"] = collected_at
    return server_frame, package_frame


def clean_registry(servers, packages):
    log = []
    exact = servers.astype(str).duplicated()
    duplicate_name = servers["registry_name"].duplicated() & ~exact
    log_step(log, "remove_exact_duplicate", "all", exact.sum(), "removed")
    log_step(log, "remove_duplicate_registry_name", "registry_name", duplicate_name.sum(), "removed")
    servers = normalize_text_columns(servers[~(exact | duplicate_name)].copy(), ["title", "description", "version", "website_url", "repository_url"], log)
    log_step(log, "extract_github_reference", "repository_url", servers["repository_id"].notna().sum(), "modified")
    shared = servers.duplicated(["repository_id", "repository_subfolder"], keep=False) & servers["repository_id"].notna()
    servers.insert(servers.columns.get_loc("source"), "shares_repository_location", shared)
    log_step(log, "flag_shared_repository_location", "repository_id", servers["shares_repository_location"].sum(), "flagged")
    packages = packages[packages["registry_name"].isin(servers["registry_name"])].drop_duplicates().reset_index(drop=True)
    return servers.reset_index(drop=True), packages, pd.DataFrame(log)


def parse_tags(value):
    if not isinstance(value, str) or not value.strip():
        return [], "empty"
    text = value.strip()
    if text.startswith("["):
        try:
            return [str(item).strip().lower() for item in json.loads(text) if str(item).strip()], "json_array"
        except ValueError:
            return [], "invalid_json"
    return [part.strip().lower() for part in text.split(",") if part.strip()], "comma_separated"


def parse_tool_names(value):
    if not isinstance(value, str) or not value.strip():
        return None, "missing"
    try:
        tools = json.loads(value)
    except ValueError:
        return None, "invalid_json"
    if not isinstance(tools, list):
        return None, "invalid_json"
    return [tool.get("name") for tool in tools if isinstance(tool, dict) and tool.get("name")], "json_array"


def clean_mcpcorpus(records, collected_at):
    log = []
    raw = pd.DataFrame({"record": [json.dumps(record, sort_keys=True) for record in records]})
    exact = exact_duplicates(raw)
    frame = pd.json_normalize(records, sep="_")
    duplicate_id = frame["id"].duplicated() & ~exact
    log_step(log, "remove_exact_duplicate", "all", exact.sum(), "removed")
    log_step(log, "remove_duplicate_id", "id", duplicate_id.sum(), "removed")
    frame = frame[~(exact | duplicate_id)].copy()
    text_columns = ["name", "title", "description", "author_name", "category", "type", "url", "server_command", "sse_url"]
    frame = normalize_text_columns(frame, text_columns, log)
    tags = frame["tags"].map(parse_tags)
    frame["tag_format"] = [item[1] for item in tags]
    frame["tags"] = ["; ".join(item[0]) or None for item in tags]
    log_step(log, "parse_mixed_format_tags", "tags", (frame["tag_format"] != "empty").sum(), "modified")
    tools = frame["tools"].map(parse_tool_names)
    frame["tool_format"] = [item[1] for item in tools]
    frame["tool_count"] = pd.array([len(item[0]) if item[0] is not None else None for item in tools], dtype="Int64")
    frame["tool_names"] = ["; ".join(item[0]) if item[0] else None for item in tools]
    log_step(log, "parse_json_string_tools", "tools", (frame["tool_format"] == "json_array").sum(), "modified")
    for column in ["github_stargazers_count", "github_forks_count", "github_open_issues_count", "github_contributors_count"]:
        frame[column] = frame[column].astype("Int64")
    for column in ["github_archived", "github_has_docker", "github_has_readme", "github_has_requirements"]:
        frame[column] = frame[column].astype("boolean")
    log_step(log, "cast_to_nullable_integer_and_boolean", "github_*", frame["github_full_name"].notna().sum(), "modified")
    frame["github_last_commit"] = pd.to_datetime(frame["github_last_commit"], utc=True, errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    frame["website_normalized"] = frame["url"].map(normalize_url)
    github = pd.DataFrame([parse_github_url(url) for url in frame["url"]], index=frame.index)
    frame = pd.concat([frame, github[["repository_id", "github_subpath"]]], axis=1)
    log_step(log, "extract_github_reference", "url", frame["repository_id"].notna().sum(), "modified")
    frame["shares_repository_location"] = frame.duplicated(["repository_id", "github_subpath"], keep=False) & frame["repository_id"].notna()
    log_step(log, "flag_shared_repository_location", "repository_id", frame["shares_repository_location"].sum(), "flagged")
    frame["corpus_id"] = "mcpcorpus:" + frame["id"].astype(str)
    frame = frame.rename(columns={
        "id": "source_id", "type": "record_type", "url": "website_url", "github_stargazers_count": "stars", "github_forks_count": "forks", "github_open_issues_count": "open_issues",
        "github_contributors_count": "contributor_count", "github_language": "primary_language", "github_license": "license",
        "github_archived": "archived", "github_has_docker": "has_docker", "github_has_readme": "has_readme",
        "github_has_requirements": "has_requirements", "github_last_commit": "last_commit_at",
    })
    frame["has_server_command"] = frame["server_command"].notna()
    frame["has_remote_url"] = frame["sse_url"].notna()
    frame["source"] = "mcpcorpus"
    frame["collected_at"] = collected_at
    columns = [
        "corpus_id", "source_id", "name", "title", "description", "author_name", "category", "record_type", "tags",
        "tag_format", "tool_count", "tool_names", "tool_format", "website_url", "website_normalized", "repository_id",
        "github_subpath", "shares_repository_location", "github_full_name", "stars", "forks", "open_issues",
        "contributor_count", "primary_language", "license", "archived", "has_docker", "has_readme", "has_requirements",
        "last_commit_at", "has_server_command", "has_remote_url", "source", "collected_at",
    ]
    return frame[columns].reset_index(drop=True), pd.DataFrame(log)


def match_sources(servers, repositories, frame, source, id_column, location_column):
    found = repositories[repositories["full_name"].notna()]
    canonical = dict(zip(found["repository_id"], "github:" + found["full_name"].str.lower()))
    index = {}
    for record_id, repository_id, location in frame[[id_column, "repository_id", location_column]].dropna(subset=["repository_id"]).itertuples(index=False):
        index.setdefault((repository_id, location if isinstance(location, str) else None), []).append(record_id)
    rows = []
    for server in servers.dropna(subset=["repository_id"]).itertuples(index=False):
        location = server.github_subpath if isinstance(server.github_subpath, str) else None
        keys = {(repository_id, location) for repository_id in (server.repository_id, canonical.get(server.repository_id)) if repository_id}
        matches = sorted({record_id for key in keys for record_id in index.get(key, [])})
        rows += [{
            "server_id": server.server_id, "linked_source": source, "linked_record_id": record_id,
            "match_key": f"{server.repository_id}|{location or ''}", "match_status": "matched" if len(matches) == 1 else "multiple_matches",
        } for record_id in matches]
    frame = pd.DataFrame(rows, columns=["server_id", "linked_source", "linked_record_id", "match_key", "match_status"])
    frame["source"] = "entity_resolution"
    frame["collected_at"] = utc_now()
    return frame


def link_sources(servers, repositories, registry_servers, corpus):
    return pd.concat([
        match_sources(servers, repositories, registry_servers, "official_mcp_registry", "registry_name", "repository_subfolder"),
        match_sources(servers, repositories, corpus, "mcpcorpus", "corpus_id", "github_subpath"),
    ], ignore_index=True)


def add_registry_candidates(candidates, server_source_map, registry_packages):
    matched = server_source_map[(server_source_map["linked_source"] == "official_mcp_registry") & (server_source_map["match_status"] == "matched")]
    supported = registry_packages[registry_packages["ecosystem"].notna() & registry_packages["package_name"].notna()]
    merged = matched.drop(columns=["source", "collected_at"]).merge(supported, left_on="linked_record_id", right_on="registry_name")
    listed = pd.DataFrame({
        "server_id": merged["server_id"], "manifest_file": None,
        "package_id": merged["ecosystem"] + ":" + merged["package_name"], "ecosystem": merged["ecosystem"],
        "package_name": merged["package_name"], "declared_name": merged["identifier"], "declared_version": merged["version"],
        "candidate_source": "official_mcp_registry",
    })
    frames = [frame for frame in (listed, candidates) if len(frame)]
    combined = pd.concat(frames, ignore_index=True) if frames else candidates
    return combined.drop_duplicates(["server_id", "package_id"]).reset_index(drop=True)
