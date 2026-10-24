import argparse
import json
import sys
from pathlib import Path

from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_common import (
    OFFICIAL, apply_migrations, canonical_repository, clean_subfolder, connect, ensure_sources, finish_run,
    is_exact_version, normalize_endpoint, normalize_package_name, parse_time, read_jsonl_gz, redact_secrets, sha256_file, start_run,
)

SEARCH_VECTOR = (
    "setweight(to_tsvector('simple', regexp_replace(%(name)s, '[^A-Za-z0-9]+', ' ', 'g')), 'A') || "
    "setweight(to_tsvector('english', coalesce(%(title)s, '')), 'B') || "
    "setweight(to_tsvector('english', coalesce(%(description)s, '')), 'C')"
)


def load_entries(path, errors):
    entries = {}
    number = 0
    for number, line in read_jsonl_gz(path):
        try:
            entry = json.loads(line)
        except ValueError as error:
            errors.append((f"line {number}", f"malformed JSON: {error}"))
            continue
        server = entry.get("server") if isinstance(entry, dict) else None
        official = ((entry.get("_meta") or {}).get(OFFICIAL) or {}) if isinstance(entry, dict) else {}
        if not isinstance(server, dict):
            errors.append((f"line {number}", "record has no server object"))
            continue
        name = (server.get("name") or "").strip()
        version = (server.get("version") or "").strip()
        status = official.get("status")
        if not name or not version:
            errors.append((f"line {number}", "record lacks server.name or server.version"))
            continue
        if status not in ("active", "deprecated", "deleted"):
            errors.append((f"{name}@{version}", f"unknown registry status {status!r}"))
            continue
        previous = entries.get(name)
        if previous:
            errors.append((name, "duplicate registry name in snapshot; kept the most recently updated record"))
            if (parse_time(official.get("updatedAt")) or parse_time("1970-01-01")) < (parse_time(previous[1].get("updatedAt")) or parse_time("1970-01-01")):
                continue
        entries[name] = (entry, official, number)
    return entries, number


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    args = parser.parse_args()
    bundle = Path(args.bundle)
    snapshot = bundle / "registry_snapshot.jsonl.gz"
    meta = json.loads((bundle / "registry_snapshot_meta.json").read_text(encoding="utf-8"))
    collected_at = parse_time(meta.get("collection_started_at"))
    with connect() as conn:
        apply_migrations(conn)
        sources = ensure_sources(conn)
        run_id = start_run(conn, sources["mcp_registry"], "registry_import", str(snapshot), sha256_file(snapshot), collected_at)
        errors = []
        entries, records_read = load_entries(snapshot, errors)
        server_rows, version_rows = [], []
        for name, (entry, official, _) in sorted(entries.items()):
            server = entry["server"]
            server_rows.append((name, official["status"], parse_time(official.get("statusChangedAt")), official.get("statusMessage"), collected_at, collected_at))
            record = redact_secrets(entry)
            version_rows.append({
                "name": name, "version": server["version"].strip(), "title": server.get("title"), "description": server.get("description"),
                "website": server.get("websiteUrl"), "schema": server.get("$schema"), "is_latest": official.get("isLatest"),
                "published": parse_time(official.get("publishedAt")), "updated": parse_time(official.get("updatedAt")),
                "publisher_meta": Jsonb(redact_secrets(server["_meta"])) if server.get("_meta") else None,
                "icons": Jsonb(server["icons"]) if server.get("icons") else None, "record": Jsonb(record), "observed": collected_at, "run_id": run_id,
            })
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO servers (registry_name, registry_status, status_changed_at, status_message, first_seen_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (registry_name) DO UPDATE SET
                    registry_status = CASE WHEN EXCLUDED.last_seen_at >= servers.last_seen_at THEN EXCLUDED.registry_status ELSE servers.registry_status END,
                    status_changed_at = CASE WHEN EXCLUDED.last_seen_at >= servers.last_seen_at THEN EXCLUDED.status_changed_at ELSE servers.status_changed_at END,
                    status_message = CASE WHEN EXCLUDED.last_seen_at >= servers.last_seen_at THEN EXCLUDED.status_message ELSE servers.status_message END,
                    first_seen_at = LEAST(servers.first_seen_at, EXCLUDED.first_seen_at),
                    last_seen_at = GREATEST(servers.last_seen_at, EXCLUDED.last_seen_at)
                """,
                server_rows,
            )
            server_ids = dict(conn.execute("SELECT registry_name, server_id FROM servers").fetchall())
            for row in version_rows:
                row["server_id"] = server_ids[row["name"]]
            cursor.executemany(
                f"""
                INSERT INTO server_versions (server_id, version, title, description, website_url, schema_url, is_latest, published_at, updated_at,
                    publisher_meta, icons, registry_record, observed_at, run_id, search_vector)
                VALUES (%(server_id)s, %(version)s, %(title)s, %(description)s, %(website)s, %(schema)s, %(is_latest)s, %(published)s, %(updated)s,
                    %(publisher_meta)s, %(icons)s, %(record)s, %(observed)s, %(run_id)s, {SEARCH_VECTOR})
                ON CONFLICT (server_id, version) DO UPDATE SET
                    title = EXCLUDED.title, description = EXCLUDED.description, website_url = EXCLUDED.website_url, schema_url = EXCLUDED.schema_url,
                    is_latest = EXCLUDED.is_latest, published_at = EXCLUDED.published_at, updated_at = EXCLUDED.updated_at,
                    publisher_meta = EXCLUDED.publisher_meta, icons = EXCLUDED.icons, registry_record = EXCLUDED.registry_record,
                    observed_at = GREATEST(server_versions.observed_at, EXCLUDED.observed_at), run_id = EXCLUDED.run_id, search_vector = EXCLUDED.search_vector
                """,
                version_rows,
            )
            conn.execute(
                """
                UPDATE servers s SET latest_version_id = x.server_version_id
                FROM (SELECT DISTINCT ON (server_id) server_id, server_version_id FROM server_versions
                      ORDER BY server_id, is_latest DESC NULLS LAST, published_at DESC NULLS LAST, server_version_id DESC) x
                WHERE s.server_id = x.server_id AND s.latest_version_id IS DISTINCT FROM x.server_version_id
                """
            )
            version_ids = {(server_id, version): version_id for version_id, server_id, version in
                           conn.execute("SELECT server_version_id, server_id, version FROM server_versions").fetchall()}
            repo_rows, link_rows, package_rows, declaration_rows, endpoint_rows = {}, [], {}, [], []
            for name, (entry, _, _) in sorted(entries.items()):
                server = entry["server"]
                version_id = version_ids[(server_ids[name], server["version"].strip())]
                repository = server.get("repository") or {}
                repo = canonical_repository(repository.get("url"))
                if repo:
                    repo_rows.setdefault(repo["canonical_url"], repo)
                    link_rows.append((version_id, repo["canonical_url"], clean_subfolder(repository.get("subfolder")), repository["url"].strip(),
                                      repository.get("source"), str(repository["id"]) if repository.get("id") is not None else None))
                elif repository.get("url"):
                    errors.append((f"{name}@{server['version']}", "repository.url could not be parsed; no repository linked"))
                for position, package in enumerate(server.get("packages") or []):
                    kind = (package.get("registryType") or "").strip().lower() or "unknown"
                    identifier = (package.get("identifier") or "").strip()
                    if not identifier:
                        errors.append((f"{name}@{server['version']}", f"package {position} has no identifier; declaration skipped"))
                        continue
                    normalized = normalize_package_name(kind, identifier)
                    package_rows.setdefault((kind, normalized), identifier)
                    declared_version = (package.get("version") or "").strip() or None
                    exact = is_exact_version(declared_version)
                    config = {key: package[key] for key in ("transport", "environmentVariables", "packageArguments", "runtimeArguments") if package.get(key)}
                    declaration_rows.append({
                        "version_id": version_id, "position": position, "kind": kind, "normalized": normalized, "identifier": identifier,
                        "declared_version": declared_version, "exact": exact, "base_url": package.get("registryBaseUrl"),
                        "transport": (package.get("transport") or {}).get("type"), "runtime_hint": package.get("runtimeHint"),
                        "sha": package.get("fileSha256"), "config": Jsonb(redact_secrets(config)) if config else None,
                    })
                for position, remote in enumerate(server.get("remotes") or []):
                    url = (remote.get("url") or "").strip()
                    if not url:
                        errors.append((f"{name}@{server['version']}", f"remote {position} has no URL; endpoint skipped"))
                        continue
                    config = {key: remote[key] for key in ("headers", "variables") if remote.get(key)}
                    endpoint_rows.append((version_id, position, url, normalize_endpoint(url), (remote.get("type") or "unknown").strip(), "{" in url,
                                          any(header.get("isSecret") for header in remote.get("headers") or []),
                                          Jsonb(redact_secrets(config)) if config else None))
            cursor.executemany(
                "INSERT INTO repositories (host, canonical_url, owner, name) VALUES (%s, %s, %s, %s) ON CONFLICT (canonical_url) DO NOTHING",
                [(r["host"], r["canonical_url"], r["owner"], r["name"]) for r in repo_rows.values()],
            )
            repo_ids = dict(conn.execute("SELECT canonical_url, repository_id FROM repositories").fetchall())
            cursor.executemany(
                """
                INSERT INTO server_repositories (server_version_id, repository_id, subfolder, declared_url, declared_source, declared_repository_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (server_version_id, repository_id, subfolder) DO UPDATE SET declared_url = EXCLUDED.declared_url,
                    declared_source = EXCLUDED.declared_source, declared_repository_id = EXCLUDED.declared_repository_id
                """,
                [(version_id, repo_ids[url], subfolder, declared, source, declared_id) for version_id, url, subfolder, declared, source, declared_id in link_rows],
            )
            cursor.executemany(
                "INSERT INTO packages (ecosystem, normalized_name, display_name) VALUES (%s, %s, %s) ON CONFLICT (ecosystem, normalized_name) DO NOTHING",
                [(kind, normalized, display) for (kind, normalized), display in package_rows.items()],
            )
            package_ids = {(kind, normalized): package_id for package_id, kind, normalized in
                           conn.execute("SELECT package_id, ecosystem, normalized_name FROM packages").fetchall()}
            exact_versions = sorted({(package_ids[(d["kind"], d["normalized"])], d["declared_version"]) for d in declaration_rows if d["exact"]})
            cursor.executemany("INSERT INTO package_versions (package_id, version) VALUES (%s, %s) ON CONFLICT (package_id, version) DO NOTHING", exact_versions)
            version_lookup = {(package_id, version): pv_id for pv_id, package_id, version in
                              conn.execute("SELECT package_version_id, package_id, version FROM package_versions").fetchall()}
            for d in declaration_rows:
                d["package_id"] = package_ids[(d["kind"], d["normalized"])]
                d["package_version_id"] = version_lookup.get((d["package_id"], d["declared_version"])) if d["exact"] else None
            cursor.executemany(
                """
                INSERT INTO server_package_declarations (server_version_id, position, package_id, package_version_id, registry_type, declared_identifier,
                    declared_version, version_is_exact, registry_base_url, transport_type, runtime_hint, file_sha256, config)
                VALUES (%(version_id)s, %(position)s, %(package_id)s, %(package_version_id)s, %(kind)s, %(identifier)s, %(declared_version)s, %(exact)s,
                    %(base_url)s, %(transport)s, %(runtime_hint)s, %(sha)s, %(config)s)
                ON CONFLICT (server_version_id, position) DO UPDATE SET package_id = EXCLUDED.package_id, package_version_id = EXCLUDED.package_version_id,
                    registry_type = EXCLUDED.registry_type, declared_identifier = EXCLUDED.declared_identifier, declared_version = EXCLUDED.declared_version,
                    version_is_exact = EXCLUDED.version_is_exact, registry_base_url = EXCLUDED.registry_base_url, transport_type = EXCLUDED.transport_type,
                    runtime_hint = EXCLUDED.runtime_hint, file_sha256 = EXCLUDED.file_sha256, config = EXCLUDED.config
                """,
                declaration_rows,
            )
            cursor.executemany(
                """
                INSERT INTO remote_endpoints (server_version_id, position, url, normalized_url, transport_type, is_templated, declares_secret_header, config)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (server_version_id, position) DO UPDATE SET url = EXCLUDED.url, normalized_url = EXCLUDED.normalized_url,
                    transport_type = EXCLUDED.transport_type, is_templated = EXCLUDED.is_templated,
                    declares_secret_header = EXCLUDED.declares_secret_header, config = EXCLUDED.config
                """,
                endpoint_rows,
            )
        counts = {
            "records_read": records_read,
            "servers": len(server_rows), "server_versions": len(version_rows), "repository_links": len(link_rows),
            "distinct_repositories": len(repo_rows), "package_declarations": len(declaration_rows), "distinct_packages": len(package_rows),
            "exact_package_versions": len(exact_versions), "remote_endpoints": len(endpoint_rows),
            "status": {status: sum(1 for row in server_rows if row[1] == status) for status in ("active", "deprecated", "deleted")},
        }
        finish_run(conn, run_id, counts, errors)
        conn.commit()
    print(json.dumps({"run_id": run_id, "counts": counts, "errors": len(errors)}, indent=2))


if __name__ == "__main__":
    main()
