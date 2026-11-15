import argparse
import csv
import gzip
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

csv.field_size_limit(sys.maxsize)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_common import (
    OFFICIAL, PUBLISHER, ROOT, canonical_repository, find_tool_lists, github_parts, is_exact_version,
    normalize_package_name,
)

RESEARCH = ROOT / "data" / "research"
STUDY = RESEARCH / "registry_study"
CACHE = RESEARCH / "cache" / "http"
DOWNLOADS = RESEARCH / "cache" / "downloads"
SNAPSHOT = STUDY / "data" / "registry_snapshot.jsonl.gz"
SNAPSHOT_META = STUDY / "data" / "registry_snapshot_meta.json"
FULL_MATCH = STUDY / "results" / "full_match_results.csv.gz"
FULL_DEPENDENCIES = STUDY / "results" / "full_resolved_dependencies.csv.gz"
FULL_RESPONSES = RESEARCH / "cache" / "full_responses.jsonl.gz"
FULL_SOURCES = {"deps.dev (package version)", "deps.dev (dependency graph)", "OSV.dev (declared package version)", "OSV.dev (resolved dependencies)"}
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
ALLOWED_HOSTS = {"api.osv.dev", "api.deps.dev", "services.nvd.nist.gov", "cveawg.mitre.org", "api.first.org"}
CONTROL_ECOSYSTEM = {"npm": "npm", "PyPI": "pypi"}


def read_csv(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def cache_key(method, url, params=None, payload=None, headers=None, parse="json"):
    return hashlib.sha256(json.dumps([method, url, params, payload, headers, parse], sort_keys=True).encode()).hexdigest()


def load_cache(full=True):
    records = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(CACHE.glob("*.json"))]
    newer = {}
    if full and FULL_RESPONSES.exists():
        with gzip.open(FULL_RESPONSES, "rt", encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                newer[record.get("final_url") or record.get("url") or ""] = record
    records = [r for r in records if (r.get("final_url") or r.get("url") or "") not in newer] + list(newer.values())
    index = defaultdict(list)
    for record in records:
        url = record.get("final_url") or record.get("url") or ""
        host = urlsplit(url).hostname or ""
        if host in ALLOWED_HOSTS:
            index[host].append((url, record))
    return index


def replay_osv_query(ecosystem, name, version):
    path = CACHE / f"{cache_key('POST', OSV_QUERY_URL, payload={'package': {'name': name, 'ecosystem': ecosystem}, 'version': version})}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def parse_ref(text):
    text = (text or "").strip()
    if ":" not in text or "@" not in text:
        return None
    kind, rest = text.split(":", 1)
    if kind.startswith("http"):
        return None
    name, _, version = rest.rpartition("@")
    return {"registry_type": kind.lower(), "identifier": name, "version": version}


def declared_packages(entry):
    packages = []
    for position, package in enumerate((entry.get("server") or {}).get("packages") or []):
        kind = (package.get("registryType") or "").strip().lower()
        identifier = (package.get("identifier") or "").strip()
        packages.append({"position": position, "registry_type": kind, "identifier": identifier,
                         "normalized": normalize_package_name(kind, identifier), "version": (package.get("version") or "").strip()})
    return packages


def ghsa_ref(packages, identifier):
    kind = next((p["registry_type"] for p in packages if f"{p['identifier']}@{p['version']}" == identifier
                 or f"{p['normalized']}@{p['version']}" == identifier), None)
    name, _, version = identifier.rpartition("@")
    return {"registry_type": kind, "identifier": name, "version": version} if kind else None


def find_position(packages, ref):
    if not ref:
        return None
    kind = ref["registry_type"]
    wanted = normalize_package_name(kind, ref["identifier"])
    for package in packages:
        if package["registry_type"] == kind and package["normalized"].lower() == wanted.lower() and package["version"] == ref["version"]:
            return package["position"]
    return None


def check(entry, check_type, scope, source, outcome, method=None, reason=None, checked_at=None, position=None, repository_url=None, details=None, key_suffix=""):
    server = entry["server"]
    key = "|".join(str(part) for part in (check_type, server["name"], server["version"], source, scope, position if position is not None else "", key_suffix))
    return {"kind": "check", "check_key": key, "server_name": server["name"], "server_version": server["version"], "check_type": check_type,
            "check_scope": scope, "source": source, "outcome": outcome, "method": method, "reason": reason or None, "checked_at": checked_at or None,
            "position": position, "repository_url": repository_url, "details": details}


def match_rows(rows, entries_by_name):
    records = []
    outcome_map = {"Matched": "evidence_found", "Not found": "not_found", "Missing identifier": "missing_identifier", "API error": "error",
                   "Authentication required": "access_restricted", "Access restricted": "access_restricted"}
    advisory_map = {"Matched": "finding_found", "No known vulnerabilities": "no_known_finding", "Missing identifier": "missing_identifier",
                    "API error": "error", "Not found": "not_found"}
    for row in rows:
        entry = entries_by_name.get(row["server_name"])
        if not entry or entry["server"]["version"] != row["server_version"]:
            continue
        source, status, reason = row["target_source"], row["match_status"], row["failure_reason"]
        fields = json.loads(row["retrieved_fields"]) if row["retrieved_fields"] else {}
        packages = declared_packages(entry)
        when = row["requested_at"] or None
        if source == "GitHub REST API":
            repo_url = ((entry["server"].get("repository") or {}).get("url") or "").strip() or None
            records.append(check(entry, "repository_metadata", "repository" if repo_url else "server", "github", outcome_map.get(status, "error"),
                                 row["matching_method"], reason, when, repository_url=repo_url, details={"http_status": row["http_status"] or None}))
            if status in ("Matched", "Not found"):
                records.append({"kind": "github_repository", "server_name": row["server_name"], "server_version": row["server_version"],
                                "repository_url": repo_url, "matched_slug": row["matching_identifier"], "status": status,
                                "github_id": row["source_record_id"] or None, "fields": fields, "observed_at": when,
                                "http_status": row["http_status"] or None, "source_url": row["source_reference"] or None})
        elif source in ("npm Registry", "PyPI", "deps.dev (package version)"):
            if status == "Not applicable":
                if source == "deps.dev (package version)" and "registryType" in reason:
                    ref = parse_ref(row["matching_identifier"])
                    records.append(check(entry, "package_metadata", "package_declaration", "deps_dev", "unsupported", row["matching_method"], reason,
                                         when, find_position(packages, ref)))
                continue
            key = {"npm Registry": "npm", "PyPI": "pypi", "deps.dev (package version)": "deps_dev"}[source]
            if key == "npm":
                name, _, version = row["matching_identifier"].rpartition("@")
                ref = {"registry_type": "npm", "identifier": name, "version": version}
            elif key == "pypi":
                name, _, version = row["matching_identifier"].partition("==")
                ref = {"registry_type": "pypi", "identifier": name, "version": version}
            else:
                ref = parse_ref(row["matching_identifier"])
            position = find_position(packages, ref)
            records.append(check(entry, "package_metadata", "package_declaration", key, outcome_map.get(status, "error"), row["matching_method"],
                                 reason, when, position, details={"http_status": row["http_status"] or None}))
            if status in ("Matched", "Not found") and ref:
                records.append({"kind": "package_metadata", "source": key, "server_name": row["server_name"], "server_version": row["server_version"],
                                "position": position, "registry_type": ref["registry_type"], "identifier": ref["identifier"], "version": ref["version"],
                                "status": status, "fields": fields, "observed_at": when, "http_status": row["http_status"] or None,
                                "source_url": row["source_reference"] or None})
        elif source == "deps.dev (dependency graph)":
            ref = parse_ref(row["matching_identifier"])
            position = find_position(packages, ref)
            if status == "Not applicable":
                remote_only = "remote-only" in reason
                records.append(check(entry, "dependency_resolution", "server" if remote_only else "package_declaration", "deps_dev",
                                     "not_applicable" if remote_only else "unsupported", row["matching_method"], reason, when, position))
                continue
            outcome = "evidence_found" if status == "Matched" else ("not_found" if status == "Not found" else outcome_map.get(status, "error"))
            records.append(check(entry, "dependency_resolution", "package_declaration", "deps_dev", outcome, row["matching_method"], reason, when, position,
                                 details=fields or None))
        elif source in ("OSV.dev (declared package version)", "GitHub Advisory Database (declared package version)"):
            key = "osv" if source.startswith("OSV") else "ghsa"
            ref = parse_ref(row["matching_identifier"]) if key == "osv" else ghsa_ref(packages, row["matching_identifier"])
            if status == "Not applicable":
                remote_only = "remote-only" in reason
                records.append(check(entry, "direct_package_advisories", "server" if remote_only else "package_declaration", key,
                                     "not_applicable" if remote_only else "unsupported", row["matching_method"], reason, when,
                                     None if remote_only else find_position(packages, ref)))
                continue
            position = find_position(packages, ref)
            records.append(check(entry, "direct_package_advisories", "package_declaration", key, advisory_map.get(status, "error"),
                                 row["matching_method"], reason, when, position,
                                 details={"advisory_ids": fields.get("advisory_ids")} if key == "osv" and fields.get("advisory_ids") else
                                 ({k: v for k, v in fields.items() if k != "cve_ids"} or None)))
            if key == "osv" and status in ("Matched", "No known vulnerabilities") and ref:
                records.append({"kind": "osv_query", "context": "declared_package", "server_name": row["server_name"],
                                "server_version": row["server_version"], "position": position, "registry_type": ref["registry_type"],
                                "identifier": ref["identifier"], "version": ref["version"], "ids": fields.get("advisory_ids") or [],
                                "observed_at": when, "method": "OSV querybatch, exact ecosystem/name/version",
                                "source_url": row["source_reference"] or None})
        elif source == "OSV.dev (resolved dependencies)":
            if status == "Not applicable":
                records.append(check(entry, "dependency_advisories", "server", "osv", "not_applicable", row["matching_method"], reason, when))
        elif source == "Glama":
            records.append(check(entry, "tool_metadata", "server", "glama", "access_restricted", row["matching_method"], reason, when))
    return records


def dependency_records(rows, entries_by_name, osv_times, graph_roots):
    records = []
    by_root = defaultdict(list)
    for row in rows:
        by_root[(row["server_name"], row["package"])].append(row)
    for (server_name, root), nodes in sorted(by_root.items()):
        entry = entries_by_name.get(server_name)
        if not entry:
            continue
        ref = parse_ref(root)
        position = find_position(declared_packages(entry), ref)
        when = osv_times.get(server_name)
        vulnerable = [node for node in nodes if node["osv_advisory_ids"].strip() and node["relation"] != "SELF"]
        failed = [node for node in nodes if node["osv_status"] != "queried"]
        for node in vulnerable:
            records.append({"kind": "dependency_node", "server_name": server_name, "server_version": entry["server"]["version"], "position": position,
                            "root": ref, "system": node["system"], "name": node["dependency"], "version": node["dependency_version"],
                            "relation": node["relation"], "ids": [value.strip() for value in node["osv_advisory_ids"].split(",") if value.strip()],
                            "observed_at": when})
        outcome = "finding_found" if vulnerable else ("error" if failed else "no_known_finding")
        records.append(check(entry, "dependency_advisories", "package_declaration", "osv", outcome,
                             "OSV querybatch over every resolved dependency version",
                             f"{len(failed)} dependency queries failed" if failed else None, when, position,
                             details={"dependency_versions_queried": len(nodes) - len(failed), "vulnerable_dependency_versions": len(vulnerable)}))
        graph_roots.add((server_name, position))
    return records


def missing_graph_checks(match_rows_list, entries_by_name, graph_roots):
    records = []
    for row in match_rows_list:
        if row["target_source"] != "deps.dev (dependency graph)":
            continue
        entry = entries_by_name.get(row["server_name"])
        if not entry:
            continue
        position = find_position(declared_packages(entry), parse_ref(row["matching_identifier"]))
        if row["match_status"] == "Not applicable":
            if "registryType" in row["failure_reason"]:
                records.append(check(entry, "dependency_advisories", "package_declaration", "osv", "unsupported", "dependency ecosystem/name/version",
                                     f"no dependency graph can be resolved: {row['failure_reason']}", None, position))
            continue
        if row["match_status"] == "Matched" and (row["server_name"], position) in graph_roots:
            continue
        fields = json.loads(row["retrieved_fields"]) if row["retrieved_fields"] else {}
        if row["match_status"] == "Matched" and fields.get("dependency_nodes") == 0:
            records.append(check(entry, "dependency_advisories", "package_declaration", "osv", "no_known_finding",
                                 "resolved graph contains no dependency nodes", None, row["requested_at"], position,
                                 details={"dependency_versions_queried": 0}))
            continue
        records.append(check(entry, "dependency_advisories", "package_declaration", "osv", "missing_identifier",
                             "dependency ecosystem/name/version", "no resolved dependency graph available from deps.dev", None, position))
    return records


def control_records(validation, controls, entries_by_name):
    records = []
    control_by_id = {row["control_id"]: row for row in controls}
    for row in validation:
        if row["check"] != "Registry-declared version check":
            continue
        server_name, _, target = row["subject"].partition(" -> ")
        package, _, version = target.rpartition("@")
        control = control_by_id[row["control_id"]]
        result = replay_osv_query(control["ecosystem"], package, version)
        entry = entries_by_name.get(server_name.strip())
        if not result or result.get("status") != 200 or not entry:
            continue
        ids = [item["id"] for item in (result.get("body") or {}).get("vulns") or []]
        kind = CONTROL_ECOSYSTEM[control["ecosystem"]]
        position = find_position(declared_packages(entry), {"registry_type": kind, "identifier": package, "version": version})
        records.append({"kind": "osv_query", "context": "registry_positive_control_check", "server_name": entry["server"]["name"],
                        "server_version": entry["server"]["version"], "position": position, "registry_type": kind, "identifier": package,
                        "version": version, "ids": ids, "observed_at": result.get("fetched_at"),
                        "method": "OSV /v1/query, exact ecosystem/name/version (positive-control registry check)",
                        "source_url": f"https://osv.dev/list?ecosystem={control['ecosystem']}&q={package}"})
        records.append(check(entry, "direct_package_advisories", "package_declaration", "osv", "finding_found" if ids else "no_known_finding",
                             "OSV /v1/query, exact ecosystem/name/version (positive-control registry check)", None,
                             result.get("fetched_at"), position, details={"advisory_ids": ids, "control_id": row["control_id"]},
                             key_suffix="positive-control"))
    return records


def cache_records(cache):
    records = []
    for url, record in cache["api.osv.dev"]:
        if "/v1/vulns/" in url and record.get("status") == 200 and isinstance(record.get("body"), dict):
            records.append({"kind": "osv_record", "id": record["body"]["id"], "observed_at": record.get("fetched_at"), "url": url, "body": record["body"]})
    for url, record in cache["api.deps.dev"]:
        path = urlsplit(url).path
        if not path.endswith(":dependencies"):
            continue
        match = re.match(r"^/v3/systems/([^/]+)/packages/([^/]+)/versions/(.+):dependencies$", path)
        if not match:
            continue
        system, name, version = (unquote(part) for part in match.groups())
        records.append({"kind": "depsdev_graph", "system": system.upper(), "name": name, "version": version, "observed_at": record.get("fetched_at"),
                        "status": record.get("status"), "url": url, "body": record.get("body") if record.get("status") == 200 else None})
    for url, record in cache["services.nvd.nist.gov"]:
        cve = (parse_qs(urlsplit(url).query).get("cveId") or [None])[0]
        if cve:
            records.append({"kind": "nvd_record", "cve_id": cve, "observed_at": record.get("fetched_at"), "status": record.get("status"), "url": url,
                            "body": record.get("body") if record.get("status") == 200 else None})
    for url, record in cache["cveawg.mitre.org"]:
        cve = urlsplit(url).path.rsplit("/", 1)[-1]
        if cve.startswith("CVE-"):
            records.append({"kind": "cveorg_record", "cve_id": cve, "observed_at": record.get("fetched_at"), "status": record.get("status"),
                            "url": url, "body": record.get("body") if record.get("status") == 200 else None})
    for url, record in cache["api.first.org"]:
        queried = [value for item in parse_qs(urlsplit(url).query).get("cve") or [] for value in item.split(",") if value]
        if queried and record.get("status") == 200:
            records.append({"kind": "epss_response", "observed_at": record.get("fetched_at"), "url": url, "cves_queried": queried,
                            "data": (record.get("body") or {}).get("data") or []})
    return records


def kev_record():
    meta = json.loads((DOWNLOADS / "cisa_kev.json.meta.json").read_text(encoding="utf-8"))
    catalog = json.loads((DOWNLOADS / "cisa_kev.json").read_text(encoding="utf-8"))
    entries = [{"cveID": item["cveID"], "dateAdded": item.get("dateAdded"), "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse")}
               for item in catalog.get("vulnerabilities") or []]
    return {"kind": "kev_catalog", "observed_at": meta["fetched_at"], "url": meta["url"], "sha256": meta["sha256"],
            "catalog_version": catalog.get("catalogVersion"), "date_released": catalog.get("dateReleased"), "count": catalog.get("count"),
            "entries": entries}


def agora_records(names):
    meta = json.loads((DOWNLOADS / "agora_servers.csv.meta.json").read_text(encoding="utf-8"))
    records = []
    for row in read_csv(DOWNLOADS / "agora_servers.csv"):
        if row["name"] in names:
            records.append({"kind": "agora_row", "name": row["name"], "endpoint": row["endpoint"] or None, "check_result": row["check_result"] or None,
                            "check_class": row["check_class"] or None, "checked_at": row["checked_at"] or None, "protocol": row["protocol"] or None,
                            "tool_count": row["tool_count"] or None, "registry_status": row["registry_status"] or None,
                            "observed_at": meta["fetched_at"], "csv_sha256": meta["sha256"]})
    return records


def tool_and_catalog_records(entries, flags):
    records = []
    pl_meta = json.loads((DOWNLOADS / "policylayer_tools.jsonl.meta.json").read_text(encoding="utf-8"))
    pl_servers = {}
    with open(DOWNLOADS / "policylayer_servers.jsonl", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                item = json.loads(line)
                pl_servers[item["slug"]] = item
    pl_tools = defaultdict(list)
    with open(DOWNLOADS / "policylayer_tools.jsonl", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                item = json.loads(line)
                pl_tools[item["server_slug"]].append(item)
    th_items = {}
    for file_name in ("toolhive_registry.json", "toolhive_official.json"):
        meta = json.loads((DOWNLOADS / f"{file_name}.meta.json").read_text(encoding="utf-8"))
        for item in json.loads((DOWNLOADS / file_name).read_text(encoding="utf-8"))["data"]["servers"]:
            provided = ((item.get("_meta") or {}).get(PUBLISHER) or {})
            extension = next((value for vendor in provided.values() for value in (vendor or {}).values()), {}) if provided else {}
            th_items[f"{file_name.removesuffix('.json')}:{item.get('name')}"] = (item, extension, meta)
    for entry in entries:
        server = entry["server"]
        name = server["name"]
        status = ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("status")
        publisher = (server.get("_meta") or {}).get(PUBLISHER) or {}
        tools = [tool for tool in find_tool_lists(publisher) if isinstance(tool, dict) and tool.get("name")]
        if tools:
            records.append({"kind": "tool_listing", "source": "mcp_registry", "server_name": name, "server_version": server["version"],
                            "declaration_kind": "publisher_declared", "match_confidence": "high", "match_method": "registry record publisher _meta",
                            "source_record_id": f"{name}@{server['version']}", "observed_at": ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("updatedAt"),
                            "source_url": None,
                            "tools": [{"name": t.get("name"), "description": t.get("description"), "input_schema": t.get("inputSchema", t.get("input_schema")),
                                       "output_schema": t.get("outputSchema"), "annotations": t.get("annotations")} for t in tools]})
        if status == "deleted":
            continue
        flag = flags.get(name)
        if flag is None:
            continue
        packages = declared_packages(entry)
        has_package = any(p["identifier"] for p in packages)
        has_github = github_parts(((server.get("repository") or {}).get("url") or "")) is not None
        has_remote = bool(server.get("remotes"))
        pl_status = flag["PolicyLayer"]
        if pl_status.startswith("Matched"):
            confidence = "high" if "(high)" in pl_status else "medium"
            slugs = [slug.strip() for slug in flag["PolicyLayer ids"].split(",") if slug.strip()]
            tools = [tool for slug in slugs for tool in pl_tools.get(slug, [])]
            scanned = [pl_servers[slug].get("last_scanned_at") for slug in slugs if slug in pl_servers and pl_servers[slug].get("last_scanned_at")]
            records.append({"kind": "tool_listing", "source": "policylayer", "server_name": name, "server_version": server["version"],
                            "declaration_kind": "third_party_observed", "match_confidence": confidence,
                            "match_method": "exact package identifier or repository + subfolder",
                            "source_record_id": ", ".join(slugs), "observed_at": max(scanned) if scanned else pl_meta["fetched_at"],
                            "source_url": "https://huggingface.co/datasets/PolicyLayer/mcp-server-catalogue",
                            "entry": {slug: {key: pl_servers[slug].get(key) for key in ("name", "categories", "source", "confidence", "tool_count", "last_scanned_at")}
                                      for slug in slugs if slug in pl_servers},
                            "tools": [{"name": t.get("name"), "description": t.get("description"), "input_schema": t.get("input_schema"),
                                       "classification": {"category": t.get("category"), "severity": t.get("severity"), "risk_weight": t.get("risk_weight"),
                                                          "risk_type": t.get("risk_type"), "classifier_confidence": t.get("confidence")}} for t in tools]})
            records.append(check(entry, "tool_metadata", "server", "policylayer", "evidence_found" if tools else "not_found",
                                 "exact package identifier or repository + subfolder", None if tools else "matched catalogue entry lists no tools",
                                 pl_meta["fetched_at"], details={"match_confidence": confidence, "tools": len(tools)}))
        elif not has_package and not has_github:
            records.append(check(entry, "tool_metadata", "server", "policylayer", "missing_identifier", "package identifier / GitHub repository",
                                 "no package identifier or GitHub repository", pl_meta["fetched_at"]))
        else:
            records.append(check(entry, "tool_metadata", "server", "policylayer", "not_found", "exact package identifier or repository + subfolder",
                                 "only a low-confidence repository-level candidate exists" if pl_status else "no PolicyLayer entry shares an identifier",
                                 pl_meta["fetched_at"], details={"possible_match_ids": flag["PolicyLayer ids"]} if pl_status else None))
        th_status = flag["ToolHive Registry"]
        th_fetched = th_items[next(iter(th_items))][2]["fetched_at"] if th_items else None
        if th_status in ("exact", "repository+subfolder"):
            ids = [value.strip() for value in flag["ToolHive Registry ids"].split(",") if value.strip()]
            item, extension, meta = th_items[ids[0]]
            definitions = extension.get("tool_definitions") or []
            names_only = [] if definitions else [{"name": tool} if isinstance(tool, str) else tool for tool in extension.get("tools") or []]
            tools = [{"name": t.get("name"), "description": t.get("description"), "input_schema": t.get("inputSchema"),
                      "output_schema": t.get("outputSchema"), "annotations": t.get("annotations")} for t in definitions or names_only if t.get("name")]
            records.append({"kind": "tool_listing", "source": "toolhive", "server_name": name, "server_version": server["version"],
                            "declaration_kind": "curator_declared", "match_confidence": "high" if th_status == "exact" else "medium",
                            "match_method": "exact remote URL / OCI image / package" if th_status == "exact" else "repository + subfolder",
                            "source_record_id": ids[0], "observed_at": (extension.get("metadata") or {}).get("last_updated") or meta["fetched_at"],
                            "source_url": meta["url"],
                            "entry": {"tier": extension.get("tier"), "status": extension.get("status"), "permissions": extension.get("permissions"),
                                      "has_provenance": bool(extension.get("provenance")), "matched_ids": ids},
                            "tools": tools})
            records.append(check(entry, "tool_metadata", "server", "toolhive", "evidence_found" if tools else "not_found",
                                 "remote URL / OCI image / package / repository + subfolder", None if tools else "catalog entry lists no tools",
                                 th_fetched, details={"match": th_status, "tools": len(tools)}))
        elif not has_package and not has_github and not has_remote and not (server.get("repository") or {}).get("url"):
            records.append(check(entry, "tool_metadata", "server", "toolhive", "missing_identifier", "remote URL / package / repository",
                                 "record has no identifier this catalog can be matched on", th_fetched))
        else:
            records.append(check(entry, "tool_metadata", "server", "toolhive", "not_found", "remote URL / OCI image / package / repository + subfolder",
                                 "only a repository-level candidate exists" if th_status else "no catalog entry shares an exact identifier", th_fetched))
        records.append(check(entry, "endpoint_status", "server", "agora", "evidence_found" if flag["agora"] == "True" else "not_found",
                             "exact registry name in the Agora CSV", None if flag["agora"] == "True" else "registry name not present in the Agora CSV",
                             None, details={"check_class": flag["agora_check_class"] or None}))
    return records


def select_seed(entries, entries_by_name, match_rows_list, validation, records):
    chosen = {}

    def add(name, reason):
        if name in entries_by_name and name not in chosen:
            chosen[name] = reason

    for row in match_rows_list:
        if row["target_source"].startswith("OSV.dev") and row["match_status"] == "Matched":
            add(row["server_name"], "sample server with OSV findings")
    for row in validation:
        if row["check"] == "Registry-declared version check":
            add(row["subject"].partition(" -> ")[0].strip(), "registry server matched by a positive-control package")
    osv_packages = set()
    for record in records:
        if record["kind"] == "osv_record":
            for affected in record["body"].get("affected") or []:
                package = affected.get("package") or {}
                ecosystem = {"npm": "npm", "PyPI": "pypi"}.get(package.get("ecosystem"))
                if ecosystem:
                    osv_packages.add((ecosystem, normalize_package_name(ecosystem, package.get("name"))))
    for entry in entries:
        for package in declared_packages(entry):
            if (package["registry_type"], package["normalized"]) in osv_packages and is_exact_version(package["version"]):
                add(entry["server"]["name"], "declares a package named in a stored OSV record")
    neo4j = [entry["server"]["name"] for entry in entries if canonical_repository((entry["server"].get("repository") or {}).get("url"))
             and canonical_repository((entry["server"].get("repository") or {}).get("url"))["canonical_url"] == "https://github.com/neo4j-contrib/mcp-neo4j"]
    for name in neo4j:
        add(name, "shared repository (neo4j-contrib/mcp-neo4j)")
    tool_servers = [record for record in records if record["kind"] == "tool_listing" and record["source"] in ("policylayer", "toolhive")]
    for record in [r for r in tool_servers if r["source"] == "toolhive"][:4] + [r for r in tool_servers if r["source"] == "policylayer"][:8]:
        add(record["server_name"], f"tool metadata from {record['source']}")
    sample_a = read_csv(STUDY / "data" / "sample_a_random.csv")
    for row in sample_a[:70]:
        add(row["name"], "random sample (first 70 draws)")
    per_category = Counter()
    for row in read_csv(STUDY / "data" / "sample_b_targeted.csv"):
        if per_category[row["sample_b_category"]] < 2:
            per_category[row["sample_b_category"]] += 1
            add(row["name"], f"targeted sample: {row['sample_b_category']}")
    for status in ("deprecated", "deleted"):
        picked = [entry["server"]["name"] for entry in entries if ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("status") == status][:3]
        for name in picked:
            add(name, f"registry status {status}")
    return chosen


def filter_for_seed(records, names, entries_by_name):
    keep = [r for r in records if r.get("server_name") in names or r.get("name") in names]
    osv_ids = {i for r in keep if r["kind"] in ("osv_query", "dependency_node") for i in r["ids"]}
    controls = read_csv(STUDY / "data" / "positive_controls.csv")
    control_packages = {(CONTROL_ECOSYSTEM[row["ecosystem"]], normalize_package_name(CONTROL_ECOSYSTEM[row["ecosystem"]], row["package"])) for row in controls}
    seed_packages = {(p["registry_type"], p["normalized"]) for name in names for p in declared_packages(entries_by_name[name])}
    for record in records:
        if record["kind"] != "osv_record":
            continue
        packages = {({"npm": "npm", "PyPI": "pypi"}.get((a.get("package") or {}).get("ecosystem")), normalize_package_name(
            {"npm": "npm", "PyPI": "pypi"}.get((a.get("package") or {}).get("ecosystem"), ""), (a.get("package") or {}).get("name"))) for a in record["body"].get("affected") or []}
        if packages & control_packages or packages & seed_packages:
            osv_ids.add(record["id"])
    osv_records = [r for r in records if r["kind"] == "osv_record" and (r["id"] in osv_ids or osv_ids & set(r["body"].get("aliases") or []))]
    cves = {alias for r in osv_records for alias in [r["id"], *(r["body"].get("aliases") or [])] if alias.startswith("CVE-")}
    roots = {(r["registry_type"], normalize_package_name(r["registry_type"], r["identifier"]), r["version"]) for r in keep if r["kind"] == "osv_query"}
    roots |= {(r["root"]["registry_type"], normalize_package_name(r["root"]["registry_type"], r["root"]["identifier"]), r["root"]["version"])
              for r in keep if r["kind"] == "dependency_node" and r["root"]}
    graphs = [r for r in records if r["kind"] == "depsdev_graph" and (r["system"].lower(), normalize_package_name(r["system"].lower(), r["name"]), r["version"]) in roots]
    cve_records = [r for r in records if r["kind"] in ("nvd_record", "cveorg_record") and r["cve_id"] in cves]
    epss = []
    for r in records:
        if r["kind"] == "epss_response" and cves & set(r["cves_queried"]):
            epss.append({**r, "cves_queried": [c for c in r["cves_queried"] if c in cves], "data": [d for d in r["data"] if d.get("cve") in cves]})
    kev = [r for r in records if r["kind"] == "kev_catalog"]
    return keep + osv_records + graphs + cve_records + epss + kev


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    lines = []
    with gzip.open(SNAPSHOT, "rt", encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    entries = [json.loads(line) for line in lines]
    entries_by_name = {entry["server"]["name"]: entry for entry in entries}
    inventory = {name for name, entry in entries_by_name.items() if ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("status") != "deleted"}
    rows = read_csv(STUDY / "results" / "match_results.csv")
    full_rows = read_csv(FULL_MATCH) if FULL_MATCH.exists() else []
    full_servers = {row["server_name"] for row in full_rows}
    rows = [row for row in rows if not (row["target_source"] in FULL_SOURCES and row["server_name"] in full_servers)] + full_rows
    validation = read_csv(STUDY / "results" / "vulnerability_validation.csv")
    controls = read_csv(STUDY / "data" / "positive_controls.csv")
    flags = {row["name"]: row for row in read_csv(STUDY / "data" / "registry_offline_flags.csv.gz")}
    print("loading research cache", flush=True)
    cache = load_cache()
    records = cache_records(cache)
    records.append(kev_record())
    records.extend(match_rows(rows, entries_by_name))
    osv_times = {row["server_name"]: row["requested_at"] for row in rows if row["target_source"] == "OSV.dev (resolved dependencies)" and row["requested_at"]}
    graph_roots = set()
    for label in ("a", "b"):
        sample = [row for row in read_csv(STUDY / "results" / f"sample_{label}_resolved_dependencies.csv.gz") if row["server_name"] not in full_servers]
        records.extend(dependency_records(sample, entries_by_name, osv_times, graph_roots))
    if FULL_DEPENDENCIES.exists():
        records.extend(dependency_records(read_csv(FULL_DEPENDENCIES), entries_by_name, osv_times, graph_roots))
    records.extend(missing_graph_checks(rows, entries_by_name, graph_roots))
    records.extend(control_records(validation, controls, entries_by_name))
    for row in read_csv(STUDY / "results" / "pypi_provenance.csv"):
        if row["server_name"] in entries_by_name:
            records.append({"kind": "pypi_provenance", **row, "observed_at": row["fetched_at"]})
    records.extend(agora_records(inventory))
    records.extend(tool_and_catalog_records(entries, flags))
    seed_reasons = None
    if args.seed:
        original = [r for r in cache_records(load_cache(full=False)) if r["kind"] == "osv_record"] + [r for r in records if r["kind"] == "tool_listing"]
        seed_reasons = select_seed(entries, entries_by_name, read_csv(STUDY / "results" / "match_results.csv"), validation, original)
        records = filter_for_seed(records, set(seed_reasons), entries_by_name)
        lines = [line for line, entry in zip(lines, entries) if entry["server"]["name"] in seed_reasons]
    with gzip.GzipFile(out / "registry_snapshot.jsonl.gz", "wb", mtime=0) as handle:
        handle.write("".join(lines).encode("utf-8"))
    source_meta = json.loads(SNAPSHOT_META.read_text(encoding="utf-8"))
    meta = {key: source_meta.get(key) for key in ("source", "endpoint", "query_parameters", "collection_started_at", "collection_finished_at", "complete")}
    meta.update(records_collected=source_meta.get("record_count"), records_in_this_file=len(lines))
    (out / "registry_snapshot_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    records.sort(key=lambda r: json.dumps(r, sort_keys=True))
    with gzip.GzipFile(out / "evidence.jsonl.gz", "wb", mtime=0) as handle:
        for record in records:
            handle.write((json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    print(json.dumps({"registry_records": len(lines), "evidence_records": dict(sorted(Counter(r["kind"] for r in records).items()))}, indent=2))


if __name__ == "__main__":
    main()
