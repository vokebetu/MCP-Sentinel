import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from packaging.utils import canonicalize_name

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_common import OFFICIAL, is_exact_version

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "data" / "research"
STUDY = RESEARCH / "registry_study"
SNAPSHOT = STUDY / "data" / "registry_snapshot.jsonl.gz"
SHARED_CACHE = RESEARCH / "cache" / "http"
LOCAL_CACHE = ROOT / "research" / "cache" / "http_full"
MATCH_OUT = STUDY / "results" / "full_match_results.csv.gz"
DEPS_OUT = STUDY / "results" / "full_resolved_dependencies.csv.gz"
RESPONSES_OUT = RESEARCH / "cache" / "full_responses.jsonl.gz"
DEPS_DEV = "https://api.deps.dev/v3"
OSV_API = "https://api.osv.dev/v1"
CVE_API = "https://cveawg.mitre.org/api/cve"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
USER_AGENT = "mcp-sentinel-research/1.0 (university data source feasibility study)"
DEPS_SYSTEMS = {"npm": "npm", "pypi": "pypi", "nuget": "nuget", "cargo": "cargo"}
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "nuget": "NuGet", "cargo": "crates.io"}
DEPS_TO_OSV = {"NPM": "npm", "PYPI": "PyPI", "NUGET": "NuGet", "CARGO": "crates.io", "MAVEN": "Maven", "GO": "Go"}
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
MATCH_COLUMNS = ["sample", "record_index", "server_name", "server_version", "target_source", "matching_method", "matching_identifier",
                 "match_status", "identity_confidence", "source_record_id", "retrieved_fields", "requested_at", "http_status",
                 "failure_reason", "source_reference", "registry_package_versions", "evidence_type", "sample_b_category"]
DEPS_COLUMNS = ["record_index", "server_name", "package", "system", "dependency", "dependency_version", "relation", "resolution_errors",
                "osv_status", "osv_advisory_ids"]
EVIDENCE = {"deps.dev (package version)": "independently observed (deps.dev index)",
            "deps.dev (dependency graph)": "independently computed (deps.dev resolution)",
            "OSV.dev (declared package version)": "official advisory (aggregated)",
            "OSV.dev (resolved dependencies)": "official advisory (aggregated)"}
CALLS = Counter()
HITS = Counter()
LOCK = threading.Lock()
CLIENT = httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=httpx.Timeout(30, connect=10),
                      limits=httpx.Limits(max_connections=16, max_keepalive_connections=16))


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cache_key(method, url, params=None, payload=None):
    return hashlib.sha256(json.dumps([method, url, params, payload, None, "json"], sort_keys=True).encode()).hexdigest()


def fetch(url, params=None, payload=None, method="GET", spacing=0.0):
    key = cache_key(method, url, params, payload)
    host = httpx.URL(url).host
    for folder in (SHARED_CACHE, LOCAL_CACHE):
        path = folder / f"{key}.json"
        if path.exists():
            with LOCK:
                HITS[host] += 1
            return json.loads(path.read_text(encoding="utf-8"))
    result = {"url": url, "status": None, "error": "not_attempted", "body": None, "fetched_at": None, "content_type": None, "bytes": None,
              "final_url": None}
    for attempt in range(4):
        if spacing:
            time.sleep(spacing)
        with LOCK:
            CALLS[host] += 1
        try:
            response = CLIENT.request(method, url, params=params, json=payload)
        except httpx.HTTPError as error:
            result.update(error=type(error).__name__, fetched_at=utc_now())
            time.sleep(2 ** attempt)
            continue
        result.update(status=response.status_code, fetched_at=utc_now(), content_type=response.headers.get("Content-Type"),
                      bytes=len(response.content), final_url=str(response.url), error=None if response.is_success else f"http_{response.status_code}")
        if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
            retry = response.headers.get("Retry-After", "")
            time.sleep(min(int(retry), 120) if retry.isdigit() else 2 ** (attempt + 1))
            continue
        if response.is_success:
            try:
                result["body"] = response.json()
            except ValueError:
                result["error"] = "malformed_json"
        else:
            result["body"] = response.text[:300]
        break
    if result["status"] in (200, 404) and result["error"] in (None, f"http_{result['status']}"):
        LOCAL_CACHE.mkdir(parents=True, exist_ok=True)
        (LOCAL_CACHE / f"{key}.json").write_text(json.dumps(result), encoding="utf-8")
    return result


def parallel(function, items, workers):
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(function, items))


def compact(fields):
    kept = {k: v for k, v in (fields or {}).items() if v is not None and v != "" and v != [] and v != {}}
    return json.dumps(kept, sort_keys=True, default=str, ensure_ascii=False) if kept else None


def load_servers():
    servers = []
    with gzip.open(SNAPSHOT, "rt", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            entry = json.loads(line)
            if ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("status") == "deleted":
                continue
            server = entry["server"]
            targets = []
            for position, package in enumerate(server.get("packages") or []):
                kind = (package.get("registryType") or "").strip().lower()
                raw = (package.get("identifier") or "").strip()
                version = (package.get("version") or "").strip()
                name = canonicalize_name(raw) if kind == "pypi" else raw
                targets.append({"position": position, "kind": kind, "name": name, "version": version, "exact": is_exact_version(version),
                                "identifier": f"{kind}:{name}@{version}"})
            servers.append({"record_index": index, "name": server["name"], "version": server.get("version"), "targets": targets,
                            "declared": "; ".join(t["identifier"] for t in targets) or None})
    return servers


def row(server, source, method, identifier, status, confidence="none", source_id=None, fields=None, result=None, reason=None, reference=None):
    matched = status in ("Matched", "Possible match", "No known vulnerabilities")
    return {"sample": "full", "record_index": server["record_index"], "server_name": server["name"], "server_version": server["version"],
            "target_source": source, "matching_method": method, "matching_identifier": identifier, "match_status": status,
            "identity_confidence": confidence if matched else "none", "source_record_id": source_id, "retrieved_fields": compact(fields),
            "requested_at": (result or {}).get("fetched_at"), "http_status": (result or {}).get("status"), "failure_reason": reason,
            "source_reference": reference, "registry_package_versions": server["declared"], "evidence_type": EVIDENCE[source],
            "sample_b_category": None}


def failure(result):
    status = {401: "Authentication required", 403: "Access restricted", 404: "Not found"}.get(result["status"], "API error")
    reason = f"HTTP {result['status']}" if result["status"] else f"request failed ({result['error']})"
    return status, reason


def deps_dev_lookup(target):
    system = DEPS_SYSTEMS[target[0]]
    base = f"{DEPS_DEV}/systems/{system}/packages/{quote(target[1], safe='')}/versions/{quote(target[2], safe='')}"
    return fetch(base), fetch(base + ":dependencies")


def version_fields(body):
    return {"published_at": body.get("publishedAt"), "is_default": body.get("isDefault"), "is_deprecated": body.get("isDeprecated"),
            "licenses": body.get("licenses"), "advisory_keys": [item.get("id") for item in body.get("advisoryKeys") or []],
            "source_repo_links": [item.get("url") for item in body.get("links") or [] if item.get("label") == "SOURCE_REPO"],
            "related_projects": sorted({f"{item['projectKey']['id']} ({item.get('relationType')}, {item.get('relationProvenance')})"
                                        for item in body.get("relatedProjects") or []}),
            "slsa_provenance_count": len(body.get("slsaProvenances") or []), "attestation_count": len(body.get("attestations") or [])}


def graph_fields(body):
    nodes = body.get("nodes") or []
    relations = Counter(node.get("relation") for node in nodes)
    errors = [node for node in nodes if node.get("errors")]
    return {"dependency_nodes": len(nodes) - relations.get("SELF", 0), "direct": relations.get("DIRECT", 0), "indirect": relations.get("INDIRECT", 0),
            "edges": len(body.get("edges") or []), "nodes_with_errors": len(errors), "graph_error": body.get("error") or None,
            "bundled_nodes": sum(1 for node in nodes if node.get("bundled")), "complete": not body.get("error") and not errors}


def osv_batches(queries, workers):
    ordered = sorted(queries)
    chunks = [ordered[start:start + 1000] for start in range(0, len(ordered), 1000)]

    def run(chunk):
        payload = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        return chunk, fetch(f"{OSV_API}/querybatch", method="POST", payload=payload)

    answers = {}
    for chunk, result in parallel(run, chunks, workers):
        found = (result["body"] or {}).get("results") if result["status"] == 200 else None
        for position, query in enumerate(chunk):
            if found is None or position >= len(found):
                answers[query] = {"ok": False, "ids": [], "result": result}
            else:
                item = found[position] or {}
                answers[query] = {"ok": True, "ids": [v["id"] for v in item.get("vulns") or []], "truncated": bool(item.get("next_page_token")),
                                  "result": result}
    return answers


def main():
    parser = argparse.ArgumentParser(description="Look up every declared npm, PyPI, NuGet and Cargo package in deps.dev and OSV, then CVE details.")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--nvd", action="store_true", help="also query NVD for each new CVE (public limit: 5 requests per 30 s)")
    parser.add_argument("--limit", type=int, help="only the first N servers, for a trial run")
    args = parser.parse_args()
    started = time.time()
    servers = load_servers()[:args.limit] if args.limit else load_servers()
    targets = sorted({(t["kind"], t["name"], t["version"]) for s in servers for t in s["targets"] if t["kind"] in DEPS_SYSTEMS and t["exact"]})
    print(f"servers {len(servers):,}; package versions to look up {len(targets):,}", flush=True)

    looked = dict(zip(targets, parallel(deps_dev_lookup, targets, args.workers)))
    print(f"deps.dev done in {time.time() - started:.0f}s; calls {dict(CALLS)} cache hits {dict(HITS)}", flush=True)

    nodes, graph_ok = {}, {}
    for target, (info, graph) in looked.items():
        if graph["status"] == 200 and (graph["body"] or {}).get("nodes"):
            graph_ok[target] = graph_fields(graph["body"])
            nodes[target] = [((n.get("versionKey") or {}).get("system"), (n.get("versionKey") or {}).get("name"),
                              (n.get("versionKey") or {}).get("version"), n.get("relation"), "; ".join(n.get("errors") or []) or None)
                             for n in graph["body"]["nodes"] if n.get("relation") != "SELF"]
    direct = {t: (OSV_ECOSYSTEMS[t[0]], t[1], t[2]) for s in servers for t in [(x["kind"], x["name"], x["version"]) for x in s["targets"]
              if x["kind"] in OSV_ECOSYSTEMS and x["exact"]]}
    dependency_queries = {(DEPS_TO_OSV[system], name, version) for items in nodes.values() for system, name, version, _, _ in items
                          if system in DEPS_TO_OSV and version}
    answers = osv_batches(set(direct.values()) | dependency_queries, max(1, args.workers // 2))
    print(f"OSV querybatch done: {len(answers):,} package versions; calls {dict(CALLS)}", flush=True)

    vuln_ids = sorted({i for a in answers.values() for i in a["ids"]})
    details = dict(zip(vuln_ids, parallel(lambda v: fetch(f"{OSV_API}/vulns/{quote(v, safe='')}"), vuln_ids, args.workers)))
    cves = sorted({alias for v, result in details.items() if result["status"] == 200
                   for alias in [v, *((result["body"] or {}).get("aliases") or [])] if CVE_ID.match(alias)})
    print(f"OSV advisories {len(vuln_ids):,}; CVEs {len(cves):,}; calls {dict(CALLS)}", flush=True)

    epss = [fetch(EPSS_API, params={"cve": ",".join(cves[i:i + 50])}) for i in range(0, len(cves), 50)]
    cve_org = parallel(lambda c: fetch(f"{CVE_API}/{c}"), cves, 4)
    nvd = [fetch(NVD_API, params={"cveId": c}, spacing=6.5) for c in cves] if args.nvd else []
    print(f"CVE details done; calls {dict(CALLS)}", flush=True)

    rows, dependency_rows = [], []
    for server in servers:
        if not server["targets"]:
            for source in ("deps.dev (package version)", "deps.dev (dependency graph)"):
                rows.append(row(server, source, "system/name/version", None, "Not applicable", reason="no package declared (remote-only server)"))
            rows.append(row(server, "OSV.dev (declared package version)", "ecosystem/name/version", None, "Not applicable",
                            reason="no package declared (remote-only server); OSV covers packages, not remote endpoints"))
            rows.append(row(server, "OSV.dev (resolved dependencies)", "dependency ecosystem/name/version", None, "Not applicable",
                            reason="no package declared (remote-only server)"))
            continue
        graphs = []
        for t in server["targets"]:
            key = (t["kind"], t["name"], t["version"])
            reference = f"https://deps.dev/{DEPS_SYSTEMS.get(t['kind'], '')}/{quote(t['name'], safe='')}/{quote(t['version'], safe='')}"
            if t["kind"] not in DEPS_SYSTEMS:
                for source in ("deps.dev (package version)", "deps.dev (dependency graph)"):
                    rows.append(row(server, source, "system/name/version", t["identifier"], "Not applicable",
                                    reason=f"registryType '{t['kind']}' is not a deps.dev package system"))
            elif not t["exact"]:
                for source in ("deps.dev (package version)", "deps.dev (dependency graph)"):
                    rows.append(row(server, source, "system/name/version", t["identifier"], "Missing identifier", reason="no exact package version declared"))
            else:
                info, graph = looked[key]
                if info["status"] == 200:
                    rows.append(row(server, "deps.dev (package version)", "system/name/version", t["identifier"], "Matched", "high", t["identifier"],
                                    version_fields(info["body"]), info, reference=reference))
                else:
                    status, reason = failure(info)
                    rows.append(row(server, "deps.dev (package version)", "system/name/version", t["identifier"], status, result=info, reason=reason,
                                    reference=reference))
                if graph["status"] != 200:
                    status, reason = failure(graph)
                    rows.append(row(server, "deps.dev (dependency graph)", "system/name/version", t["identifier"], status, result=graph, reason=reason,
                                    reference=reference))
                else:
                    fields = graph_fields(graph["body"])
                    rows.append(row(server, "deps.dev (dependency graph)", "system/name/version", t["identifier"],
                                    "Matched" if key in graph_ok else "Not found", "high", t["identifier"], fields, graph,
                                    None if fields["complete"] else "graph returned with resolution errors", reference))
                    if key in graph_ok:
                        graphs.append((t, key))
            if t["kind"] not in OSV_ECOSYSTEMS:
                rows.append(row(server, "OSV.dev (declared package version)", "ecosystem/name/version", t["identifier"], "Not applicable",
                                reason=f"registryType '{t['kind']}' has no OSV ecosystem"))
            elif not t["exact"]:
                rows.append(row(server, "OSV.dev (declared package version)", "ecosystem/name/version", t["identifier"], "Missing identifier",
                                reason="no exact package version declared"))
            else:
                query = direct[key]
                answer = answers[query]
                if not answer["ok"]:
                    status, reason = failure(answer["result"])
                    rows.append(row(server, "OSV.dev (declared package version)", "ecosystem/name/version", t["identifier"], "API error",
                                    result=answer["result"], reason=reason))
                else:
                    rows.append(row(server, "OSV.dev (declared package version)", "ecosystem/name/version", t["identifier"],
                                    "Matched" if answer["ids"] else "No known vulnerabilities", "high", ", ".join(answer["ids"]) or None,
                                    {"advisory_ids": answer["ids"], "paginated_result": answer.get("truncated")}, answer["result"],
                                    reference=f"https://osv.dev/list?ecosystem={query[0]}&q={quote(query[1])}"))
        if not graphs:
            rows.append(row(server, "OSV.dev (resolved dependencies)", "dependency ecosystem/name/version", None, "Missing identifier",
                            reason="no resolved dependency graph available from deps.dev"))
            continue
        queried, unsupported, server_rows = set(), set(), []
        for t, key in graphs:
            for system, name, version, relation, errors in nodes[key]:
                query = (DEPS_TO_OSV.get(system), name, version)
                answer = answers.get(query) if query[0] and version else None
                if query[0] and version:
                    queried.add(query)
                else:
                    unsupported.add((system, name))
                server_rows.append({"record_index": server["record_index"], "server_name": server["name"], "package": t["identifier"],
                                    "system": system, "dependency": name, "dependency_version": version, "relation": relation,
                                    "resolution_errors": errors, "osv_status": "queried" if answer and answer["ok"] else "not queried or failed",
                                    "osv_advisory_ids": ", ".join(answer["ids"]) if answer else None})
        dependency_rows.extend(server_rows)
        failed = [q for q in queried if not answers[q]["ok"]]
        vulnerable = {f"{n}@{v}": answers[(e, n, v)]["ids"] for e, n, v in sorted(queried) if answers[(e, n, v)]["ok"] and answers[(e, n, v)]["ids"]}
        ids = sorted({i for values in vulnerable.values() for i in values})
        fields = {"dependency_versions_queried": len(queried), "unsupported_dependencies": len(unsupported), "failed_queries": len(failed),
                  "vulnerable_dependency_versions": sorted(vulnerable), "advisory_ids": ids}
        status = "API error" if failed and not vulnerable else ("Matched" if vulnerable else "No known vulnerabilities")
        first = answers[min(queried)]["result"] if queried else None
        rows.append(row(server, "OSV.dev (resolved dependencies)", "dependency ecosystem/name/version", f"{len(queried)} resolved dependency versions",
                        status, "high", ", ".join(ids) or None, fields, first, f"{len(failed)} dependency queries failed" if failed else None))

    with gzip.GzipFile(MATCH_OUT, "wb", mtime=0) as raw, io.TextIOWrapper(raw, encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MATCH_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with gzip.GzipFile(DEPS_OUT, "wb", mtime=0) as raw, io.TextIOWrapper(raw, encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DEPS_COLUMNS)
        writer.writeheader()
        writer.writerows(dependency_rows)
    keep = [graph for _, graph in looked.values() if graph["status"] == 200] + [r for r in details.values() if r["status"] == 200] + epss + cve_org + nvd
    with gzip.GzipFile(RESPONSES_OUT, "wb", mtime=0) as handle:
        for result in sorted(keep, key=lambda r: r.get("final_url") or r["url"]):
            handle.write((json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    summary = {"servers": len(servers), "package_versions": len(targets), "graphs": len(graph_ok), "dependency_rows": len(dependency_rows),
               "osv_queries": len(answers), "advisories": len(vuln_ids), "cves": len(cves), "network_calls": dict(CALLS),
               "cache_hits": dict(HITS), "seconds": round(time.time() - started)}
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
