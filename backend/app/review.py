import hashlib
import json
import uuid
from collections import Counter
from urllib.parse import quote

from fastapi import APIRouter, HTTPException

from .db import fetch_all, fetch_one
from .models import ReviewItem, ReviewResponse, ToolFlag

router = APIRouter(prefix="/api/servers", tags=["Review"])
PURL_TYPES = {"npm": "npm", "pypi": "pypi", "nuget": "nuget", "cargo": "cargo", "go": "golang", "maven": "maven"}
NOTES = [
    "Each item shows whether evidence exists, not whether the server is safe. Missing or not assessed items need their own review.",
    "Dependency lists and vulnerability matches model a fresh install on the lookup date, not software actually installed anywhere.",
    "Tool review hints are text patterns over stored tool descriptions. No server was run or contacted.",
]


def core(server_id):
    row = fetch_one(
        """
        SELECT s.server_id, s.registry_name, sv.server_version_id, sv.version, sv.observed_at, ss.vulnerability_assessment_state,
               ss.distinct_advisories, ss.direct_advisories, ss.dependency_advisories, ss.highest_advisory_severity, ss.latest_check_at
        FROM servers s JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
        JOIN server_security_summary ss ON ss.server_id = s.server_id WHERE s.server_id = %(id)s
        """, {"id": server_id})
    if not row:
        raise HTTPException(status_code=404, detail="server not found")
    return row


def item(key, label, status, detail, source=None, observed_at=None, attention=False):
    return ReviewItem(item=key, label=label, status=status, attention=attention, detail=detail, source=source, observed_at=observed_at)


def fingerprint(tools):
    canonical = sorted({(t["tool_name"], t["description"] or "", json.dumps(t["input_schema"], sort_keys=True) if t["input_schema"] is not None else "")
                        for t in tools})
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False).encode()).hexdigest(), len(canonical)


def publisher_item(row):
    namespace = row["registry_name"].split("/")[0]
    if namespace.startswith("io.github."):
        detail = f"Namespace {namespace} was verified by the registry through the GitHub account {namespace[len('io.github.'):]}."
    else:
        detail = f"Namespace {namespace} was verified by the registry through ownership of the domain {'.'.join(reversed(namespace.split('.')))}."
    return item("publisher_identity", "Identifiable publisher", "present", detail, "Official MCP Registry", row["observed_at"])


def repository_item(version_id):
    repos = fetch_all(
        """SELECT r.canonical_url, r.lookup_status, r.is_archived, r.stars, r.pushed_at, r.metadata_observed_at
           FROM server_repositories sr JOIN repositories r ON r.repository_id = sr.repository_id WHERE sr.server_version_id = %(v)s
           ORDER BY r.canonical_url""", {"v": version_id})
    label = "Source repository and maintainer activity"
    if not repos:
        return item("source_repository", label, "missing", "No source repository is declared in the registry record.", attention=True)
    repo = repos[0]
    if repo["lookup_status"] == "found":
        archived = " The repository is archived." if repo["is_archived"] else ""
        return item("source_repository", label, "present",
                    f"{repo['canonical_url']}: last push {str(repo['pushed_at'])[:10]}, {repo['stars'] or 0} stars.{archived}",
                    "GitHub REST API", repo["metadata_observed_at"], attention=bool(repo["is_archived"]))
    if repo["lookup_status"] == "not_found":
        return item("source_repository", label, "missing", f"GitHub returned 404 for {repo['canonical_url']} (private, moved or deleted).",
                    "GitHub REST API", repo["metadata_observed_at"], attention=True)
    return item("source_repository", label, "not_assessed", f"{repo['canonical_url']} is declared; its activity was not checked.")


def secrets_item(packages, remotes):
    secrets = sorted({v.get("name") for p in packages for v in (p["config"] or {}).get("environmentVariables") or [] if v.get("isSecret")})
    headers = sorted({h.get("name") for r in remotes for h in (r["config"] or {}).get("headers") or [] if h.get("name")})
    gated = sum(1 for r in remotes if r["declares_secret_header"])
    parts = []
    if secrets:
        parts.append("Asks for secret settings: " + ", ".join(secrets) + ".")
    if headers:
        parts.append(f"Hosted endpoints use headers: {', '.join(headers)} ({gated} marked secret).")
    if not parts:
        parts.append("Declares no secret settings or login headers in the registry record.")
    return item("secrets_and_logins", "Secrets and logins it needs", "present", " ".join(parts), "Official MCP Registry")


def package_items(row, packages):
    version_id = row["server_version_id"]
    if not packages:
        reason = "No installable package is declared, so this check does not apply."
        return [item(key, label, "not_applicable", reason) for key, label in (
            ("pinned_versions", "Pinned versions"), ("known_vulnerabilities", "Known vulnerabilities"),
            ("sbom", "Software bill of materials (SBOM)"), ("provenance", "Signed builds and provenance"))]
    loose = [p["declared_identifier"] + (f"@{p['declared_version']}" if p["declared_version"] else "") for p in packages
             if not p["version_is_exact"] and "@sha256:" not in p["declared_identifier"]]
    pinned = item("pinned_versions", "Pinned versions", "missing" if loose else "present",
                  f"No exact version or image digest: {', '.join(loose)}. A tag or range can change after review." if loose else
                  f"All {len(packages)} declared packages pin an exact version or image digest.", "Official MCP Registry", row["observed_at"],
                  attention=bool(loose))
    state = row["vulnerability_assessment_state"]
    when = row["latest_check_at"]
    if state == "findings_recorded":
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "present",
                     f"{row['distinct_advisories']} distinct advisories ({row['direct_advisories']} in declared packages, "
                     f"{row['dependency_advisories']} in modeled dependencies); highest severity {row['highest_advisory_severity'] or 'unknown'}.",
                     "OSV.dev", when, attention=True)
    elif state == "no_known_findings_in_completed_checks":
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "present",
                     "Checks completed with no known advisories. This is not proof of safety.", "OSV.dev", when)
    elif state == "checks_could_not_complete" and all(p["registry_type"] in ("oci", "mcpb") for p in packages):
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "missing",
                     "Docker images and MCPB files have no vulnerability database lookup. Review the image or bundle separately.",
                     "OSV.dev", when, attention=True)
    elif state == "checks_could_not_complete":
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "missing",
                     "Some declared packages could not be checked (no exact version, unsupported type or no dependency list).",
                     "OSV.dev", when, attention=True)
    elif state == "no_package_vulnerability_path":
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "not_applicable",
                     "The declared package types (for example Docker images or MCPB files) have no vulnerability database lookup.")
    else:
        vulns = item("known_vulnerabilities", "Known vulnerabilities", "not_assessed", "No vulnerability lookup is recorded for this version.",
                     attention=True)
    version_ids = [p["package_version_id"] for p in packages if p["package_version_id"]]
    graphs = fetch_all(
        """SELECT DISTINCT ON (root_package_version_id) root_package_version_id, status, node_count, resolved_at
           FROM dependency_resolutions WHERE root_package_version_id = ANY(%(ids)s) ORDER BY root_package_version_id, resolved_at DESC""",
        {"ids": version_ids})
    tried = fetch_one("""SELECT count(*) AS n, max(checked_at) AS at FROM assessment_checks
                         WHERE server_version_id = %(v)s AND check_type = 'dependency_resolution'""", {"v": version_id})
    if graphs:
        sbom = item("sbom", "Software bill of materials (SBOM)", "present",
                    f"Dependency lists for {len(graphs)} of {len(packages)} declared packages, {sum(g['node_count'] or 0 for g in graphs)} nodes. "
                    "Download it as CycloneDX JSON.", "deps.dev", max(g["resolved_at"] for g in graphs))
    elif tried["n"]:
        sbom = item("sbom", "Software bill of materials (SBOM)", "missing", "deps.dev returned no dependency list for the declared packages.",
                    "deps.dev", tried["at"], attention=True)
    else:
        sbom = item("sbom", "Software bill of materials (SBOM)", "not_assessed", "No dependency lookup is recorded for this version.")
    payloads = fetch_all(
        """SELECT observation_kind, payload, observed_at FROM evidence_observations
           WHERE package_version_id = ANY(%(ids)s) AND observation_kind IN ('deps_dev_package_version', 'pypi_provenance')""", {"ids": version_ids})
    if payloads:
        slsa = sum(int(p["payload"].get("slsa_provenance_count") or 0) for p in payloads if p["observation_kind"] == "deps_dev_package_version")
        attested = sum(int(p["payload"].get("attestation_count") or 0) for p in payloads if p["observation_kind"] == "deps_dev_package_version")
        pypi = sum(1 for p in payloads if p["observation_kind"] == "pypi_provenance" and str(p["payload"].get("has_provenance")) == "True")
        found = slsa + attested + pypi
        detail = (f"Published with provenance: {slsa} SLSA provenance and {attested + pypi} attestation records." if found else
                  "The package registry reports no SLSA provenance or signed attestation for the declared versions.")
        provenance = item("provenance", "Signed builds and provenance", "present" if found else "missing", detail, "deps.dev",
                          max(p["observed_at"] for p in payloads if p["observed_at"]) if any(p["observed_at"] for p in payloads) else None,
                          attention=not found)
    else:
        provenance = item("provenance", "Signed builds and provenance", "not_assessed", "No provenance lookup is recorded for the declared packages.")
    return [pinned, vulns, sbom, provenance]


def tool_items(version_id):
    tools = fetch_all(
        """SELECT tool_name, description, input_schema, classification, annotations, observed_at FROM tool_observations
           WHERE server_version_id = %(v)s""", {"v": version_id})
    flags = [ToolFlag(**f) for f in fetch_all(
        """SELECT tool_name, flag, explanation, matched_text FROM tool_review_flags WHERE server_version_id = %(v)s
           ORDER BY tool_name, flag""", {"v": version_id})]
    if not tools:
        reason = "No tool list is available from the tested sources."
        return [item(key, label, "not_assessed", reason) for key, label in (
            ("tool_permissions", "Tool permission review"), ("prompt_injection_hints", "Prompt injection hints in tool descriptions"),
            ("tool_fingerprint", "Tool definition fingerprint"))], flags, None
    observed = max((t["observed_at"] for t in tools if t["observed_at"]), default=None)
    names = sorted({t["tool_name"] for t in tools})
    categories = Counter(c.get("category") for t in tools if (c := t["classification"]) and c.get("category"))
    severities = Counter(c.get("severity") for t in tools if (c := t["classification"]) and c.get("severity"))
    destructive = sorted({t["tool_name"] for t in tools if (t["annotations"] or {}).get("destructiveHint") is True})
    risky = sum(categories.get(k, 0) for k in ("Destructive", "Execute", "Financial")) + severities.get("Critical", 0) + severities.get("High", 0)
    detail = f"{len(names)} tools."
    if categories:
        detail += " By category: " + ", ".join(f"{k} {v}" for k, v in categories.most_common()) + "."
        detail += " By severity: " + ", ".join(f"{k} {v}" for k, v in severities.most_common()) + "."
    else:
        detail += " No permission classification is available for these tools."
    if destructive:
        detail += f" Marked destructive by the publisher: {', '.join(destructive[:10])}."
    permissions = item("tool_permissions", "Tool permission review", "present", detail, "PolicyLayer, ToolHive, Docker", observed,
                       attention=bool(risky or destructive))
    described = sum(1 for t in tools if t["description"])
    if not described:
        hints = item("prompt_injection_hints", "Prompt injection hints in tool descriptions", "not_assessed", "The listed tools have no descriptions.")
    elif flags:
        hints = item("prompt_injection_hints", "Prompt injection hints in tool descriptions", "present",
                     f"{len(flags)} review hints in {len({f.tool_name for f in flags})} tools. Read the matched text below; most hints are harmless.",
                     "MCP Sentinel text patterns", observed, attention=True)
    else:
        hints = item("prompt_injection_hints", "Prompt injection hints in tool descriptions", "present",
                     f"No review hints in {described} tool descriptions. Text patterns cannot prove a description is safe.",
                     "MCP Sentinel text patterns", observed)
    digest, count = fingerprint(tools)
    fp = item("tool_fingerprint", "Tool definition fingerprint", "present",
              f"SHA-256 {digest} over {count} distinct tool definitions. Review again if it changes.", "MCP Sentinel", observed)
    return [permissions, hints, fp], flags, digest


@router.get("/{server_id}/review", response_model=ReviewResponse)
def review(server_id: int):
    row = core(server_id)
    version_id = row["server_version_id"]
    packages = fetch_all(
        """SELECT declaration_id, registry_type, declared_identifier, declared_version, version_is_exact, package_version_id, config
           FROM server_package_declarations WHERE server_version_id = %(v)s ORDER BY position""", {"v": version_id})
    remotes = fetch_all("SELECT url, declares_secret_header, config FROM remote_endpoints WHERE server_version_id = %(v)s ORDER BY position",
                        {"v": version_id})
    tools, flags, digest = tool_items(version_id)
    items = [publisher_item(row), repository_item(version_id), *package_items(row, packages), *tools, secrets_item(packages, remotes),
             item("static_analysis", "Static code analysis", "not_assessed", "No static analysis was run. MCP Sentinel does not download server code.")]
    return ReviewResponse(server_id=server_id, registry_name=row["registry_name"], version=row["version"], items=items, tool_flags=flags,
                          tool_fingerprint=digest, sbom_available=any(i.item == "sbom" and i.status == "present" for i in items), notes=NOTES)


def purl(ecosystem, name, version):
    kind = PURL_TYPES.get(ecosystem, ecosystem)
    if kind == "pypi":
        name = name.lower().replace("_", "-")
    if kind == "maven" and ":" in name:
        name = name.replace(":", "/", 1)
    path = "/".join(quote(part, safe="") for part in name.split("/")) if kind in ("maven", "golang") else quote(name, safe="")
    return f"pkg:{kind}/{path}@{quote(version or '', safe='')}"


@router.get("/{server_id}/sbom")
def sbom(server_id: int):
    row = core(server_id)
    rows = fetch_all(
        """
        SELECT DISTINCT e.to_ecosystem, e.to_name, e.to_version, e.to_relation, r.resolved_at
        FROM server_package_declarations d
        JOIN LATERAL (SELECT resolution_id, resolved_at FROM dependency_resolutions x WHERE x.root_package_version_id = d.package_version_id
                      ORDER BY x.resolved_at DESC LIMIT 1) r ON true
        JOIN dependency_edges e ON e.resolution_id = r.resolution_id
        WHERE d.server_version_id = %(v)s AND e.to_relation <> 'SELF'
        """, {"v": row["server_version_id"]})
    if not rows:
        raise HTTPException(status_code=404, detail="no dependency list is stored for this server")
    components = {}
    for r in sorted(rows, key=lambda r: (r["to_ecosystem"], r["to_name"], r["to_version"] or "", r["to_relation"] != "DIRECT")):
        ref = purl(r["to_ecosystem"], r["to_name"], r["to_version"])
        components.setdefault(ref, {"type": "library", "bom-ref": ref, "name": r["to_name"], "version": r["to_version"], "purl": ref,
                                    "properties": [{"name": "mcp-sentinel:relation", "value": r["to_relation"]}]})
    resolved = max(r["resolved_at"] for r in rows)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'mcp-sentinel:{row['server_version_id']}:{resolved.isoformat()}')}",
            "version": 1,
            "metadata": {"timestamp": resolved.isoformat(), "tools": {"components": [{"type": "application", "name": "MCP Sentinel"}]},
                         "component": {"type": "application", "bom-ref": row["registry_name"], "name": row["registry_name"], "version": row["version"]},
                         "properties": [{"name": "mcp-sentinel:source", "value": "deps.dev dependency resolution of the declared packages"},
                                        {"name": "mcp-sentinel:note", "value": "Modeled fresh install on the resolution date, not an observed installation."}]},
            "components": list(components.values())}
