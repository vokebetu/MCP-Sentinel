from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from typing import Literal

import psycopg
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout

from .db import fetch_all, fetch_one, pool
from .ai import close_client, router as ai_router
from .models import (
    CheckRecord, CheckTypeCoverage, CompareEntry, CompareResponse, CoverageResponse, CveContext, EndpointObservation, EvidenceSource, Finding,
    Health, PackageDeclaration, RemoteEndpoint, Repository, SecurityResponse, SecuritySummary, ServerDetail, ServerPage, ServerSummary, SourceInfo,
    Stats, ToolInfo,
)

CHECK_TYPES = [
    ("repository_metadata", "Repository metadata (GitHub)", "servers that declare a repository URL"),
    ("package_metadata", "Package metadata (npm, PyPI, deps.dev)", "each declared package"),
    ("dependency_resolution", "Dependency graph resolution (deps.dev)", "each declared package in a deps.dev-supported ecosystem"),
    ("direct_package_advisories", "Known vulnerabilities in declared package versions (OSV, GHSA)", "each declared package"),
    ("dependency_advisories", "Known vulnerabilities in modeled dependencies (OSV)", "each declared package with a resolved dependency graph"),
    ("endpoint_status", "Third-party endpoint observation (Agora)", "every non-deleted server"),
    ("tool_metadata", "Tool metadata (PolicyLayer, ToolHive, Glama)", "every non-deleted server"),
]
PACKAGE_CHECKS = {"package_metadata", "dependency_resolution", "direct_package_advisories", "dependency_advisories"}
SORTS = {
    "name": "p.registry_name ASC",
    "concerns": "ss.distinct_advisories DESC NULLS LAST, severity_rank DESC NULLS LAST, p.registry_name ASC",
    "newest": "p.published_at DESC NULLS LAST, p.registry_name ASC",
    "relevance": "rank DESC, p.registry_name ASC",
}
INTERPRETATION = [
    "Direct package findings mean the exact package version declared in the registry record is inside an advisory's affected range.",
    "Modeled dependency exposures come from a deps.dev resolution of the declared package. They describe what a fresh install would resolve on the "
    "observation date, not what any deployment actually runs.",
    "Advisory aliases (GHSA, PYSEC, CVE) are grouped, so each distinct vulnerability is counted once.",
    "EPSS is a CVE-level probability of exploitation activity, not a probability that this MCP server is compromised.",
    "No recorded finding is not evidence of safety. Check the assessment coverage indicator for what was and was not examined.",
]
METHODOLOGY = [
    "Coverage lists every recorded check for this server version, with its source, scope, date and outcome.",
    "A check type with no recorded check is shown as not_assessed. It was never run, which is different from no_known_finding.",
    "not_applicable_to_server is derived from the registry record itself, for example package checks on a server that declares no package.",
    "Vulnerability checks were run for 400 sampled servers and for registry versions linked to stored advisories. Most registry "
    "servers have endpoint and tool-catalog lookups but no package vulnerability lookup.",
    "Coverage is not a security score. Complete coverage with no findings still does not show that a server is safe.",
]
LIMITATIONS = [
    "The Official MCP Registry snapshot is from a single collection run; the registry changes daily.",
    "Package vulnerability lookups exist only for 400 sampled servers and for packages named in stored advisories.",
    "Remote-only servers have no package-level vulnerability path; their endpoints were never scanned.",
    "Endpoint observations are historical third-party (Agora) handshake results, not live status.",
    "Tool input schemas are available for about 1.3% of the registry from the tested downloadable sources.",
    "OCI and MCPB packages could not be checked for vulnerabilities, and deps.dev returned no dependency graphs for NuGet packages.",
]


@asynccontextmanager
async def lifespan(app):
    pool.open(wait=False)
    yield
    pool.close()
    close_client()


app = FastAPI(title="MCP Sentinel API", version="0.3.0", lifespan=lifespan)
app.include_router(ai_router)


@app.exception_handler(PoolTimeout)
@app.exception_handler(psycopg.OperationalError)
async def database_unavailable(request: Request, exc: Exception):
    return JSONResponse(status_code=503, content={"detail": "database unavailable"})


@app.exception_handler(psycopg.errors.UndefinedTable)
async def schema_missing(request: Request, exc: Exception):
    return JSONResponse(status_code=503, content={"detail": "database schema is not initialized"})


@app.get("/health", response_model=Health)
def health():
    try:
        versions = [row["version"] for row in fetch_all("SELECT version FROM schema_migrations ORDER BY version")]
        servers = fetch_one("SELECT count(*) AS n FROM servers")["n"]
    except psycopg.errors.UndefinedTable:
        return JSONResponse(status_code=503, content=Health(status="degraded", database="schema missing", schema_versions=[], servers=None).model_dump())
    except (PoolTimeout, psycopg.OperationalError):
        return JSONResponse(status_code=503, content=Health(status="degraded", database="unreachable", schema_versions=[], servers=None).model_dump())
    return Health(status="ok", database="ok", schema_versions=versions, servers=servers)


LIST_SQL = """
SELECT p.server_id, p.registry_name, p.title, p.version, p.registry_status, p.ecosystems, p.deployment_type, p.has_github_repository,
       p.package_count, p.remote_count, p.observed_tool_count, p.valid_input_schema_count, p.published_at,
       ss.vulnerability_assessment_state, ss.distinct_advisories, ss.direct_advisories, ss.dependency_advisories, ss.highest_advisory_severity,
       CASE ss.highest_advisory_severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 END AS severity_rank,
       CASE WHEN %(q)s::text IS NULL THEN 0
            ELSE ts_rank(sv.search_vector, websearch_to_tsquery('english', %(q)s) || websearch_to_tsquery('simple', %(q)s))
                 + CASE WHEN p.registry_name ILIKE '%%' || %(q)s || '%%' THEN 1 ELSE 0 END END AS rank,
       count(*) OVER () AS total
FROM server_profiles p
JOIN server_security_summary ss ON ss.server_id = p.server_id
JOIN server_versions sv ON sv.server_version_id = p.server_version_id
WHERE (%(q)s::text IS NULL OR sv.search_vector @@ (websearch_to_tsquery('english', %(q)s) || websearch_to_tsquery('simple', %(q)s))
       OR p.registry_name ILIKE '%%' || %(q)s || '%%')
  AND (%(status)s::text = 'all' OR (%(status)s = 'non_deleted' AND p.registry_status <> 'deleted') OR p.registry_status = %(status)s)
  AND (%(ecosystem)s::text IS NULL OR %(ecosystem)s = ANY (p.ecosystems))
  AND (%(deployment)s::text IS NULL OR p.deployment_type = %(deployment)s)
  AND (%(has_repository)s::boolean IS NULL OR (p.repository_count > 0) = %(has_repository)s)
  AND (%(assessment)s::text IS NULL OR ss.vulnerability_assessment_state = %(assessment)s)
  AND (%(has_tools)s::boolean IS NULL OR (p.observed_tool_count > 0) = %(has_tools)s)
  AND (%(server_ids)s::bigint[] IS NULL OR p.server_id = ANY (%(server_ids)s))
ORDER BY {order}
LIMIT %(limit)s OFFSET %(offset)s
"""


def list_servers(params, sort="name", page=1, page_size=25):
    base = {"q": None, "status": "all", "ecosystem": None, "deployment": None, "has_repository": None, "assessment": None, "has_tools": None,
            "server_ids": None, **params, "limit": page_size, "offset": (page - 1) * page_size}
    rows = fetch_all(LIST_SQL.format(order=SORTS[sort]), base)
    return (rows[0]["total"] if rows else 0), [ServerSummary(**row) for row in rows]


@app.get("/api/servers", response_model=ServerPage)
def search_servers(
    q: str | None = Query(None, max_length=200),
    status: Literal["non_deleted", "active", "deprecated", "deleted", "all"] = "non_deleted",
    ecosystem: str | None = Query(None, max_length=40),
    deployment: Literal["remote_only", "packages_only", "packages_and_remotes", "neither"] | None = None,
    has_repository: bool | None = None,
    assessment: Literal["findings_recorded", "no_known_findings_in_completed_checks", "checks_could_not_complete",
                        "no_package_vulnerability_path", "not_assessed"] | None = None,
    has_tools: bool | None = None,
    sort: Literal["name", "concerns", "newest", "relevance"] = "name",
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(25, ge=1, le=100),
):
    query = (q or "").strip() or None
    if sort == "relevance" and not query:
        sort = "name"
    total, items = list_servers({"q": query, "status": status, "ecosystem": ecosystem, "deployment": deployment, "has_repository": has_repository,
                                 "assessment": assessment, "has_tools": has_tools}, sort, page, page_size)
    return ServerPage(total=total, page=page, page_size=page_size, items=items)


def server_row(server_id):
    row = fetch_one(
        """
        SELECT s.server_id, s.registry_name, s.registry_status, s.status_changed_at, s.status_message, s.first_seen_at, s.last_seen_at,
               sv.server_version_id, sv.version, sv.title, sv.description, sv.website_url, sv.published_at, sv.updated_at,
               sv.observed_at AS snapshot_observed_at, p.deployment_type, p.package_count, p.remote_count, p.repository_count
        FROM servers s
        JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
        JOIN server_profiles p ON p.server_id = s.server_id
        WHERE s.server_id = %(id)s
        """,
        {"id": server_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail="server not found")
    return row


def repositories_for(version_id):
    return [Repository(**row) for row in fetch_all(
        """
        SELECT r.repository_id, r.canonical_url, r.host, r.owner, r.name, sr.subfolder, sr.declared_repository_id, r.github_id, r.lookup_status,
               r.full_name_observed, r.is_archived, r.is_fork, r.stars, r.license, r.pushed_at, r.metadata_observed_at,
               (SELECT count(DISTINCT x.server_version_id) FROM server_repositories x WHERE x.repository_id = r.repository_id) AS servers_sharing
        FROM server_repositories sr JOIN repositories r ON r.repository_id = sr.repository_id
        WHERE sr.server_version_id = %(v)s ORDER BY r.canonical_url
        """, {"v": version_id})]


def packages_for(version_id):
    rows = fetch_all(
        """
        SELECT d.position, d.registry_type, d.declared_identifier AS identifier, d.declared_version, d.version_is_exact, pv.published_at,
               pv.is_deprecated, pv.is_yanked, pv.metadata_observed_at, d.transport_type, d.runtime_hint, d.registry_base_url,
               COALESCE((SELECT array_agg(e ->> 'name') FROM jsonb_array_elements(d.config -> 'environmentVariables') e), ARRAY[]::text[]) AS environment_variables,
               CASE WHEN r.resolution_id IS NOT NULL THEN jsonb_build_object('source', 'deps.dev', 'resolved_at', r.resolved_at, 'status', r.status,
                    'node_count', r.node_count, 'edge_count', r.edge_count) END AS dependency_resolution
        FROM server_package_declarations d
        LEFT JOIN package_versions pv ON pv.package_version_id = d.package_version_id
        LEFT JOIN LATERAL (SELECT * FROM dependency_resolutions x WHERE x.root_package_version_id = d.package_version_id
                           ORDER BY x.resolved_at DESC LIMIT 1) r ON true
        WHERE d.server_version_id = %(v)s ORDER BY d.position
        """, {"v": version_id})
    return [PackageDeclaration(**row) for row in rows]


@app.get("/api/servers/{server_id}", response_model=ServerDetail)
def server_detail(server_id: int):
    row = server_row(server_id)
    version_id = row["server_version_id"]
    repositories = repositories_for(version_id)
    packages = packages_for(version_id)
    observations = defaultdict(list)
    for obs in fetch_all(
        """
        SELECT eo.endpoint_id, ds.name AS source, eo.observed_at, eo.check_result, eo.availability_class, eo.auth_gated, eo.protocol_version,
               eo.observed_tool_count
        FROM endpoint_observations eo JOIN evidence_observations e ON e.observation_id = eo.observation_id
        JOIN data_sources ds ON ds.source_id = e.source_id
        WHERE eo.server_version_id = %(v)s AND eo.endpoint_id IS NOT NULL ORDER BY eo.observed_at DESC
        """, {"v": version_id}):
        observations[obs.pop("endpoint_id")].append(EndpointObservation(**obs))
    remotes = [RemoteEndpoint(**{k: v for k, v in r.items() if k != "endpoint_id"}, observations=observations[r["endpoint_id"]]) for r in fetch_all(
        """SELECT endpoint_id, position, url, transport_type, is_templated, declares_secret_header FROM remote_endpoints
           WHERE server_version_id = %(v)s ORDER BY position""", {"v": version_id})]
    tools = [ToolInfo(**t) for t in fetch_all(
        """
        SELECT t.tool_name, t.description, ds.name AS source, t.declaration_kind, e.match_confidence, t.input_schema_state, t.input_schema,
               t.output_schema IS NOT NULL AS has_output_schema, t.annotations, t.classification, t.classification_source, t.observed_at
        FROM tool_observations t JOIN evidence_observations e ON e.observation_id = t.observation_id JOIN data_sources ds ON ds.source_id = e.source_id
        WHERE t.server_version_id = %(v)s ORDER BY ds.name, t.tool_position
        """, {"v": version_id})]
    sources = [EvidenceSource(source_key="mcp_registry", source_name="Official MCP Registry", evidence_types=["publisher_declared"], observations=1,
                              latest_observed_at=row["snapshot_observed_at"], redistribution="permitted_with_attribution",
                              attribution="Data from the Official MCP Registry (registry.modelcontextprotocol.io)")]
    sources += [EvidenceSource(**s) for s in fetch_all(
        """
        SELECT ds.source_key, ds.name AS source_name, array_agg(DISTINCT e.evidence_type) AS evidence_types, count(*) AS observations,
               max(e.observed_at) AS latest_observed_at, ds.redistribution, ds.attribution
        FROM evidence_observations e JOIN data_sources ds ON ds.source_id = e.source_id
        WHERE e.server_version_id = %(v)s
           OR e.repository_id IN (SELECT repository_id FROM server_repositories WHERE server_version_id = %(v)s)
           OR e.package_version_id IN (SELECT package_version_id FROM server_package_declarations WHERE server_version_id = %(v)s)
        GROUP BY ds.source_key, ds.name, ds.redistribution, ds.attribution ORDER BY ds.name
        """, {"v": version_id})]
    state = fetch_one("SELECT vulnerability_assessment_state FROM server_security_summary WHERE server_id = %(id)s", {"id": server_id})
    missing = []
    if not repositories:
        missing.append("No source repository is declared in the registry record.")
    elif all(r.lookup_status is None for r in repositories):
        missing.append("The declared repository has not been checked against GitHub in the stored evidence.")
    elif any(r.lookup_status == "not_found" for r in repositories):
        missing.append("GitHub returned 404 for the declared repository (private, moved or deleted; the cause is unknown).")
    if not packages:
        missing.append("No installable package is declared, so package and dependency vulnerability checks do not apply.")
    if any(not p.version_is_exact for p in packages):
        missing.append("At least one package is declared without an exact version, so it cannot be matched to advisories.")
    if not tools:
        missing.append("No tool names or schemas are available from the tested sources.")
    elif not any(t.input_schema_state == "valid" for t in tools):
        missing.append("Tool names are available, but no valid JSON Schema input schema was found.")
    if remotes and not any(r.observations for r in remotes):
        missing.append("No third-party observation is linked to the declared remote endpoints.")
    if state and state["vulnerability_assessment_state"] == "not_assessed":
        missing.append("No vulnerability lookup has been recorded for this server version. Absence of findings is not evidence of safety.")
    return ServerDetail(**{k: row[k] for k in ServerDetail.model_fields if k in row}, repositories=repositories, packages=packages, remotes=remotes,
                        tools=tools, evidence_sources=sources, missing_information=missing)


def security_summary(server_id):
    row = fetch_one("SELECT * FROM server_security_summary WHERE server_id = %(id)s", {"id": server_id})
    return SecuritySummary(**row)


@app.get("/api/servers/{server_id}/security", response_model=SecurityResponse)
def server_security(server_id: int):
    row = server_row(server_id)
    findings = fetch_all(
        """
        SELECT f.finding_id, f.finding_category, f.match_method, f.range_check, f.finding_status, f.first_observed_at, f.last_observed_at, f.advisory_id AS aid,
               a.canonical_id AS advisory_id, a.summary, a.severity_label, a.severity_source, a.published_at AS advisory_published_at,
               p.ecosystem AS affected_ecosystem, p.display_name AS affected_package, pv.version AS affected_version,
               d.registry_type || ':' || d.declared_identifier || '@' || COALESCE(d.declared_version, '?') AS declared_package,
               CASE WHEN r.resolution_id IS NOT NULL THEN jsonb_build_object('source', 'deps.dev', 'resolved_at', r.resolved_at, 'status', r.status,
                    'node_count', r.node_count) END AS resolution,
               ds.name AS evidence_source, e.source_url AS evidence_url,
               (SELECT array_agg(ai.identifier ORDER BY ai.identifier) FROM advisory_identifiers ai WHERE ai.advisory_id = f.advisory_id) AS identifiers,
               COALESCE((SELECT array_agg(DISTINCT fv ORDER BY fv) FROM advisory_affected_packages aap, unnest(aap.fixed_versions) fv
                         WHERE aap.advisory_id = f.advisory_id AND aap.package_id = pv.package_id), ARRAY[]::text[]) AS fixed_versions
        FROM security_findings f
        JOIN advisories a ON a.advisory_id = f.advisory_id
        JOIN package_versions pv ON pv.package_version_id = f.affected_package_version_id
        JOIN packages p ON p.package_id = pv.package_id
        JOIN server_package_declarations d ON d.declaration_id = f.declaration_id
        LEFT JOIN dependency_resolutions r ON r.resolution_id = f.resolution_id
        JOIN evidence_observations e ON e.observation_id = f.observation_id
        JOIN data_sources ds ON ds.source_id = e.source_id
        WHERE f.server_version_id = %(v)s
        ORDER BY f.finding_category, CASE upper(a.severity_label) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
                 a.canonical_id
        """, {"v": row["server_version_id"]})
    cves = defaultdict(list)
    if findings:
        for cve in fetch_all("SELECT * FROM advisory_cve_context WHERE advisory_id = ANY(%(ids)s) ORDER BY cve_id",
                             {"ids": sorted({f["aid"] for f in findings})}):
            cves[cve["advisory_id"]].append(CveContext(**cve))
    labels = {
        ("direct_package", "osv_exact_version_query"): "Known vulnerability: the declared package version was returned by an exact-version OSV query",
        ("direct_package", "osv_record_range_evaluation"): "Known vulnerability: the declared package version is inside the stored OSV affected range",
        ("resolved_dependency", "osv_exact_version_query"): "Modeled dependency exposure: a deps.dev resolution of the declared package includes an "
                                                            "affected version (not proof of installation)",
    }
    items = [Finding(**{k: v for k, v in f.items() if k != "aid"}, evidence_label=labels.get((f["finding_category"], f["match_method"]), f["match_method"]),
                     cves=cves[f["aid"]]) for f in findings]
    return SecurityResponse(server_id=server_id, registry_name=row["registry_name"], summary=security_summary(server_id), findings=items,
                            interpretation=INTERPRETATION)


def coverage_for(row):
    records = fetch_all(
        """
        SELECT c.check_type, c.check_scope, ds.source_key, ds.name AS source_name, c.outcome, c.checked_at, c.method, c.reason,
               CASE WHEN d.declaration_id IS NOT NULL THEN d.registry_type || ':' || d.declared_identifier || '@' || COALESCE(d.declared_version, '?')
                    WHEN r.repository_id IS NOT NULL THEN r.canonical_url END AS subject
        FROM assessment_checks c JOIN data_sources ds ON ds.source_id = c.source_id
        LEFT JOIN server_package_declarations d ON d.declaration_id = c.declaration_id
        LEFT JOIN repositories r ON r.repository_id = c.repository_id
        WHERE c.server_version_id = %(v)s ORDER BY c.check_type, ds.source_key, subject NULLS FIRST
        """, {"v": row["server_version_id"]})
    by_type = defaultdict(list)
    for record in records:
        by_type[record["check_type"]].append(CheckRecord(**record))
    result = []
    for check_type, label, applicability in CHECK_TYPES:
        items = by_type.get(check_type, [])
        if items:
            status = "recorded"
        elif check_type in PACKAGE_CHECKS and row["package_count"] == 0:
            status = "not_applicable_to_server"
        elif check_type == "repository_metadata" and row["repository_count"] == 0:
            status = "not_applicable_to_server"
        else:
            status = "not_assessed"
        result.append(CheckTypeCoverage(check_type=check_type, label=label, applicability=applicability, status=status,
                                        outcomes=dict(Counter(item.outcome for item in items)), records=items))
    return result


@app.get("/api/servers/{server_id}/coverage", response_model=CoverageResponse)
def server_coverage(server_id: int):
    row = server_row(server_id)
    check_types = coverage_for(row)
    totals = Counter()
    for item in check_types:
        totals.update(item.outcomes)
        if item.status != "recorded":
            totals[item.status] += 1
    return CoverageResponse(server_id=server_id, registry_name=row["registry_name"], check_types=check_types, outcome_totals=dict(totals),
                            not_assessed_check_types=[c.check_type for c in check_types if c.status == "not_assessed"], methodology=METHODOLOGY)


@app.get("/api/compare", response_model=CompareResponse)
def compare(server_ids: str = Query(..., pattern=r"^\d+(,\d+){1,3}$", description="two to four comma-separated server ids")):
    ids = list(dict.fromkeys(int(value) for value in server_ids.split(",")))
    if len(ids) < 2:
        raise HTTPException(status_code=422, detail="provide at least two different server ids")
    _, summaries = list_servers({"server_ids": ids}, page_size=len(ids))
    by_id = {summary.server_id: summary for summary in summaries}
    entries = []
    for server_id in ids:
        if server_id not in by_id:
            raise HTTPException(status_code=404, detail=f"server {server_id} not found")
        row = server_row(server_id)
        version_id = row["server_version_id"]
        coverage = {c.check_type: ([f"{r.source_key}: {r.outcome}" for r in c.records] or [c.status]) for c in coverage_for(row)}
        fresh = fetch_one(
            """
            SELECT (SELECT max(observed_at) FROM evidence_observations WHERE server_version_id = %(v)s) AS latest_evidence_at,
                   (SELECT max(checked_at) FROM assessment_checks WHERE server_version_id = %(v)s) AS latest_check_at,
                   (SELECT array_agg(DISTINCT ds.name) FROM tool_observations t JOIN evidence_observations e ON e.observation_id = t.observation_id
                    JOIN data_sources ds ON ds.source_id = e.source_id WHERE t.server_version_id = %(v)s) AS tool_sources
            """, {"v": version_id})
        entries.append(CompareEntry(summary=by_id[server_id], snapshot_observed_at=row["snapshot_observed_at"], repositories=repositories_for(version_id),
                                    packages=packages_for(version_id), security=security_summary(server_id), coverage=coverage,
                                    tool_sources=fresh["tool_sources"] or [], latest_evidence_at=fresh["latest_evidence_at"],
                                    latest_check_at=fresh["latest_check_at"]))
    notes = ["Counts are distinct advisories after alias grouping. Direct package findings and modeled dependency exposures are reported separately."]
    states = {entry.summary.vulnerability_assessment_state for entry in entries}
    if len(states) > 1:
        notes.append("These servers have different assessment coverage. A server with fewer recorded findings is not necessarily more secure.")
    if "not_assessed" in states:
        notes.append("At least one server has no recorded vulnerability lookup, so its finding count is unknown rather than zero.")
    return CompareResponse(servers=entries, notes=notes)


@app.get("/api/stats", response_model=Stats)
def stats():
    runs = fetch_one(
        """
        SELECT max(r.source_collected_at) FILTER (WHERE ds.source_key = 'mcp_registry') AS snapshot_collected_at, max(r.finished_at) AS last_import_at
        FROM collection_runs r JOIN data_sources ds ON ds.source_id = r.source_id WHERE r.status IN ('succeeded', 'partial')
        """)
    totals = {row["registry_status"]: row["n"] for row in fetch_all("SELECT registry_status, count(*) AS n FROM servers GROUP BY 1")}
    totals["all"] = sum(totals.values())
    totals["non_deleted"] = totals["all"] - totals.get("deleted", 0)
    deployment = {row["deployment_type"]: row["n"] for row in fetch_all(
        "SELECT deployment_type, count(*) AS n FROM server_profiles WHERE registry_status <> 'deleted' GROUP BY 1 ORDER BY 2 DESC")}
    ecosystems = {row["registry_type"]: row["n"] for row in fetch_all(
        """SELECT d.registry_type, count(DISTINCT d.server_version_id) AS n FROM server_package_declarations d
           JOIN servers s ON s.latest_version_id = d.server_version_id WHERE s.registry_status <> 'deleted' GROUP BY 1 ORDER BY 2 DESC""")}
    states = {row["vulnerability_assessment_state"]: row["n"] for row in fetch_all(
        """SELECT ss.vulnerability_assessment_state, count(*) AS n FROM server_security_summary ss JOIN servers s ON s.server_id = ss.server_id
           WHERE s.registry_status <> 'deleted' GROUP BY 1 ORDER BY 2 DESC""")}
    enrichment = fetch_one(
        """
        SELECT
          (SELECT count(DISTINCT server_version_id) FROM assessment_checks WHERE check_type IN ('direct_package_advisories', 'dependency_advisories')
             AND outcome IN ('finding_found', 'no_known_finding')) AS servers_with_completed_vulnerability_check,
          (SELECT count(DISTINCT server_version_id) FROM security_findings) AS servers_with_findings,
          (SELECT count(DISTINCT server_version_id) FROM security_findings WHERE finding_category = 'direct_package') AS servers_with_direct_findings,
          (SELECT count(DISTINCT server_version_id) FROM security_findings WHERE finding_category = 'resolved_dependency') AS servers_with_dependency_exposures,
          (SELECT count(DISTINCT advisory_id) FROM security_findings) AS distinct_advisories_in_findings,
          (SELECT count(*) FROM advisories) AS advisories_stored,
          (SELECT count(DISTINCT repository_id) FROM repositories WHERE lookup_status IS NOT NULL) AS repositories_checked_on_github,
          (SELECT count(DISTINCT server_version_id) FROM endpoint_observations) AS servers_with_endpoint_observation,
          (SELECT count(DISTINCT server_version_id) FROM tool_observations) AS servers_with_tool_names,
          (SELECT count(DISTINCT server_version_id) FROM tool_observations WHERE input_schema_state = 'valid') AS servers_with_valid_input_schema,
          (SELECT count(*) FROM dependency_resolutions) AS dependency_resolutions,
          (SELECT count(*) FROM assessment_checks) AS assessment_checks
        """)
    sources = [SourceInfo(**row) for row in fetch_all(
        """
        SELECT ds.source_key, ds.name, ds.license, ds.redistribution, ds.attribution, ds.notes,
               (SELECT max(finished_at) FROM collection_runs r WHERE r.source_id = ds.source_id) AS last_import_at,
               (SELECT count(*) FROM evidence_observations e WHERE e.source_id = ds.source_id) AS evidence_observations
        FROM data_sources ds ORDER BY ds.source_id
        """)]
    return Stats(snapshot_collected_at=runs["snapshot_collected_at"], last_import_at=runs["last_import_at"], totals=totals, deployment_types=deployment,
                 ecosystems=ecosystems, assessment_states=states, enrichment=dict(enrichment), sources=sources, limitations=LIMITATIONS)
