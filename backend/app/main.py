import json
import logging
import re
import time
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from typing import Literal

import psycopg
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from psycopg_pool import PoolTimeout

from .db import fetch_all, fetch_one, pool
from .ai import close_client, router as ai_router
from .review import router as review_router
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
    "Package vulnerability checks (deps.dev and OSV) ran on 2026-11-14 for every declared npm, PyPI, NuGet and Cargo package version. "
    "Remote-only servers have no package to check, and Docker images and MCPB files have no vulnerability database lookup.",
    "Coverage is not a security score. Complete coverage with no findings still does not show that a server is safe.",
]
LIMITATIONS = [
    "The Official MCP Registry snapshot is from a single collection run; the registry changes daily.",
    "Package vulnerability lookups need an exact declared version in npm, PyPI, NuGet or Cargo. NVD scores exist only for CVEs from the research sample.",
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
app.include_router(review_router)


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mcp_sentinel.api")
REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


@app.middleware("http")
async def request_log(request: Request, call_next):
    supplied = request.headers.get("x-request-id", "")
    request.state.request_id = supplied if REQUEST_ID.match(supplied) else uuid.uuid4().hex[:12]
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    log.info(json.dumps({"event": "request", "request_id": request.state.request_id, "method": request.method, "path": request.url.path,
                         "status": response.status_code, "ms": round((time.perf_counter() - started) * 1000, 1)}))
    return response


def unavailable(request, exc, reason, detail):
    request_id = getattr(request.state, "request_id", None)
    log.warning(json.dumps({"event": "database_error", "request_id": request_id, "path": request.url.path, "reason": reason,
                            "error": type(exc).__name__}))
    return JSONResponse(status_code=503, content={"detail": detail, "reason": reason, "request_id": request_id}, headers={"Retry-After": "1"})


@app.exception_handler(PoolTimeout)
async def database_busy(request: Request, exc: Exception):
    return unavailable(request, exc, "database_busy", "The database is busy: no connection became free in time. Please retry.")


@app.exception_handler(psycopg.errors.QueryCanceled)
async def query_timeout(request: Request, exc: Exception):
    return unavailable(request, exc, "query_timeout", "The database query exceeded its time limit.")


@app.exception_handler(psycopg.OperationalError)
async def database_unavailable(request: Request, exc: Exception):
    return unavailable(request, exc, "database_unavailable", "database unavailable")


@app.exception_handler(psycopg.errors.UndefinedTable)
async def schema_missing(request: Request, exc: Exception):
    return unavailable(request, exc, "schema_missing", "database schema is not initialized")


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


CHECK_TYPES_SQL = "('direct_package_advisories', 'dependency_advisories')"
STATE_SQL = f"""CASE
    WHEN EXISTS (SELECT 1 FROM security_findings f WHERE f.server_version_id = sv.server_version_id AND f.finding_status <> 'withdrawn')
        THEN 'findings_recorded'
    WHEN EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id AND c.check_type IN {CHECK_TYPES_SQL}
                 AND c.outcome IN ('finding_found', 'no_known_finding')) THEN 'no_known_findings_in_completed_checks'
    WHEN EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id AND c.check_type IN {CHECK_TYPES_SQL}
                 AND c.outcome IN ('missing_identifier', 'unsupported', 'access_restricted', 'error', 'not_found')) THEN 'checks_could_not_complete'
    WHEN EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id AND c.check_type IN {CHECK_TYPES_SQL}
                 AND c.outcome = 'not_applicable') THEN 'no_package_vulnerability_path'
    ELSE 'not_assessed' END"""
HAS_PACKAGE_SQL = "EXISTS (SELECT 1 FROM server_package_declarations d WHERE d.server_version_id = sv.server_version_id)"
HAS_REMOTE_SQL = "EXISTS (SELECT 1 FROM remote_endpoints r WHERE r.server_version_id = sv.server_version_id)"
DEPLOYMENT_SQL = f"""CASE WHEN {HAS_PACKAGE_SQL} AND {HAS_REMOTE_SQL} THEN 'packages_and_remotes' WHEN {HAS_PACKAGE_SQL} THEN 'packages_only'
    WHEN {HAS_REMOTE_SQL} THEN 'remote_only' ELSE 'neither' END"""
TOOL_STATE_SQL = """CASE
    WHEN EXISTS (SELECT 1 FROM tool_observations t WHERE t.server_version_id = sv.server_version_id) THEN 'listed'
    WHEN EXISTS (SELECT 1 FROM endpoint_observations eo WHERE eo.server_version_id = sv.server_version_id AND eo.observed_tool_count > 0)
        THEN 'count_observed'
    WHEN EXISTS (SELECT 1 FROM endpoint_observations eo WHERE eo.server_version_id = sv.server_version_id
                 AND (eo.observed_tool_count = 0 OR eo.check_result = 'ok_no_tools')) THEN 'observed_none'
    ELSE 'not_observed' END"""
RANK_SQL = """CASE WHEN %(q)s::text IS NULL THEN 0
    ELSE ts_rank(sv.search_vector, websearch_to_tsquery('english', %(q)s) || websearch_to_tsquery('simple', %(q)s))
         + CASE WHEN s.registry_name ILIKE '%%' || %(q)s || '%%' THEN 1 ELSE 0 END END"""
CONCERNS_JOIN = """LEFT JOIN LATERAL (
    SELECT NULLIF(count(DISTINCT f.advisory_id), 0) AS advisories,
           max(CASE upper(a.severity_label) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 END) AS severity
    FROM security_findings f JOIN advisories a ON a.advisory_id = f.advisory_id
    WHERE f.server_version_id = sv.server_version_id AND f.finding_status <> 'withdrawn') fa ON true"""
CHECKED_SQL = f"""EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id AND c.check_type IN {CHECK_TYPES_SQL}
    AND c.outcome IN ('finding_found', 'no_known_finding'))"""
ORDERS = {
    "name": ("", "s.registry_name ASC"),
    "concerns": (CONCERNS_JOIN, f"COALESCE(fa.advisories, CASE WHEN {CHECKED_SQL} THEN 0 END) DESC NULLS LAST, fa.severity DESC NULLS LAST, s.registry_name ASC"),
    "newest": ("", "sv.published_at DESC NULLS LAST, s.registry_name ASC"),
    "relevance": ("", f"{RANK_SQL} DESC, s.registry_name ASC"),
}
FILTER_SQL = f"""
FROM servers s
JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
{{join}}
WHERE (%(q)s::text IS NULL OR sv.search_vector @@ (websearch_to_tsquery('english', %(q)s) || websearch_to_tsquery('simple', %(q)s))
       OR s.registry_name ILIKE '%%' || %(q)s || '%%')
  AND (%(status)s::text = 'all' OR (%(status)s = 'non_deleted' AND s.registry_status <> 'deleted') OR s.registry_status = %(status)s)
  AND (%(ecosystem)s::text IS NULL OR EXISTS (SELECT 1 FROM server_package_declarations d WHERE d.server_version_id = sv.server_version_id
                                               AND d.registry_type = %(ecosystem)s))
  AND (%(deployment)s::text IS NULL OR {DEPLOYMENT_SQL} = %(deployment)s)
  AND (%(has_repository)s::boolean IS NULL
       OR EXISTS (SELECT 1 FROM server_repositories sr WHERE sr.server_version_id = sv.server_version_id) = %(has_repository)s)
  AND (%(github)s::boolean IS NULL OR EXISTS (SELECT 1 FROM server_repositories sr JOIN repositories r ON r.repository_id = sr.repository_id
                                               WHERE sr.server_version_id = sv.server_version_id AND r.host = 'github.com') = %(github)s)
  AND (%(assessment)s::text IS NULL OR {STATE_SQL} = %(assessment)s)
  AND (%(has_tools)s::boolean IS NULL
       OR EXISTS (SELECT 1 FROM tool_observations t WHERE t.server_version_id = sv.server_version_id) = %(has_tools)s)
  AND (%(tool_info)s::text IS NULL OR ({TOOL_STATE_SQL}) = ANY (string_to_array(%(tool_info)s, ',')))
  AND (%(tool_hints)s::boolean IS NULL
       OR EXISTS (SELECT 1 FROM tool_review_flags fl WHERE fl.server_version_id = sv.server_version_id) = %(tool_hints)s)
  AND (%(server_ids)s::bigint[] IS NULL OR s.server_id = ANY (%(server_ids)s))
"""
DETAIL_SQL = f"""
SELECT s.server_id, s.registry_name, sv.title, sv.version, s.registry_status, sv.published_at,
       pk.ecosystems, pk.package_count, re.remote_count, rp.repository_count, rp.has_github_repository, rp.repository_url,
       tl.listed_tools, tl.valid_schemas, tl.listing_observed_at, ag.handshake_tools, ag.handshake_none, ag.handshake_observed_at,
       (SELECT count(*) FROM tool_review_flags fl WHERE fl.server_version_id = sv.server_version_id) AS tool_review_hints,
       fi.distinct_found, fi.direct_found, fi.dependency_found, fi.severity_rank,
       ck.completed_direct, ck.completed_dependency, ck.incomplete, ck.not_applicable
FROM unnest(%(ids)s::bigint[]) WITH ORDINALITY AS page(server_id, ord)
JOIN servers s ON s.server_id = page.server_id
JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
LEFT JOIN LATERAL (SELECT count(*) AS package_count, COALESCE(array_agg(DISTINCT d.registry_type ORDER BY d.registry_type), ARRAY[]::text[]) AS ecosystems
                   FROM server_package_declarations d WHERE d.server_version_id = sv.server_version_id) pk ON true
LEFT JOIN LATERAL (SELECT count(*) AS remote_count FROM remote_endpoints r WHERE r.server_version_id = sv.server_version_id) re ON true
LEFT JOIN LATERAL (SELECT count(*) AS repository_count, COALESCE(bool_or(r.host = 'github.com'), false) AS has_github_repository,
                          (array_agg(r.canonical_url ORDER BY r.canonical_url))[1] AS repository_url
                   FROM server_repositories sr JOIN repositories r ON r.repository_id = sr.repository_id
                   WHERE sr.server_version_id = sv.server_version_id) rp ON true
LEFT JOIN LATERAL (SELECT count(DISTINCT t.tool_name) AS listed_tools,
                          count(DISTINCT t.tool_name) FILTER (WHERE t.input_schema_state = 'valid') AS valid_schemas,
                          max(t.observed_at) AS listing_observed_at
                   FROM tool_observations t WHERE t.server_version_id = sv.server_version_id) tl ON true
LEFT JOIN LATERAL (SELECT max(eo.observed_tool_count) AS handshake_tools,
                          COALESCE(bool_or(eo.observed_tool_count = 0 OR eo.check_result = 'ok_no_tools'), false) AS handshake_none,
                          max(eo.observed_at) AS handshake_observed_at
                   FROM endpoint_observations eo WHERE eo.server_version_id = sv.server_version_id) ag ON true
LEFT JOIN LATERAL (SELECT count(DISTINCT f.advisory_id) AS distinct_found,
                          count(DISTINCT f.advisory_id) FILTER (WHERE f.finding_category = 'direct_package') AS direct_found,
                          count(DISTINCT f.advisory_id) FILTER (WHERE f.finding_category = 'resolved_dependency') AS dependency_found,
                          max(CASE upper(a.severity_label) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'MEDIUM' THEN 2
                                  WHEN 'LOW' THEN 1 END) AS severity_rank
                   FROM security_findings f JOIN advisories a ON a.advisory_id = f.advisory_id
                   WHERE f.server_version_id = sv.server_version_id AND f.finding_status <> 'withdrawn') fi ON true
LEFT JOIN LATERAL (SELECT count(*) FILTER (WHERE c.check_type = 'direct_package_advisories' AND c.outcome IN ('finding_found', 'no_known_finding'))
                              AS completed_direct,
                          count(*) FILTER (WHERE c.check_type = 'dependency_advisories' AND c.outcome IN ('finding_found', 'no_known_finding'))
                              AS completed_dependency,
                          count(*) FILTER (WHERE c.check_type IN {CHECK_TYPES_SQL}
                                           AND c.outcome IN ('missing_identifier', 'unsupported', 'access_restricted', 'error', 'not_found')) AS incomplete,
                          count(*) FILTER (WHERE c.check_type IN {CHECK_TYPES_SQL} AND c.outcome = 'not_applicable') AS not_applicable
                   FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id) ck ON true
ORDER BY page.ord
"""
SEVERITIES = {4: "CRITICAL", 3: "HIGH", 2: "MODERATE", 1: "LOW"}
FILTER_DEFAULTS = {"q": None, "status": "all", "ecosystem": None, "deployment": None, "has_repository": None, "github": None, "assessment": None,
                   "has_tools": None, "tool_info": None, "tool_hints": None, "server_ids": None}


def summarize(row):
    found = row["distinct_found"] > 0
    completed_direct, completed_dependency = row["completed_direct"], row["completed_dependency"]
    if found:
        state = "findings_recorded"
    elif completed_direct + completed_dependency > 0:
        state = "no_known_findings_in_completed_checks"
    elif row["incomplete"] > 0:
        state = "checks_could_not_complete"
    elif row["not_applicable"] > 0:
        state = "no_package_vulnerability_path"
    else:
        state = "not_assessed"
    if row["listed_tools"]:
        tools = ("listed", row["listed_tools"], "tool catalogs", row["listing_observed_at"])
    elif row["handshake_tools"]:
        tools = ("count_observed", row["handshake_tools"], "endpoint handshake (Agora)", row["handshake_observed_at"])
    elif row["handshake_none"]:
        tools = ("observed_none", 0, "endpoint handshake (Agora)", row["handshake_observed_at"])
    else:
        tools = ("not_observed", None, None, None)
    if row["package_count"] and row["remote_count"]:
        deployment = "packages_and_remotes"
    elif row["package_count"]:
        deployment = "packages_only"
    elif row["remote_count"]:
        deployment = "remote_only"
    else:
        deployment = "neither"
    return ServerSummary(
        server_id=row["server_id"], registry_name=row["registry_name"], title=row["title"], version=row["version"],
        registry_status=row["registry_status"], ecosystems=row["ecosystems"], deployment_type=deployment,
        has_github_repository=row["has_github_repository"], repository_url=row["repository_url"], package_count=row["package_count"],
        remote_count=row["remote_count"], observed_tool_count=row["listed_tools"] or None,
        valid_input_schema_count=row["valid_schemas"] if row["listed_tools"] else None, tool_metadata_state=tools[0], tool_count=tools[1],
        tool_count_source=tools[2], tool_observed_at=tools[3], tool_review_hints=row["tool_review_hints"], published_at=row["published_at"],
        vulnerability_assessment_state=state,
        distinct_advisories=row["distinct_found"] if found or completed_direct + completed_dependency > 0 else None,
        direct_advisories=row["direct_found"] if found or completed_direct > 0 else None,
        dependency_advisories=row["dependency_found"] if found or completed_dependency > 0 else None,
        highest_advisory_severity=SEVERITIES.get(row["severity_rank"]))


def summaries(ids):
    return [summarize(row) for row in fetch_all(DETAIL_SQL, {"ids": ids})] if ids else []


def filter_params(params):
    return {**FILTER_DEFAULTS, **params}


def list_servers(params, sort="name", page=1, page_size=25):
    join, order = ORDERS[sort]
    values = filter_params(params)
    sql = FILTER_SQL.format(join=join)
    total = fetch_one(f"SELECT count(*) AS n {sql}", values)["n"]
    ids = [r["server_id"] for r in fetch_all(f"SELECT s.server_id {sql} ORDER BY {order} LIMIT %(limit)s OFFSET %(offset)s",
                                              {**values, "limit": page_size, "offset": (page - 1) * page_size})]
    return total, summaries(ids)


def search_params(q, status, ecosystem, deployment, has_repository, github, assessment, has_tools, tool_info, tool_hints, sort):
    query = (q or "").strip() or None
    if sort == "relevance" and not query:
        sort = "name"
    return {"q": query, "status": status, "ecosystem": ecosystem, "deployment": deployment, "has_repository": has_repository, "github": github,
            "assessment": assessment, "has_tools": has_tools, "tool_info": ",".join(tool_info) if tool_info else None,
            "tool_hints": tool_hints}, sort


@app.get("/api/servers", response_model=ServerPage)
def search_servers(
    q: str | None = Query(None, max_length=200),
    status: Literal["non_deleted", "active", "deprecated", "deleted", "all"] = "non_deleted",
    ecosystem: str | None = Query(None, max_length=40),
    deployment: Literal["remote_only", "packages_only", "packages_and_remotes", "neither"] | None = None,
    has_repository: bool | None = None,
    github: bool | None = None,
    assessment: Literal["findings_recorded", "no_known_findings_in_completed_checks", "checks_could_not_complete",
                        "no_package_vulnerability_path", "not_assessed"] | None = None,
    has_tools: bool | None = None,
    tool_info: list[Literal["listed", "count_observed", "observed_none", "not_observed"]] | None = Query(None),
    tool_hints: bool | None = None,
    sort: Literal["name", "concerns", "newest", "relevance"] = "name",
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(25, ge=1, le=100),
):
    params, sort = search_params(q, status, ecosystem, deployment, has_repository, github, assessment, has_tools, tool_info, tool_hints, sort)
    total, items = list_servers(params, sort, page, page_size)
    return ServerPage(total=total, page=page, page_size=page_size, items=items)


@app.get("/api/servers/export")
def export_servers(
    q: str | None = Query(None, max_length=200),
    status: Literal["non_deleted", "active", "deprecated", "deleted", "all"] = "non_deleted",
    ecosystem: str | None = Query(None, max_length=40),
    deployment: Literal["remote_only", "packages_only", "packages_and_remotes", "neither"] | None = None,
    has_repository: bool | None = None,
    github: bool | None = None,
    assessment: Literal["findings_recorded", "no_known_findings_in_completed_checks", "checks_could_not_complete",
                        "no_package_vulnerability_path", "not_assessed"] | None = None,
    has_tools: bool | None = None,
    tool_info: list[Literal["listed", "count_observed", "observed_none", "not_observed"]] | None = Query(None),
    tool_hints: bool | None = None,
    sort: Literal["name", "concerns", "newest", "relevance"] = "name",
):
    params, sort = search_params(q, status, ecosystem, deployment, has_repository, github, assessment, has_tools, tool_info, tool_hints, sort)
    join, order = ORDERS[sort]
    with pool.connection(timeout=10) as conn:
        ids = [r["server_id"] for r in conn.execute(f"SELECT s.server_id {FILTER_SQL.format(join=join)} ORDER BY {order}", filter_params(params))]

    def lines():
        for start in range(0, len(ids), 2000):
            for item in summaries(ids[start:start + 2000]):
                yield item.model_dump_json() + "\n"

    return StreamingResponse(lines(), media_type="application/x-ndjson", headers={"X-Total-Count": str(len(ids))})


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
    summary = summaries([server_id])[0]
    if not tools and summary.tool_metadata_state == "count_observed":
        missing.append(f"No tool names are stored, but an endpoint handshake (Agora) reported {summary.tool_count} tools.")
    elif not tools and summary.tool_metadata_state == "observed_none":
        missing.append("No tool names are stored; an endpoint handshake (Agora) answered without listing tools.")
    elif not tools:
        missing.append("Tool metadata was not observed in the checked sources. This does not mean the server has no tools.")
    elif not any(t.input_schema_state == "valid" for t in tools):
        missing.append("Tool names are available, but no valid JSON Schema input schema was found.")
    if remotes and not any(r.observations for r in remotes):
        missing.append("No third-party observation is linked to the declared remote endpoints.")
    if state and state["vulnerability_assessment_state"] == "not_assessed":
        missing.append("No vulnerability lookup has been recorded for this server version. Absence of findings is not evidence of safety.")
    return ServerDetail(**{k: row[k] for k in ServerDetail.model_fields if k in row}, repositories=repositories, packages=packages, remotes=remotes,
                        tools=tools, tool_metadata_state=summary.tool_metadata_state, tool_count=summary.tool_count,
                        tool_count_source=summary.tool_count_source, tool_observed_at=summary.tool_observed_at, evidence_sources=sources,
                        missing_information=missing)


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
    for entry in entries:
        name, state = entry.summary.registry_name, entry.summary.vulnerability_assessment_state
        if state == "not_assessed":
            notes.append(f"{name} has no recorded package vulnerability lookup, so its finding count is unknown rather than zero.")
        elif state == "checks_could_not_complete":
            notes.append(f"{name} has no completed eligible package assessment: its checks could not complete, so its finding count is "
                         "unknown rather than zero.")
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
