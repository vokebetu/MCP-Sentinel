from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel

AssessmentState = Literal[
    "findings_recorded", "no_known_findings_in_completed_checks", "checks_could_not_complete", "no_package_vulnerability_path", "not_assessed"
]


class ServerSummary(BaseModel):
    server_id: int
    registry_name: str
    title: str | None
    version: str
    registry_status: str
    ecosystems: list[str]
    deployment_type: str
    has_github_repository: bool
    package_count: int
    remote_count: int
    observed_tool_count: int
    valid_input_schema_count: int
    published_at: datetime | None
    vulnerability_assessment_state: AssessmentState
    distinct_advisories: int | None
    direct_advisories: int | None
    dependency_advisories: int | None
    highest_advisory_severity: str | None


class ServerPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ServerSummary]


class Repository(BaseModel):
    repository_id: int
    canonical_url: str
    host: str
    owner: str | None
    name: str | None
    subfolder: str
    declared_repository_id: str | None
    github_id: int | None
    lookup_status: str | None
    full_name_observed: str | None
    is_archived: bool | None
    is_fork: bool | None
    stars: int | None
    license: str | None
    pushed_at: datetime | None
    metadata_observed_at: datetime | None
    servers_sharing: int


class PackageDeclaration(BaseModel):
    position: int
    registry_type: str
    identifier: str
    declared_version: str | None
    version_is_exact: bool
    published_at: datetime | None
    is_deprecated: bool | None
    is_yanked: bool | None
    metadata_observed_at: datetime | None
    transport_type: str | None
    runtime_hint: str | None
    registry_base_url: str | None
    environment_variables: list[str]
    dependency_resolution: dict[str, Any] | None


class EndpointObservation(BaseModel):
    source: str
    observed_at: datetime | None
    check_result: str | None
    availability_class: str | None
    auth_gated: bool | None
    protocol_version: str | None
    observed_tool_count: int | None


class RemoteEndpoint(BaseModel):
    position: int
    url: str
    transport_type: str
    is_templated: bool
    declares_secret_header: bool
    observations: list[EndpointObservation]


class ToolInfo(BaseModel):
    tool_name: str
    description: str | None
    source: str
    declaration_kind: str
    match_confidence: str | None
    input_schema_state: str
    input_schema: dict[str, Any] | None
    has_output_schema: bool
    annotations: dict[str, Any] | None
    classification: dict[str, Any] | None
    classification_source: str | None
    observed_at: datetime | None


class EvidenceSource(BaseModel):
    source_key: str
    source_name: str
    evidence_types: list[str]
    observations: int
    latest_observed_at: datetime | None
    redistribution: str
    attribution: str | None


class ServerDetail(BaseModel):
    server_id: int
    registry_name: str
    registry_status: str
    status_changed_at: datetime | None
    status_message: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    version: str
    title: str | None
    description: str | None
    website_url: str | None
    published_at: datetime | None
    updated_at: datetime | None
    snapshot_observed_at: datetime
    deployment_type: str
    repositories: list[Repository]
    packages: list[PackageDeclaration]
    remotes: list[RemoteEndpoint]
    tools: list[ToolInfo]
    evidence_sources: list[EvidenceSource]
    missing_information: list[str]


class CveContext(BaseModel):
    cve_id: str
    nvd_status: str | None
    nvd_cvss_v31_score: float | None
    nvd_cvss_v31_severity: str | None
    epss_score: float | None
    epss_percentile: float | None
    epss_model_date: date | None
    kev_listed: bool | None
    kev_catalog_version: str | None


class Finding(BaseModel):
    finding_id: int
    finding_category: Literal["direct_package", "resolved_dependency"]
    evidence_label: str
    advisory_id: str
    identifiers: list[str]
    summary: str | None
    severity_label: str | None
    severity_source: str | None
    advisory_published_at: datetime | None
    affected_ecosystem: str
    affected_package: str
    affected_version: str
    fixed_versions: list[str]
    declared_package: str
    resolution: dict[str, Any] | None
    match_method: str
    range_check: str
    finding_status: str
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_source: str
    evidence_url: str | None
    cves: list[CveContext]


class SecuritySummary(BaseModel):
    vulnerability_assessment_state: AssessmentState
    distinct_advisories: int | None
    direct_advisories: int | None
    dependency_advisories: int | None
    vulnerable_dependency_versions: int | None
    highest_advisory_severity: str | None
    cve_count: int | None
    max_nvd_cvss_v31: float | None
    max_epss_score: float | None
    kev_listed_cves: int | None
    completed_direct_checks: int
    completed_dependency_checks: int
    incomplete_vulnerability_checks: int
    not_applicable_vulnerability_checks: int
    latest_finding_observed_at: datetime | None


class SecurityResponse(BaseModel):
    server_id: int
    registry_name: str
    summary: SecuritySummary
    findings: list[Finding]
    interpretation: list[str]


class CheckRecord(BaseModel):
    check_type: str
    check_scope: str
    source_key: str
    source_name: str
    outcome: str
    subject: str | None
    checked_at: datetime | None
    method: str | None
    reason: str | None


class CheckTypeCoverage(BaseModel):
    check_type: str
    label: str
    applicability: str
    status: Literal["recorded", "not_assessed", "not_applicable_to_server"]
    outcomes: dict[str, int]
    records: list[CheckRecord]


class CoverageResponse(BaseModel):
    server_id: int
    registry_name: str
    check_types: list[CheckTypeCoverage]
    outcome_totals: dict[str, int]
    not_assessed_check_types: list[str]
    methodology: list[str]


class CompareEntry(BaseModel):
    summary: ServerSummary
    snapshot_observed_at: datetime
    repositories: list[Repository]
    packages: list[PackageDeclaration]
    security: SecuritySummary
    coverage: dict[str, list[str]]
    tool_sources: list[str]
    latest_evidence_at: datetime | None
    latest_check_at: datetime | None


class CompareResponse(BaseModel):
    servers: list[CompareEntry]
    notes: list[str]


class SourceInfo(BaseModel):
    source_key: str
    name: str
    license: str | None
    redistribution: str
    attribution: str | None
    notes: str | None
    last_import_at: datetime | None
    evidence_observations: int


class Stats(BaseModel):
    snapshot_collected_at: datetime | None
    last_import_at: datetime | None
    totals: dict[str, int]
    deployment_types: dict[str, int]
    ecosystems: dict[str, int]
    assessment_states: dict[str, int]
    enrichment: dict[str, int]
    sources: list[SourceInfo]
    limitations: list[str]


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    database: str
    schema_versions: list[str]
    servers: int | None


class ReviewItem(BaseModel):
    item: str
    label: str
    status: Literal["present", "missing", "not_assessed", "not_applicable"]
    attention: bool
    detail: str
    source: str | None
    observed_at: datetime | None


class ToolFlag(BaseModel):
    tool_name: str
    flag: str
    explanation: str
    matched_text: str | None


class ReviewResponse(BaseModel):
    server_id: int
    registry_name: str
    version: str
    items: list[ReviewItem]
    tool_flags: list[ToolFlag]
    tool_fingerprint: str | None
    sbom_available: bool
    notes: list[str]
