CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE data_sources (
    source_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_key       TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    source_kind      TEXT NOT NULL,
    homepage_url     TEXT,
    license          TEXT,
    redistribution   TEXT NOT NULL CHECK (redistribution IN ('permitted', 'permitted_with_attribution', 'restricted', 'unknown')),
    attribution      TEXT,
    notes            TEXT
);

CREATE TABLE collection_runs (
    run_id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id            BIGINT NOT NULL REFERENCES data_sources (source_id),
    run_kind             TEXT NOT NULL CHECK (run_kind IN ('registry_import', 'enrichment_import')),
    started_at           TIMESTAMPTZ NOT NULL,
    finished_at          TIMESTAMPTZ,
    status               TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    input_artifact       TEXT NOT NULL,
    input_sha256         TEXT,
    source_collected_at  TIMESTAMPTZ,
    record_counts        JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_count          INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    error_summary        TEXT,
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE import_errors (
    error_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id      BIGINT NOT NULL REFERENCES collection_runs (run_id) ON DELETE CASCADE,
    record_ref  TEXT,
    message     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE servers (
    server_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    registry_name      TEXT NOT NULL UNIQUE,
    registry_status    TEXT NOT NULL CHECK (registry_status IN ('active', 'deprecated', 'deleted')),
    status_changed_at  TIMESTAMPTZ,
    status_message     TEXT,
    first_seen_at      TIMESTAMPTZ NOT NULL,
    last_seen_at       TIMESTAMPTZ NOT NULL,
    latest_version_id  BIGINT,
    CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE server_versions (
    server_version_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id          BIGINT NOT NULL REFERENCES servers (server_id) ON DELETE CASCADE,
    version            TEXT NOT NULL,
    title              TEXT,
    description        TEXT,
    website_url        TEXT,
    schema_url         TEXT,
    is_latest          BOOLEAN,
    published_at       TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ,
    publisher_meta     JSONB,
    icons              JSONB,
    registry_record    JSONB NOT NULL,
    observed_at        TIMESTAMPTZ NOT NULL,
    run_id             BIGINT NOT NULL REFERENCES collection_runs (run_id),
    search_vector      TSVECTOR NOT NULL,
    UNIQUE (server_id, version)
);

ALTER TABLE servers
    ADD CONSTRAINT servers_latest_version_fk
    FOREIGN KEY (latest_version_id) REFERENCES server_versions (server_version_id) ON DELETE SET NULL;

CREATE TABLE repositories (
    repository_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host                  TEXT NOT NULL,
    canonical_url         TEXT NOT NULL UNIQUE,
    owner                 TEXT,
    name                  TEXT,
    github_id             BIGINT UNIQUE,
    lookup_status         TEXT CHECK (lookup_status IN ('found', 'not_found', 'error')),
    full_name_observed    TEXT,
    is_archived           BOOLEAN,
    is_fork               BOOLEAN,
    is_disabled           BOOLEAN,
    stars                 INTEGER CHECK (stars >= 0),
    license               TEXT,
    default_branch        TEXT,
    language              TEXT,
    created_at_source     TIMESTAMPTZ,
    pushed_at             TIMESTAMPTZ,
    metadata_observed_at  TIMESTAMPTZ
);

CREATE TABLE server_repositories (
    server_version_id       BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    repository_id           BIGINT NOT NULL REFERENCES repositories (repository_id),
    subfolder               TEXT NOT NULL DEFAULT '',
    declared_url            TEXT NOT NULL,
    declared_source         TEXT,
    declared_repository_id  TEXT,
    link_method             TEXT NOT NULL DEFAULT 'registry_declared',
    PRIMARY KEY (server_version_id, repository_id, subfolder)
);

CREATE TABLE packages (
    package_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ecosystem        TEXT NOT NULL,
    normalized_name  TEXT NOT NULL,
    display_name     TEXT NOT NULL,
    UNIQUE (ecosystem, normalized_name)
);

CREATE TABLE package_versions (
    package_version_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_id            BIGINT NOT NULL REFERENCES packages (package_id),
    version               TEXT NOT NULL CHECK (version <> ''),
    published_at          TIMESTAMPTZ,
    is_deprecated         BOOLEAN,
    is_yanked             BOOLEAN,
    metadata_observed_at  TIMESTAMPTZ,
    UNIQUE (package_id, version)
);

CREATE TABLE server_package_declarations (
    declaration_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_version_id    BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    position             INTEGER NOT NULL CHECK (position >= 0),
    package_id           BIGINT NOT NULL REFERENCES packages (package_id),
    package_version_id   BIGINT REFERENCES package_versions (package_version_id),
    registry_type        TEXT NOT NULL,
    declared_identifier  TEXT NOT NULL,
    declared_version     TEXT,
    version_is_exact     BOOLEAN NOT NULL,
    registry_base_url    TEXT,
    transport_type       TEXT,
    runtime_hint         TEXT,
    file_sha256          TEXT,
    config               JSONB,
    UNIQUE (server_version_id, position),
    CHECK (package_version_id IS NULL OR version_is_exact)
);

CREATE TABLE remote_endpoints (
    endpoint_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_version_id       BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    position                INTEGER NOT NULL CHECK (position >= 0),
    url                     TEXT NOT NULL,
    normalized_url          TEXT,
    transport_type          TEXT NOT NULL,
    is_templated            BOOLEAN NOT NULL,
    declares_secret_header  BOOLEAN NOT NULL,
    config                  JSONB,
    UNIQUE (server_version_id, position)
);

CREATE TABLE advisories (
    advisory_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    canonical_id         TEXT NOT NULL UNIQUE,
    summary              TEXT,
    details              TEXT,
    published_at         TIMESTAMPTZ,
    modified_at          TIMESTAMPTZ,
    withdrawn_at         TIMESTAMPTZ,
    severity_label       TEXT,
    severity_source      TEXT,
    cvss_vectors         JSONB,
    cwe_ids              TEXT[],
    alias_review_needed  BOOLEAN NOT NULL DEFAULT false,
    alias_review_reason  TEXT
);

CREATE TABLE evidence_observations (
    observation_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id          BIGINT NOT NULL REFERENCES data_sources (source_id),
    run_id             BIGINT NOT NULL REFERENCES collection_runs (run_id),
    observation_key    TEXT NOT NULL,
    observation_kind   TEXT NOT NULL,
    evidence_type      TEXT NOT NULL CHECK (evidence_type IN (
                           'publisher_declared', 'independently_observed', 'official_advisory',
                           'computed_resolution', 'inferred_classification', 'curator_declared', 'third_party_observed')),
    source_record_id   TEXT,
    source_url         TEXT,
    observed_at        TIMESTAMPTZ,
    match_method       TEXT,
    match_confidence   TEXT CHECK (match_confidence IN ('high', 'medium', 'low')),
    server_version_id  BIGINT REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    package_version_id BIGINT REFERENCES package_versions (package_version_id),
    repository_id      BIGINT REFERENCES repositories (repository_id),
    endpoint_id        BIGINT REFERENCES remote_endpoints (endpoint_id) ON DELETE CASCADE,
    advisory_id        BIGINT REFERENCES advisories (advisory_id),
    payload            JSONB,
    UNIQUE (source_id, observation_key)
);

CREATE TABLE advisory_identifiers (
    identifier          TEXT PRIMARY KEY,
    advisory_id         BIGINT NOT NULL REFERENCES advisories (advisory_id) ON DELETE CASCADE,
    identifier_type     TEXT NOT NULL CHECK (identifier_type IN ('CVE', 'GHSA', 'PYSEC', 'OSV', 'OTHER')),
    osv_observation_id  BIGINT REFERENCES evidence_observations (observation_id)
);

CREATE TABLE advisory_affected_packages (
    affected_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    advisory_id        BIGINT NOT NULL REFERENCES advisories (advisory_id) ON DELETE CASCADE,
    package_id         BIGINT NOT NULL REFERENCES packages (package_id),
    source_record_id   TEXT NOT NULL,
    entry_index        INTEGER NOT NULL CHECK (entry_index >= 0),
    ranges             JSONB NOT NULL,
    affected_versions  JSONB,
    fixed_versions     TEXT[],
    observation_id     BIGINT NOT NULL REFERENCES evidence_observations (observation_id),
    UNIQUE (source_record_id, entry_index)
);

CREATE TABLE dependency_resolutions (
    resolution_id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_package_version_id  BIGINT NOT NULL REFERENCES package_versions (package_version_id),
    source_id                BIGINT NOT NULL REFERENCES data_sources (source_id),
    observation_id           BIGINT NOT NULL REFERENCES evidence_observations (observation_id),
    resolved_at              TIMESTAMPTZ NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'failed')),
    node_count               INTEGER CHECK (node_count >= 0),
    edge_count               INTEGER CHECK (edge_count >= 0),
    error                    TEXT,
    UNIQUE (root_package_version_id, source_id, resolved_at)
);

CREATE TABLE dependency_edges (
    edge_id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resolution_id            BIGINT NOT NULL REFERENCES dependency_resolutions (resolution_id) ON DELETE CASCADE,
    from_node                INTEGER NOT NULL CHECK (from_node >= 0),
    to_node                  INTEGER NOT NULL CHECK (to_node >= 0),
    from_package_version_id  BIGINT REFERENCES package_versions (package_version_id),
    to_package_version_id    BIGINT REFERENCES package_versions (package_version_id),
    to_ecosystem             TEXT NOT NULL,
    to_name                  TEXT NOT NULL,
    to_version               TEXT,
    to_relation              TEXT CHECK (to_relation IN ('SELF', 'DIRECT', 'INDIRECT')),
    requirement              TEXT,
    to_errors                JSONB,
    UNIQUE (resolution_id, from_node, to_node)
);

CREATE TABLE security_findings (
    finding_id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_version_id           BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    advisory_id                 BIGINT NOT NULL REFERENCES advisories (advisory_id),
    affected_package_version_id BIGINT NOT NULL REFERENCES package_versions (package_version_id),
    finding_category            TEXT NOT NULL CHECK (finding_category IN ('direct_package', 'resolved_dependency')),
    declaration_id              BIGINT NOT NULL REFERENCES server_package_declarations (declaration_id) ON DELETE CASCADE,
    resolution_id               BIGINT REFERENCES dependency_resolutions (resolution_id),
    observation_id              BIGINT NOT NULL REFERENCES evidence_observations (observation_id),
    match_method                TEXT NOT NULL CHECK (match_method IN ('osv_exact_version_query', 'osv_record_range_evaluation')),
    range_check                 TEXT NOT NULL CHECK (range_check IN ('affected', 'not_affected', 'undetermined')),
    finding_status              TEXT NOT NULL CHECK (finding_status IN ('active', 'conflicting_evidence', 'withdrawn')),
    first_observed_at           TIMESTAMPTZ NOT NULL,
    last_observed_at            TIMESTAMPTZ NOT NULL,
    CHECK ((finding_category = 'resolved_dependency') = (resolution_id IS NOT NULL)),
    CHECK (last_observed_at >= first_observed_at),
    UNIQUE (server_version_id, advisory_id, affected_package_version_id, finding_category)
);

CREATE TABLE assessment_checks (
    check_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    check_key          TEXT NOT NULL UNIQUE,
    server_version_id  BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    check_type         TEXT NOT NULL CHECK (check_type IN (
                           'repository_metadata', 'package_metadata', 'dependency_resolution',
                           'direct_package_advisories', 'dependency_advisories', 'endpoint_status', 'tool_metadata')),
    check_scope        TEXT NOT NULL CHECK (check_scope IN ('server', 'package_declaration', 'repository', 'endpoint')),
    declaration_id     BIGINT REFERENCES server_package_declarations (declaration_id) ON DELETE CASCADE,
    resolution_id      BIGINT REFERENCES dependency_resolutions (resolution_id),
    repository_id      BIGINT REFERENCES repositories (repository_id),
    endpoint_id        BIGINT REFERENCES remote_endpoints (endpoint_id) ON DELETE CASCADE,
    source_id          BIGINT NOT NULL REFERENCES data_sources (source_id),
    run_id             BIGINT NOT NULL REFERENCES collection_runs (run_id),
    observation_id     BIGINT REFERENCES evidence_observations (observation_id),
    checked_at         TIMESTAMPTZ,
    outcome            TEXT NOT NULL CHECK (outcome IN (
                           'finding_found', 'no_known_finding', 'evidence_found', 'not_found',
                           'missing_identifier', 'not_applicable', 'unsupported', 'access_restricted', 'error')),
    method             TEXT,
    reason             TEXT,
    details            JSONB,
    CHECK (check_scope <> 'package_declaration' OR declaration_id IS NOT NULL OR outcome IN ('not_applicable', 'missing_identifier')),
    CHECK (outcome NOT IN ('finding_found', 'no_known_finding') OR check_type IN ('direct_package_advisories', 'dependency_advisories'))
);

CREATE TABLE tool_observations (
    tool_observation_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_version_id     BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    endpoint_id           BIGINT REFERENCES remote_endpoints (endpoint_id) ON DELETE CASCADE,
    observation_id        BIGINT NOT NULL REFERENCES evidence_observations (observation_id) ON DELETE CASCADE,
    tool_position         INTEGER NOT NULL CHECK (tool_position >= 0),
    tool_name             TEXT NOT NULL,
    description           TEXT,
    declaration_kind      TEXT NOT NULL CHECK (declaration_kind IN ('publisher_declared', 'curator_declared', 'third_party_observed')),
    input_schema          JSONB,
    input_schema_state    TEXT NOT NULL CHECK (input_schema_state IN ('valid', 'empty', 'invalid', 'not_object', 'absent', 'unparseable')),
    output_schema         JSONB,
    annotations           JSONB,
    classification        JSONB,
    classification_source TEXT,
    observed_at           TIMESTAMPTZ,
    UNIQUE (observation_id, tool_position),
    CHECK (input_schema_state <> 'valid' OR input_schema IS NOT NULL),
    CHECK (classification IS NULL OR classification_source IS NOT NULL)
);

CREATE TABLE endpoint_observations (
    endpoint_observation_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_version_id        BIGINT NOT NULL REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    endpoint_id              BIGINT REFERENCES remote_endpoints (endpoint_id) ON DELETE CASCADE,
    observation_id           BIGINT NOT NULL UNIQUE REFERENCES evidence_observations (observation_id) ON DELETE CASCADE,
    observed_url             TEXT,
    check_result             TEXT,
    availability_class       TEXT,
    auth_gated               BOOLEAN,
    protocol_version         TEXT,
    observed_tool_count      INTEGER CHECK (observed_tool_count >= 0),
    observed_at              TIMESTAMPTZ
);

CREATE TABLE cve_observations (
    cve_observation_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id               TEXT NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    source_id            BIGINT NOT NULL REFERENCES data_sources (source_id),
    observation_id       BIGINT REFERENCES evidence_observations (observation_id),
    observed_at          TIMESTAMPTZ,
    lookup_status        TEXT NOT NULL CHECK (lookup_status IN ('found', 'not_found', 'error')),
    record_state         TEXT,
    nvd_status           TEXT,
    cvss_v31_score       NUMERIC(3, 1) CHECK (cvss_v31_score BETWEEN 0 AND 10),
    cvss_v31_severity    TEXT CHECK (cvss_v31_severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cvss_v31_vector      TEXT,
    cvss_v31_source      TEXT,
    cvss_v40_score       NUMERIC(3, 1) CHECK (cvss_v40_score BETWEEN 0 AND 10),
    epss_score           NUMERIC(10, 9) CHECK (epss_score BETWEEN 0 AND 1),
    epss_percentile      NUMERIC(10, 9) CHECK (epss_percentile BETWEEN 0 AND 1),
    epss_model_date      DATE,
    kev_listed           BOOLEAN,
    kev_catalog_version  TEXT,
    kev_date_added       DATE,
    kev_ransomware_use   TEXT,
    UNIQUE (cve_id, source_id, observed_at),
    CHECK (kev_listed IS NULL OR kev_catalog_version IS NOT NULL)
);

CREATE INDEX servers_status_idx ON servers (registry_status);
CREATE INDEX servers_name_trgm_idx ON servers USING gin (registry_name gin_trgm_ops);
CREATE INDEX server_versions_server_idx ON server_versions (server_id);
CREATE INDEX server_versions_search_idx ON server_versions USING gin (search_vector);
CREATE INDEX server_versions_published_idx ON server_versions (published_at);
CREATE INDEX server_repositories_repository_idx ON server_repositories (repository_id);
CREATE INDEX package_versions_package_idx ON package_versions (package_id);
CREATE INDEX declarations_package_idx ON server_package_declarations (package_id);
CREATE INDEX declarations_package_version_idx ON server_package_declarations (package_version_id);
CREATE INDEX remote_endpoints_version_idx ON remote_endpoints (server_version_id);
CREATE INDEX remote_endpoints_normalized_idx ON remote_endpoints (normalized_url);
CREATE INDEX evidence_server_version_idx ON evidence_observations (server_version_id);
CREATE INDEX evidence_package_version_idx ON evidence_observations (package_version_id);
CREATE INDEX evidence_repository_idx ON evidence_observations (repository_id);
CREATE INDEX evidence_advisory_idx ON evidence_observations (advisory_id);
CREATE INDEX evidence_observed_at_idx ON evidence_observations (observed_at);
CREATE INDEX advisory_identifiers_advisory_idx ON advisory_identifiers (advisory_id);
CREATE INDEX advisory_affected_package_idx ON advisory_affected_packages (package_id);
CREATE INDEX advisory_affected_advisory_idx ON advisory_affected_packages (advisory_id);
CREATE INDEX resolutions_root_idx ON dependency_resolutions (root_package_version_id);
CREATE INDEX edges_to_version_idx ON dependency_edges (to_package_version_id);
CREATE INDEX findings_server_version_idx ON security_findings (server_version_id);
CREATE INDEX findings_advisory_idx ON security_findings (advisory_id);
CREATE INDEX checks_server_version_idx ON assessment_checks (server_version_id, check_type);
CREATE INDEX checks_outcome_idx ON assessment_checks (check_type, outcome);
CREATE INDEX tool_observations_version_idx ON tool_observations (server_version_id);
CREATE INDEX endpoint_observations_version_idx ON endpoint_observations (server_version_id);
CREATE INDEX endpoint_observations_endpoint_idx ON endpoint_observations (endpoint_id);
CREATE INDEX cve_observations_cve_idx ON cve_observations (cve_id);

INSERT INTO schema_migrations (version) VALUES ('001_initial');
