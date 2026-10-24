CREATE VIEW cve_latest_observations AS
SELECT DISTINCT ON (o.cve_id, o.source_id)
       o.*, ds.source_key
FROM cve_observations o
JOIN data_sources ds ON ds.source_id = o.source_id
ORDER BY o.cve_id, o.source_id, o.observed_at DESC NULLS LAST;

CREATE VIEW advisory_cve_context AS
SELECT ai.advisory_id,
       ai.identifier AS cve_id,
       nvd.nvd_status,
       nvd.cvss_v31_score AS nvd_cvss_v31_score,
       nvd.cvss_v31_severity AS nvd_cvss_v31_severity,
       nvd.cvss_v31_source,
       nvd.observed_at AS nvd_observed_at,
       epss.epss_score,
       epss.epss_percentile,
       epss.epss_model_date,
       kev.kev_listed,
       kev.kev_catalog_version,
       kev.kev_date_added
FROM advisory_identifiers ai
LEFT JOIN cve_latest_observations nvd ON nvd.cve_id = ai.identifier AND nvd.source_key = 'nvd'
LEFT JOIN cve_latest_observations epss ON epss.cve_id = ai.identifier AND epss.source_key = 'epss'
LEFT JOIN cve_latest_observations kev ON kev.cve_id = ai.identifier AND kev.source_key = 'cisa_kev'
WHERE ai.identifier_type = 'CVE';

CREATE VIEW server_profiles AS
SELECT s.server_id,
       s.registry_name,
       s.registry_status,
       s.status_changed_at,
       s.first_seen_at,
       s.last_seen_at,
       sv.server_version_id,
       sv.version,
       sv.title,
       sv.description,
       sv.website_url,
       sv.published_at,
       sv.updated_at,
       sv.observed_at AS snapshot_observed_at,
       COALESCE(p.package_count, 0) AS package_count,
       COALESCE(p.ecosystems, ARRAY[]::TEXT[]) AS ecosystems,
       COALESCE(e.remote_count, 0) AS remote_count,
       COALESCE(r.repository_count, 0) AS repository_count,
       COALESCE(r.has_github_repository, false) AS has_github_repository,
       CASE
           WHEN COALESCE(p.package_count, 0) > 0 AND COALESCE(e.remote_count, 0) > 0 THEN 'packages_and_remotes'
           WHEN COALESCE(p.package_count, 0) > 0 THEN 'packages_only'
           WHEN COALESCE(e.remote_count, 0) > 0 THEN 'remote_only'
           ELSE 'neither'
       END AS deployment_type,
       COALESCE(t.tool_count, 0) AS observed_tool_count,
       COALESCE(t.valid_schema_tools, 0) AS valid_input_schema_count
FROM servers s
JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
LEFT JOIN (
    SELECT server_version_id,
           count(*) AS package_count,
           array_agg(DISTINCT registry_type ORDER BY registry_type) AS ecosystems
    FROM server_package_declarations
    GROUP BY server_version_id
) p ON p.server_version_id = sv.server_version_id
LEFT JOIN (
    SELECT server_version_id, count(*) AS remote_count
    FROM remote_endpoints
    GROUP BY server_version_id
) e ON e.server_version_id = sv.server_version_id
LEFT JOIN (
    SELECT sr.server_version_id,
           count(*) AS repository_count,
           bool_or(r.host = 'github.com') AS has_github_repository
    FROM server_repositories sr
    JOIN repositories r ON r.repository_id = sr.repository_id
    GROUP BY sr.server_version_id
) r ON r.server_version_id = sv.server_version_id
LEFT JOIN (
    SELECT server_version_id,
           count(*) AS tool_count,
           count(*) FILTER (WHERE input_schema_state = 'valid') AS valid_schema_tools
    FROM tool_observations
    GROUP BY server_version_id
) t ON t.server_version_id = sv.server_version_id;

CREATE VIEW server_security_summary AS
WITH findings AS (
    SELECT server_version_id,
           count(DISTINCT advisory_id) AS distinct_advisories,
           count(DISTINCT advisory_id) FILTER (WHERE finding_category = 'direct_package') AS direct_advisories,
           count(DISTINCT advisory_id) FILTER (WHERE finding_category = 'resolved_dependency') AS dependency_advisories,
           count(DISTINCT affected_package_version_id) FILTER (WHERE finding_category = 'resolved_dependency') AS vulnerable_dependency_versions,
           count(*) FILTER (WHERE finding_status = 'conflicting_evidence') AS conflicting_findings,
           max(last_observed_at) AS latest_finding_observed_at
    FROM security_findings
    WHERE finding_status <> 'withdrawn'
    GROUP BY server_version_id
),
severity AS (
    SELECT f.server_version_id,
           max(CASE upper(a.severity_label)
                   WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1
               END) AS severity_rank,
           count(DISTINCT c.cve_id) AS cve_count,
           max(c.nvd_cvss_v31_score) AS max_nvd_cvss_v31,
           max(c.epss_score) AS max_epss_score,
           count(DISTINCT c.cve_id) FILTER (WHERE c.kev_listed) AS kev_listed_cves
    FROM (SELECT DISTINCT server_version_id, advisory_id FROM security_findings WHERE finding_status <> 'withdrawn') f
    JOIN advisories a ON a.advisory_id = f.advisory_id
    LEFT JOIN advisory_cve_context c ON c.advisory_id = f.advisory_id
    GROUP BY f.server_version_id
),
checks AS (
    SELECT server_version_id,
           count(*) FILTER (WHERE check_type = 'direct_package_advisories' AND outcome IN ('finding_found', 'no_known_finding')) AS completed_direct_checks,
           count(*) FILTER (WHERE check_type = 'dependency_advisories' AND outcome IN ('finding_found', 'no_known_finding')) AS completed_dependency_checks,
           count(*) FILTER (WHERE check_type IN ('direct_package_advisories', 'dependency_advisories')
                              AND outcome IN ('missing_identifier', 'unsupported', 'access_restricted', 'error', 'not_found')) AS incomplete_vulnerability_checks,
           count(*) FILTER (WHERE check_type IN ('direct_package_advisories', 'dependency_advisories') AND outcome = 'not_applicable') AS not_applicable_vulnerability_checks,
           count(*) AS total_checks,
           max(checked_at) AS latest_check_at
    FROM assessment_checks
    GROUP BY server_version_id
)
SELECT s.server_id,
       sv.server_version_id,
       s.registry_name,
       CASE
           WHEN COALESCE(f.distinct_advisories, 0) > 0 THEN 'findings_recorded'
           WHEN COALESCE(c.completed_direct_checks, 0) + COALESCE(c.completed_dependency_checks, 0) > 0 THEN 'no_known_findings_in_completed_checks'
           WHEN COALESCE(c.incomplete_vulnerability_checks, 0) > 0 THEN 'checks_could_not_complete'
           WHEN COALESCE(c.not_applicable_vulnerability_checks, 0) > 0 THEN 'no_package_vulnerability_path'
           ELSE 'not_assessed'
       END AS vulnerability_assessment_state,
       CASE WHEN f.server_version_id IS NOT NULL OR COALESCE(c.completed_direct_checks, 0) > 0 THEN COALESCE(f.direct_advisories, 0) END AS direct_advisories,
       CASE WHEN f.server_version_id IS NOT NULL OR COALESCE(c.completed_dependency_checks, 0) > 0 THEN COALESCE(f.dependency_advisories, 0) END AS dependency_advisories,
       CASE WHEN f.server_version_id IS NOT NULL OR COALESCE(c.completed_direct_checks, 0) + COALESCE(c.completed_dependency_checks, 0) > 0 THEN COALESCE(f.distinct_advisories, 0) END AS distinct_advisories,
       f.vulnerable_dependency_versions,
       f.conflicting_findings,
       CASE sev.severity_rank WHEN 4 THEN 'CRITICAL' WHEN 3 THEN 'HIGH' WHEN 2 THEN 'MODERATE' WHEN 1 THEN 'LOW' END AS highest_advisory_severity,
       sev.cve_count,
       sev.max_nvd_cvss_v31,
       sev.max_epss_score,
       sev.kev_listed_cves,
       f.latest_finding_observed_at,
       COALESCE(c.completed_direct_checks, 0) AS completed_direct_checks,
       COALESCE(c.completed_dependency_checks, 0) AS completed_dependency_checks,
       COALESCE(c.incomplete_vulnerability_checks, 0) AS incomplete_vulnerability_checks,
       COALESCE(c.not_applicable_vulnerability_checks, 0) AS not_applicable_vulnerability_checks,
       COALESCE(c.total_checks, 0) AS total_checks,
       c.latest_check_at
FROM servers s
JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
LEFT JOIN findings f ON f.server_version_id = sv.server_version_id
LEFT JOIN severity sev ON sev.server_version_id = sv.server_version_id
LEFT JOIN checks c ON c.server_version_id = sv.server_version_id;

INSERT INTO schema_migrations (version) VALUES ('002_views');
