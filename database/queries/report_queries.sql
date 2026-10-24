WITH inventory AS (
    SELECT server_id, latest_version_id FROM servers WHERE registry_status <> 'deleted'
),
declarations AS (
    SELECT i.server_id, d.registry_type
    FROM inventory i
    JOIN server_package_declarations d ON d.server_version_id = i.latest_version_id
),
multi_ecosystem AS (
    SELECT server_id FROM declarations GROUP BY server_id HAVING count(DISTINCT registry_type) > 1
)
SELECT ecosystem, servers, package_declarations, servers_also_in_another_ecosystem, pct_of_inventory
FROM (
    SELECT d.registry_type AS ecosystem,
           count(DISTINCT d.server_id) AS servers,
           count(*) AS package_declarations,
           count(DISTINCT d.server_id) FILTER (WHERE m.server_id IS NOT NULL) AS servers_also_in_another_ecosystem,
           round(100.0 * count(DISTINCT d.server_id) / (SELECT count(*) FROM inventory), 1) AS pct_of_inventory
    FROM declarations d
    LEFT JOIN multi_ecosystem m ON m.server_id = d.server_id
    GROUP BY d.registry_type
    UNION ALL
    SELECT '(no package declared)', count(*), 0, 0, round(100.0 * count(*) / (SELECT count(*) FROM inventory), 1)
    FROM inventory i
    WHERE NOT EXISTS (SELECT 1 FROM declarations d WHERE d.server_id = i.server_id)
    UNION ALL
    SELECT '(distinct servers with any package)', count(DISTINCT server_id), count(*),
           (SELECT count(*) FROM multi_ecosystem), round(100.0 * count(DISTINCT server_id) / (SELECT count(*) FROM inventory), 1)
    FROM declarations
) distribution
ORDER BY servers DESC;

SELECT s.registry_name,
       sv.version AS registry_version,
       d.registry_type || ':' || d.declared_identifier || '@' || d.declared_version AS declared_package,
       f.finding_category,
       CASE f.finding_category WHEN 'direct_package' THEN 'known vulnerability in declared version'
                               ELSE 'modeled dependency exposure (deps.dev graph)' END AS evidence_meaning,
       a.canonical_id AS advisory,
       (SELECT string_agg(ai.identifier, ', ' ORDER BY ai.identifier) FROM advisory_identifiers ai
         WHERE ai.advisory_id = a.advisory_id AND ai.identifier_type = 'CVE') AS cve_ids,
       (SELECT string_agg(ai.identifier, ', ' ORDER BY ai.identifier) FROM advisory_identifiers ai
         WHERE ai.advisory_id = a.advisory_id AND ai.identifier_type <> 'CVE') AS other_ids,
       a.severity_label AS ghsa_severity,
       (SELECT max(c.nvd_cvss_v31_score) FROM advisory_cve_context c WHERE c.advisory_id = a.advisory_id) AS nvd_cvss_v31,
       (SELECT max(c.epss_score) FROM advisory_cve_context c WHERE c.advisory_id = a.advisory_id) AS max_epss,
       p.display_name || '@' || pv.version AS affected_package_version,
       (SELECT string_agg(DISTINCT fv, ', ') FROM advisory_affected_packages aap, unnest(aap.fixed_versions) fv
         WHERE aap.advisory_id = a.advisory_id AND aap.package_id = p.package_id) AS fixed_in,
       ds.name AS evidence_source,
       f.match_method,
       f.range_check,
       f.last_observed_at::date AS observed
FROM servers s
JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
JOIN security_findings f ON f.server_version_id = sv.server_version_id
JOIN advisories a ON a.advisory_id = f.advisory_id
JOIN server_package_declarations d ON d.declaration_id = f.declaration_id
JOIN package_versions pv ON pv.package_version_id = f.affected_package_version_id
JOIN packages p ON p.package_id = pv.package_id
JOIN evidence_observations e ON e.observation_id = f.observation_id
JOIN data_sources ds ON ds.source_id = e.source_id
WHERE s.registry_name = 'io.github.MervinPraison/praisonai'
ORDER BY f.finding_category,
         CASE upper(a.severity_label) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
         nvd_cvss_v31 DESC NULLS LAST, a.canonical_id;

SELECT s.registry_name,
       f.finding_category,
       count(DISTINCT f.finding_id) AS findings,
       count(DISTINCT f.advisory_id) AS distinct_advisories,
       count(DISTINCT ai.identifier) AS cve_ids,
       count(DISTINCT f.advisory_id) FILTER (WHERE upper(a.severity_label) IN ('CRITICAL', 'HIGH')) AS critical_or_high,
       max(c.nvd_cvss_v31_score) AS max_nvd_cvss_v31,
       max(c.epss_score) AS max_epss,
       count(DISTINCT ai.identifier) FILTER (WHERE c.kev_listed) AS kev_listed,
       string_agg(DISTINCT p.display_name || '@' || pv.version, ', ') AS affected_package_versions
FROM servers s
JOIN security_findings f ON f.server_version_id = s.latest_version_id
JOIN advisories a ON a.advisory_id = f.advisory_id
JOIN package_versions pv ON pv.package_version_id = f.affected_package_version_id
JOIN packages p ON p.package_id = pv.package_id
LEFT JOIN advisory_identifiers ai ON ai.advisory_id = a.advisory_id AND ai.identifier_type = 'CVE'
LEFT JOIN advisory_cve_context c ON c.advisory_id = a.advisory_id AND c.cve_id = ai.identifier
WHERE s.registry_name = 'io.github.MervinPraison/praisonai'
GROUP BY s.registry_name, f.finding_category
ORDER BY f.finding_category;

WITH compared AS (
    SELECT s.server_id, s.registry_name, s.latest_version_id
    FROM servers s
    WHERE s.registry_name IN ('io.github.Buer2333/tiktok-shop-mcp', 'io.github.06ketan/medium-ops')
),
checks AS (
    SELECT c.server_version_id, c.check_type,
           string_agg(DISTINCT ds.source_key || ':' || c.outcome, ', ') AS outcomes
    FROM assessment_checks c
    JOIN data_sources ds ON ds.source_id = c.source_id
    WHERE c.server_version_id IN (SELECT latest_version_id FROM compared)
    GROUP BY c.server_version_id, c.check_type
),
check_matrix AS (
    SELECT x.server_id, t.check_type, COALESCE(ch.outcomes, 'not_assessed') AS outcomes
    FROM compared x
    CROSS JOIN (VALUES ('repository_metadata'), ('package_metadata'), ('dependency_resolution'), ('direct_package_advisories'),
                       ('dependency_advisories'), ('endpoint_status'), ('tool_metadata')) AS t(check_type)
    LEFT JOIN checks ch ON ch.server_version_id = x.latest_version_id AND ch.check_type = t.check_type
)
SELECT x.registry_name,
       pr.deployment_type,
       (SELECT string_agg(d.registry_type || ':' || d.declared_identifier || '@' || COALESCE(d.declared_version, '?'), ', ')
          FROM server_package_declarations d WHERE d.server_version_id = x.latest_version_id) AS declared_packages,
       (SELECT string_agg(r.canonical_url || ' [GitHub lookup: ' || COALESCE(r.lookup_status, 'not checked') || ']', ', ')
          FROM server_repositories sr JOIN repositories r ON r.repository_id = sr.repository_id
         WHERE sr.server_version_id = x.latest_version_id) AS repository,
       ss.direct_advisories,
       ss.dependency_advisories,
       ss.vulnerability_assessment_state,
       (SELECT string_agg(m.check_type || '=' || m.outcomes, '; ' ORDER BY m.check_type) FROM check_matrix m
         WHERE m.server_id = x.server_id) AS recorded_assessment_outcomes,
       (SELECT string_agg(m.check_type, ', ' ORDER BY m.check_type) FROM check_matrix m
         WHERE m.server_id = x.server_id AND (m.outcomes = 'not_assessed' OR m.outcomes ~ '(missing_identifier|unsupported|access_restricted|error)')) AS missing_or_incomplete_checks,
       CASE ss.vulnerability_assessment_state
           WHEN 'findings_recorded' THEN 'findings recorded; inspect them individually as in query 2'
           WHEN 'no_known_findings_in_completed_checks' THEN 'no known advisories in the completed checks (not proof of safety)'
           WHEN 'not_assessed' THEN 'finding count unknown: no vulnerability lookup was recorded'
           ELSE 'vulnerability checks could not complete or do not apply'
       END AS interpretation
FROM compared x
JOIN server_profiles pr ON pr.server_id = x.server_id
JOIN server_security_summary ss ON ss.server_id = x.server_id
ORDER BY x.registry_name DESC;
