-- name: coverage_by_state
SELECT evidence_coverage AS assessment_state, COUNT(*) AS servers,
       SUM(COALESCE(completed_vulnerability_checks, 0)) AS completed_checks
FROM gold_server_security GROUP BY evidence_coverage ORDER BY servers DESC;

-- name: findings_by_deployment
SELECT deployment_type, COUNT(*) AS assessed_servers,
       SUM(COALESCE(distinct_advisories, 0)) AS distinct_advisories_sum
FROM gold_server_security WHERE model_eligible = true
GROUP BY deployment_type ORDER BY assessed_servers DESC;

-- name: top_recorded_findings
SELECT registry_name, distinct_advisories, highest_advisory_severity,
       completed_vulnerability_checks, evidence_coverage
FROM gold_server_security WHERE model_eligible = true
ORDER BY distinct_advisories DESC, completed_vulnerability_checks DESC LIMIT 20;

-- name: coverage_gap
SELECT COUNT(*) AS total_servers,
       SUM(CASE WHEN model_eligible THEN 1 ELSE 0 END) AS eligible_servers,
       SUM(CASE WHEN NOT model_eligible THEN 1 ELSE 0 END) AS noneligible_servers
FROM gold_server_security;
