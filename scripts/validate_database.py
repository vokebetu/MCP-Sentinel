import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_common import OFFICIAL, ROOT, canonical_repository, connect, is_exact_version, normalize_package_name, range_status, read_jsonl_gz

STABLE_TABLES = [
    "data_sources", "servers", "server_versions", "repositories", "server_repositories", "packages", "package_versions",
    "server_package_declarations", "remote_endpoints", "advisories", "advisory_identifiers", "advisory_affected_packages",
    "evidence_observations", "dependency_resolutions", "dependency_edges", "security_findings", "assessment_checks",
    "tool_observations", "endpoint_observations", "cve_observations",
]
REFERENCE_FIGURES = {"non_deleted": 48673, "package_declarations": 20175, "remote_endpoints": 32726, "active": 48056, "deprecated": 617, "deleted": 1346}


def snapshot_expectations(bundle):
    statuses = Counter()
    declarations = remotes = inexact = 0
    shared = Counter()
    names = set()
    for _, line in read_jsonl_gz(Path(bundle) / "registry_snapshot.jsonl.gz"):
        entry = json.loads(line)
        server = entry["server"]
        status = ((entry.get("_meta") or {}).get(OFFICIAL) or {}).get("status")
        names.add(server["name"])
        statuses[status] += 1
        if status == "deleted":
            continue
        packages = [p for p in server.get("packages") or [] if (p.get("identifier") or "").strip()]
        declarations += len(packages)
        inexact += sum(1 for p in packages if not is_exact_version((p.get("version") or "").strip()))
        remotes += sum(1 for r in server.get("remotes") or [] if (r.get("url") or "").strip())
        repo = canonical_repository((server.get("repository") or {}).get("url"))
        if repo and repo["host"] == "github.com":
            shared[repo["canonical_url"]] += 1
    return {"servers": len(names), "active": statuses["active"], "deprecated": statuses["deprecated"], "deleted": statuses["deleted"],
            "non_deleted": len(names) - statuses["deleted"], "package_declarations": declarations, "remote_endpoints": remotes,
            "inexact_declarations": inexact, "shared_github_repositories": sum(1 for count in shared.values() if count > 1)}


def scalar(conn, sql, params=None):
    return conn.execute(sql, params or ()).fetchone()[0]


def table_counts(conn):
    return {table: scalar(conn, f"SELECT count(*) FROM {table}") for table in STABLE_TABLES}


def control_checks(conn, results):
    path = ROOT / "tests" / "fixtures" / "positive_controls.csv"
    with open(path, encoding="utf-8", newline="") as handle:
        controls = list(csv.DictReader(handle))
    for control in controls:
        ecosystem = {"npm": "npm", "PyPI": "pypi"}[control["ecosystem"]]
        rows = conn.execute(
            """
            SELECT aap.ranges, aap.affected_versions FROM advisory_affected_packages aap
            JOIN packages p ON p.package_id = aap.package_id
            JOIN advisory_identifiers ai ON ai.advisory_id = aap.advisory_id
            WHERE ai.identifier = %s AND p.ecosystem = %s AND p.normalized_name = %s
            """,
            (control["primary_advisory"], ecosystem, normalize_package_name(ecosystem, control["package"])),
        ).fetchall()
        if not rows:
            results.append({"check": f"positive control {control['control_id']}", "passed": None, "detail": "advisory not stored in this database (seed subset)"})
            continue
        entries = [{"ranges": ranges, "versions": versions or []} for ranges, versions in rows]
        affected = any(range_status(ecosystem, control["tested_affected_version"], entry) == "affected" for entry in entries)
        fixed = any(range_status(ecosystem, control["tested_fixed_version"], entry) == "affected" for entry in entries)
        results.append({"check": f"positive control {control['control_id']} {control['package']}", "passed": affected and not fixed,
                        "detail": f"{control['tested_affected_version']} affected={affected}; {control['tested_fixed_version']} affected={fixed}"})
        false_positive = scalar(conn, """
            SELECT count(*) FROM security_findings f
            JOIN package_versions pv ON pv.package_version_id = f.affected_package_version_id
            JOIN packages p ON p.package_id = pv.package_id
            JOIN advisory_identifiers ai ON ai.advisory_id = f.advisory_id AND ai.identifier = %s
            WHERE p.ecosystem = %s AND p.normalized_name = %s AND pv.version = %s
            """, (control["primary_advisory"], ecosystem, normalize_package_name(ecosystem, control["package"]), control["tested_fixed_version"]))
        results.append({"check": f"positive control {control['control_id']} fixed version has no finding", "passed": false_positive == 0, "detail": false_positive})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    args = parser.parse_args()
    expected = snapshot_expectations(args.bundle)
    results = []

    def check(name, actual, wanted, reference=None):
        results.append({"check": name, "passed": actual == wanted, "actual": actual, "expected_from_source": wanted,
                        **({"reference": reference} if reference is not None else {})})

    with connect() as conn:
        status = dict(conn.execute("SELECT registry_status, count(*) FROM servers GROUP BY 1").fetchall())
        check("registry identities", scalar(conn, "SELECT count(*) FROM servers"), expected["servers"])
        for key in ("active", "deprecated", "deleted"):
            check(f"status {key}", status.get(key, 0), expected[key], REFERENCE_FIGURES[key] if expected["servers"] > 40000 else None)
        check("non-deleted inventory", scalar(conn, "SELECT count(*) FROM servers WHERE registry_status <> 'deleted'"), expected["non_deleted"],
              REFERENCE_FIGURES["non_deleted"] if expected["servers"] > 40000 else None)
        check("package declarations (non-deleted)", scalar(conn, """SELECT count(*) FROM server_package_declarations d JOIN servers s
              ON s.latest_version_id = d.server_version_id WHERE s.registry_status <> 'deleted'"""), expected["package_declarations"],
              REFERENCE_FIGURES["package_declarations"] if expected["servers"] > 40000 else None)
        check("remote endpoints (non-deleted)", scalar(conn, """SELECT count(*) FROM remote_endpoints e JOIN servers s
              ON s.latest_version_id = e.server_version_id WHERE s.registry_status <> 'deleted'"""), expected["remote_endpoints"],
              REFERENCE_FIGURES["remote_endpoints"] if expected["servers"] > 40000 else None)
        check("every server has a latest version", scalar(conn, "SELECT count(*) FROM servers WHERE latest_version_id IS NULL"), 0)
        check("unvalidated constraints", scalar(conn, "SELECT count(*) FROM pg_constraint WHERE NOT convalidated"), 0)
        check("shared GitHub repositories (non-deleted)", scalar(conn, """
              SELECT count(*) FROM (SELECT sr.repository_id FROM server_repositories sr JOIN repositories r USING (repository_id)
              JOIN servers s ON s.latest_version_id = sr.server_version_id WHERE s.registry_status <> 'deleted' AND r.host = 'github.com'
              GROUP BY sr.repository_id HAVING count(*) > 1) x"""), expected["shared_github_repositories"])
        check("inexact declarations keep a NULL package version", scalar(conn, """SELECT count(*) FROM server_package_declarations d JOIN servers s
              ON s.latest_version_id = d.server_version_id WHERE s.registry_status <> 'deleted' AND NOT d.version_is_exact AND d.package_version_id IS NULL"""),
              expected["inexact_declarations"])
        check("no package version created for an inexact declaration", scalar(conn, """SELECT count(*) FROM server_package_declarations
              WHERE NOT version_is_exact AND package_version_id IS NOT NULL"""), 0)
        check("findings whose stored OSV ranges do not cover the version", scalar(conn, "SELECT count(*) FROM security_findings WHERE range_check = 'not_affected'"), 0)
        check("dependency findings without resolution context", scalar(conn, """SELECT count(*) FROM security_findings f
              LEFT JOIN dependency_resolutions r ON r.resolution_id = f.resolution_id
              JOIN server_package_declarations d ON d.declaration_id = f.declaration_id
              WHERE f.finding_category = 'resolved_dependency' AND (r.resolution_id IS NULL OR r.root_package_version_id IS DISTINCT FROM d.package_version_id)"""), 0)
        check("direct findings not tied to the declared exact version", scalar(conn, """SELECT count(*) FROM security_findings f
              JOIN server_package_declarations d ON d.declaration_id = f.declaration_id
              WHERE f.finding_category = 'direct_package' AND f.affected_package_version_id IS DISTINCT FROM d.package_version_id"""), 0)
        check("findings without traceable evidence", scalar(conn, """SELECT count(*) FROM security_findings f
              LEFT JOIN evidence_observations e ON e.observation_id = f.observation_id WHERE e.observation_id IS NULL"""), 0)
        check("findings on servers without package declarations", scalar(conn, """SELECT count(*) FROM security_findings f
              WHERE NOT EXISTS (SELECT 1 FROM server_package_declarations d WHERE d.server_version_id = f.server_version_id)"""), 0)
        check("advisories without a stored OSV record", scalar(conn, """SELECT count(*) FROM advisories a WHERE NOT EXISTS
              (SELECT 1 FROM advisory_identifiers ai WHERE ai.advisory_id = a.advisory_id AND ai.osv_observation_id IS NOT NULL)"""), 0)
        check("CVSS scores stored as zero placeholders", scalar(conn, "SELECT count(*) FROM cve_observations WHERE cvss_v31_score = 0"), 0)
        check("KEV results without a catalog version", scalar(conn, "SELECT count(*) FROM cve_observations WHERE kev_listed IS NOT NULL AND kev_catalog_version IS NULL"), 0)
        check("valid tool schemas missing a schema document", scalar(conn, "SELECT count(*) FROM tool_observations WHERE input_schema_state = 'valid' AND input_schema IS NULL"), 0)
        check("finding_found checks without a stored finding", scalar(conn, """SELECT count(*) FROM assessment_checks c
              WHERE c.check_type = 'direct_package_advisories' AND c.outcome = 'finding_found'
              AND NOT EXISTS (SELECT 1 FROM security_findings f WHERE f.server_version_id = c.server_version_id)"""), 0)
        control_checks(conn, results)
        counts = table_counts(conn)
        summary = {
            "servers_with_findings": scalar(conn, "SELECT count(DISTINCT server_version_id) FROM security_findings"),
            "distinct_advisories_in_findings": scalar(conn, "SELECT count(DISTINCT advisory_id) FROM security_findings"),
            "servers_with_valid_tool_schemas": scalar(conn, "SELECT count(DISTINCT server_version_id) FROM tool_observations WHERE input_schema_state = 'valid'"),
            "assessment_states": dict(conn.execute("SELECT vulnerability_assessment_state, count(*) FROM server_security_summary GROUP BY 1 ORDER BY 1").fetchall()),
        }
    failed = [r for r in results if r["passed"] is False]
    output = {"passed": not failed, "checks": len(results), "failed": len(failed), "results": results, "table_counts": counts, "summary": summary,
              "snapshot_expectations": expected}
    print(json.dumps(output, indent=2, default=str))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
