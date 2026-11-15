import gzip
import json
from pathlib import Path

import psycopg
import pytest

from conftest import SEED, run_script

ROOT = Path(__file__).resolve().parents[1]
STABLE = ["servers", "server_versions", "repositories", "server_repositories", "packages", "package_versions", "server_package_declarations",
          "remote_endpoints", "advisories", "advisory_identifiers", "advisory_affected_packages", "evidence_observations", "dependency_resolutions",
          "dependency_edges", "security_findings", "assessment_checks", "tool_observations", "endpoint_observations", "cve_observations"]


def one(db, sql, params=()):
    return db.execute(sql, params).fetchone()[0]


def advisory_for(db, identifier):
    return one(db, "SELECT advisory_id FROM advisory_identifiers WHERE identifier = %s", (identifier,))


def findings_for(db, name):
    return db.execute(
        """SELECT f.finding_category, a.canonical_id, f.match_method, f.range_check, f.finding_status FROM security_findings f
           JOIN server_versions sv ON sv.server_version_id = f.server_version_id JOIN servers s ON s.server_id = sv.server_id
           JOIN advisories a ON a.advisory_id = f.advisory_id WHERE s.registry_name = %s""", (name,)).fetchall()


def test_seed_registry_counts_match_the_seed_snapshot(db):
    with gzip.open(SEED / "registry_snapshot.jsonl.gz", "rt", encoding="utf-8") as handle:
        entries = [json.loads(line) for line in handle]
    statuses = {}
    for entry in entries:
        status = entry["_meta"]["io.modelcontextprotocol.registry/official"]["status"]
        statuses[status] = statuses.get(status, 0) + 1
    assert one(db, "SELECT count(*) FROM servers") == len(entries)
    assert dict(db.execute("SELECT registry_status, count(*) FROM servers GROUP BY 1").fetchall()) == statuses
    declared = sum(1 for e in entries for p in e["server"].get("packages") or [] if (p.get("identifier") or "").strip())
    assert one(db, "SELECT count(*) FROM server_package_declarations") == declared


def test_reimport_is_idempotent(seed_database_url):
    with psycopg.connect(seed_database_url) as conn:
        before = {table: one(conn, f"SELECT count(*) FROM {table}") for table in STABLE}
    run_script("import_registry.py", seed_database_url, "--bundle", str(SEED))
    run_script("import_enrichment.py", seed_database_url, "--bundle", str(SEED))
    with psycopg.connect(seed_database_url) as conn:
        after = {table: one(conn, f"SELECT count(*) FROM {table}") for table in STABLE}
        runs = one(conn, "SELECT count(*) FROM collection_runs WHERE status = 'succeeded'")
    assert after == before
    assert runs > 1


def test_validation_script_passes_on_seed(seed_database_url):
    result = run_script("validate_database.py", seed_database_url, "--bundle", str(SEED))
    report = json.loads(result.stdout)
    assert report["passed"] and report["failed"] == 0


def test_praisonai_direct_findings_group_aliases(db):
    rows = findings_for(db, "io.github.MervinPraison/praisonai")
    direct = {r[1] for r in rows if r[0] == "direct_package"}
    dependency = {r[1] for r in rows if r[0] == "resolved_dependency"}
    assert len(direct) == 81
    assert dependency and not (direct & dependency)
    assert advisory_for(db, "CVE-2026-40159") in {one(db, "SELECT advisory_id FROM advisories WHERE canonical_id = %s", (c,)) for c in direct}
    assert all(r[3] == "affected" and r[4] == "active" for r in rows)
    duplicate_ids = one(db, """SELECT count(*) FROM (SELECT identifier FROM advisory_identifiers GROUP BY identifier HAVING count(*) > 1) x""")
    assert duplicate_ids == 0


def test_python_control_duplicates_are_grouped_with_their_ghsa_record(db):
    for ghsa, pysec in (("GHSA-9h52-p55h-vw2f", None), ("GHSA-5cgr-j3jf-jw3v", None), ("GHSA-vcqx-v2mg-7chx", None), ("GHSA-3r68-hf9h-887v", None)):
        group = db.execute("SELECT identifier FROM advisory_identifiers WHERE advisory_id = %s", (advisory_for(db, ghsa),)).fetchall()
        assert any(identifier.startswith("PYSEC-") for (identifier,) in group), ghsa
        assert sum(1 for (identifier,) in group if identifier.startswith("CVE-")) >= 1


def test_advisory_with_two_cves_is_one_advisory(db):
    advisory = advisory_for(db, "GHSA-gxw4-4fc5-9gr5")
    assert advisory == advisory_for(db, "CVE-2025-53967") == advisory_for(db, "CVE-2025-15061")
    assert one(db, "SELECT canonical_id FROM advisories WHERE advisory_id = %s", (advisory,)) == "GHSA-gxw4-4fc5-9gr5"


def test_registry_versions_after_the_control_fix_are_not_flagged(db):
    assert not [r for r in findings_for(db, "io.github.GLips/Figma-Context-MCP") if r[1] == "GHSA-gxw4-4fc5-9gr5"]
    assert not [r for r in findings_for(db, "io.github.cyanheads/git-mcp-server") if r[1] in ("GHSA-3q26-f695-pp76", "CVE-2025-53107")]
    neo4j = findings_for(db, "io.github.neo4j-contrib/mcp-neo4j-cypher")
    control = one(db, "SELECT canonical_id FROM advisories WHERE advisory_id = %s", (advisory_for(db, "GHSA-vcqx-v2mg-7chx"),))
    assert control not in {r[1] for r in neo4j}
    assert advisory_for(db, "CVE-2026-35402") in {one(db, "SELECT advisory_id FROM advisories WHERE canonical_id = %s", (r[1],)) for r in neo4j}


def test_wireshark_finding_is_a_direct_package_finding(db):
    rows = findings_for(db, "io.github.bx33661/wireshark-mcp")
    assert rows and all(r[0] == "direct_package" and r[2] in ("osv_exact_version_query", "osv_record_range_evaluation") for r in rows)
    assert advisory_for(db, "CVE-2026-43901") in {one(db, "SELECT advisory_id FROM advisories WHERE canonical_id = %s", (r[1],)) for r in rows}
    outcome = one(db, """SELECT c.outcome FROM assessment_checks c JOIN servers s ON s.latest_version_id = c.server_version_id
                          JOIN data_sources ds ON ds.source_id = c.source_id
                          WHERE s.registry_name = 'io.github.bx33661/wireshark-mcp' AND c.check_type = 'direct_package_advisories'
                            AND ds.source_key = 'osv'""")
    assert outcome == "finding_found"


def test_dependency_findings_keep_their_resolution_context(db):
    bad = one(db, """SELECT count(*) FROM security_findings f JOIN server_package_declarations d ON d.declaration_id = f.declaration_id
                     LEFT JOIN dependency_resolutions r ON r.resolution_id = f.resolution_id
                     WHERE f.finding_category = 'resolved_dependency' AND (r.root_package_version_id IS DISTINCT FROM d.package_version_id)""")
    assert bad == 0
    assert one(db, "SELECT count(*) FROM security_findings WHERE finding_category = 'resolved_dependency'") > 0


def test_inexact_declarations_never_create_package_versions(db):
    assert one(db, "SELECT count(*) FROM server_package_declarations WHERE NOT version_is_exact AND package_version_id IS NOT NULL") == 0
    assert one(db, "SELECT count(*) FROM package_versions WHERE version = ''") == 0


def test_shared_repository_links_several_servers(db):
    linked = one(db, """SELECT count(DISTINCT sr.server_version_id) FROM server_repositories sr JOIN repositories r USING (repository_id)
                        WHERE r.canonical_url = 'https://github.com/neo4j-contrib/mcp-neo4j'""")
    assert linked >= 2


def test_unassessed_servers_report_unknown_not_zero(db):
    rows = db.execute("SELECT distinct_advisories, direct_advisories, dependency_advisories FROM server_security_summary "
                      "WHERE vulnerability_assessment_state = 'not_assessed'").fetchall()
    assert rows and all(row == (None, None, None) for row in rows)
    assessed = db.execute("SELECT distinct_advisories FROM server_security_summary WHERE vulnerability_assessment_state = "
                          "'no_known_findings_in_completed_checks'").fetchall()
    assert assessed and all(row[0] == 0 for row in assessed)


def test_remote_only_servers_have_no_package_findings(db):
    assert one(db, """SELECT count(*) FROM security_findings f JOIN server_profiles p ON p.server_version_id = f.server_version_id
                      WHERE p.deployment_type = 'remote_only'""") == 0


def test_kev_negative_lookups_name_their_catalog(db):
    rows = db.execute("SELECT kev_listed, kev_catalog_version FROM cve_observations o JOIN data_sources ds USING (source_id) WHERE ds.source_key = 'cisa_kev'").fetchall()
    assert rows and all(version for _, version in rows)
    assert one(db, "SELECT count(*) FROM cve_observations WHERE cvss_v31_score = 0") == 0


def test_tool_schemas_marked_valid_pass_validation(db):
    from sentinel_common import schema_state
    rows = db.execute("SELECT input_schema FROM tool_observations WHERE input_schema_state = 'valid'").fetchall()
    assert rows and all(schema_state(schema)[0] == "valid" for (schema,) in rows)
    kinds = {k for (k,) in db.execute("SELECT DISTINCT declaration_kind FROM tool_observations")}
    assert kinds <= {"publisher_declared", "curator_declared", "third_party_observed"}


def test_no_secret_values_in_stored_registry_records(db):
    leaked = one(db, """SELECT count(*) FROM server_versions sv, jsonb_path_query(sv.registry_record, 'strict $.**') item
                        WHERE jsonb_typeof(item) = 'object' AND item @> '{"isSecret": true}'
                          AND ((item ? 'value' AND item->>'value' <> '<redacted: isSecret>') OR (item ? 'default' AND item->>'default' <> '<redacted: isSecret>'))""")
    assert leaked == 0


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_report_queries_return_rows(db, index):
    statements = [s.strip() for s in (ROOT / "database" / "queries" / "report_queries.sql").read_text().split(";\n") if s.strip()]
    assert len(statements) == 4
    rows = db.execute(statements[index]).fetchall()
    assert rows
