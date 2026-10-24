import csv
import gzip
import json
import re
from pathlib import Path

import pytest

from sentinel_common import (
    REDACTED, canonical_repository, clean_subfolder, is_exact_version, normalize_endpoint, normalize_package_name, range_status, redact_secrets,
    schema_state,
)

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = ROOT / "tests" / "fixtures" / "positive_controls.csv"
SEED_EVIDENCE = ROOT / "data" / "seed" / "evidence.jsonl.gz"


def seed_osv_records():
    with gzip.open(SEED_EVIDENCE, "rt", encoding="utf-8") as handle:
        return {r["id"]: r["body"] for r in map(json.loads, handle) if r["kind"] == "osv_record"}


def test_pypi_names_use_pep503_but_npm_names_do_not():
    assert normalize_package_name("pypi", "Mcp_Neo4j.Cypher") == "mcp-neo4j-cypher"
    assert normalize_package_name("npm", "@Scope/Some_Package") == "@Scope/Some_Package"
    assert normalize_package_name("nuget", "My.Package") == "my.package"


@pytest.mark.parametrize("version, exact", [("1.2.3", True), ("2025.7.1", True), ("^1.2.0", False), (">=1.0", False), ("latest", False),
                                            ("1.x", False), ("", False), (None, False)])
def test_exact_version_detection(version, exact):
    assert is_exact_version(version) is exact


def test_github_repositories_are_canonical_without_merging_other_hosts():
    a = canonical_repository("https://github.com/Neo4j-Contrib/mcp-neo4j.git")
    b = canonical_repository("https://www.github.com/neo4j-contrib/MCP-Neo4j/tree/main/servers")
    assert a["canonical_url"] == b["canonical_url"] == "https://github.com/neo4j-contrib/mcp-neo4j"
    assert a["owner"] == "Neo4j-Contrib"
    assert canonical_repository("https://gitlab.com/Group/Project")["canonical_url"] == "https://gitlab.com/Group/Project"
    assert canonical_repository("https://gitlab.com/Group/Project") != canonical_repository("https://gitlab.com/group/project")
    assert canonical_repository("") is None and canonical_repository("not a url") is None
    assert clean_subfolder("./servers/x/") == "servers/x"


def test_endpoint_normalization():
    assert normalize_endpoint("HTTPS://Api.Example.com:443/mcp/") == "https://api.example.com/mcp"
    assert normalize_endpoint("https://api.example.com:8443/mcp?x=1") == "https://api.example.com:8443/mcp?x=1"


def test_secret_values_are_redacted_but_structure_is_kept():
    record = {"environmentVariables": [{"name": "TOKEN", "isSecret": True, "value": "abc123", "default": "def"},
                                       {"name": "REGION", "isSecret": False, "default": "us-east-1"}]}
    cleaned = redact_secrets(record)
    assert cleaned["environmentVariables"][0] == {"name": "TOKEN", "isSecret": True, "value": REDACTED, "default": REDACTED}
    assert cleaned["environmentVariables"][1]["default"] == "us-east-1"
    assert record["environmentVariables"][0]["value"] == "abc123"


def test_schema_validation_states():
    assert schema_state({"type": "object", "properties": {"q": {"type": "string"}}})[0] == "valid"
    assert schema_state('{"type": "object"}')[0] == "valid"
    assert schema_state({})[0] == "empty"
    assert schema_state(None)[0] == "absent"
    assert schema_state("{not json")[0] == "unparseable"
    assert schema_state({"type": "string"})[0] == "not_object"
    assert schema_state([{"type": "object"}])[0] == "not_object"
    assert schema_state([])[0] == "empty"
    assert schema_state({"type": "object", "properties": {"q": {"type": 12}}})[0] == "invalid"


def test_range_evaluation_on_synthetic_semver_and_pep440_ranges():
    npm = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.0"}]}]}
    assert range_status("npm", "1.3.9", npm) == "affected"
    assert range_status("npm", "1.4.0", npm) == "not_affected"
    assert range_status("npm", "1.4.0-rc.1", npm) == "affected"
    pypi = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.2"}]}]}
    assert range_status("pypi", "1.2.0", pypi) == "affected"
    assert range_status("pypi", "1.2.1", pypi) == "not_affected"
    assert range_status("pypi", "0.9", pypi) == "not_affected"
    assert range_status("pypi", "not-a-version", pypi) == "undetermined"
    git_only = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
    assert range_status("pypi", "1.0", git_only) == "undetermined"
    assert range_status("pypi", "1.0", {**git_only, "versions": ["0.9"]}) == "not_affected"
    assert range_status("pypi", "1.0.0", {"versions": ["1.0"]}) == "affected"


def test_positive_controls_flag_affected_and_clear_fixed_versions_with_real_osv_records():
    records = seed_osv_records()
    with open(CONTROLS, encoding="utf-8", newline="") as handle:
        controls = list(csv.DictReader(handle))
    assert len(controls) == 10
    for control in controls:
        ecosystem = {"npm": "npm", "PyPI": "pypi"}[control["ecosystem"]]
        body = records[control["primary_advisory"]]
        entries = [a for a in body["affected"] if normalize_package_name(ecosystem, a["package"]["name"]) == normalize_package_name(ecosystem, control["package"])]
        assert entries, control["control_id"]
        assert any(range_status(ecosystem, control["tested_affected_version"], e) == "affected" for e in entries), control["control_id"]
        assert all(range_status(ecosystem, control["tested_fixed_version"], e) != "affected" for e in entries), control["control_id"]
        expected_cves = {c.strip() for c in re.split(r"[;,]", control["expected_cve_ids"]) if c.strip()}
        assert expected_cves <= set(body.get("aliases") or []), control["control_id"]


def test_praisonai_2_3_42_is_inside_the_cve_2026_40159_range():
    records = seed_osv_records()
    matches = [body for body in records.values() if "CVE-2026-40159" in (body.get("aliases") or []) + [body["id"]]]
    assert matches
    assert any(range_status("pypi", "2.3.42", a) == "affected" for body in matches for a in body["affected"]
               if normalize_package_name("pypi", a["package"]["name"]) == "praisonai")
