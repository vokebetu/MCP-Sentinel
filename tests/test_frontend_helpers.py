import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("sentinel_ui", Path(__file__).resolve().parents[1] / "frontend" / "sentinel_ui.py")
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)


def item(**overrides):
    base = {"server_id": 7, "registry_name": "io.example/demo", "title": "Demo", "version": "1.0.0", "registry_status": "active",
            "ecosystems": ["npm"], "deployment_type": "packages_only", "repository_url": "https://github.com/example/demo",
            "vulnerability_assessment_state": "no_known_findings_in_completed_checks", "distinct_advisories": 0, "direct_advisories": 0,
            "dependency_advisories": 0, "highest_advisory_severity": None, "tool_metadata_state": "listed", "tool_count": 3,
            "valid_input_schema_count": 2, "tool_review_hints": 0, "published_at": "2026-10-01T00:00:00Z"}
    return {**base, **overrides}


def test_missing_states_stay_distinct():
    states = {
        "no_package_vulnerability_path": "— Not applicable", "not_assessed": "○ Not assessed", "checks_could_not_complete": "? Unknown",
    }
    for state, label in states.items():
        row = item(vulnerability_assessment_state=state, distinct_advisories=None, direct_advisories=None, dependency_advisories=None)
        assert ui.advisory_count(row, "distinct_advisories") == label and ui.severity_text(row) == label
    checked = item()
    assert ui.advisory_count(checked, "distinct_advisories") == "0" and ui.security_text(checked) == "✓ Checked — none found"
    assert ui.severity_text(checked) == "✓ None found"
    found = item(vulnerability_assessment_state="findings_recorded", distinct_advisories=5, direct_advisories=1, dependency_advisories=4,
                 highest_advisory_severity="HIGH")
    assert ui.security_text(found) == "Findings: 5 advisories · highest HIGH"
    assert (ui.advisory_count(found, "direct_advisories"), ui.advisory_count(found, "dependency_advisories")) == ("1", "4")


def test_tools_not_observed_is_not_zero():
    assert ui.tools_text(item(tool_metadata_state="not_observed", tool_count=None)) == "Not observed"
    assert ui.tools_text(item(tool_metadata_state="observed_none", tool_count=0)) == "0 observed (handshake)"
    assert ui.tools_text(item(tool_metadata_state="count_observed", tool_count=8)) == "8 (handshake count)"
    assert ui.tools_text(item()) == "3 listed"
    assert ui.schemas_text(item(tool_metadata_state="not_observed")) == "Not observed"


def test_safe_urls_only():
    assert ui.safe_url("https://github.com/a/b") == "https://github.com/a/b"
    assert ui.safe_url("http://example.org/x") == "http://example.org/x"
    for bad in ("javascript:alert(1)", "profile?server_id=1", "ftp://x/y", "", None, "https:///nohost"):
        assert ui.safe_url(bad) is None


def test_csv_matches_rows_and_guards_formulas():
    rows = ui.table_rows([item(title="=HYPERLINK(\"http://evil\")", repository_url=None), item(server_id=8, title="+1", version="-2")],
                         ui.DEFAULT_COLUMNS + ["status"])
    assert list(rows[0]) == ["Server ID"] + [ui.COLUMNS[c] for c in ui.DEFAULT_COLUMNS + ["status"]]
    assert rows[0]["Repo"] == "Not declared"
    text = ui.to_csv(rows).splitlines()
    assert text[0].split(",")[0] == "Server ID"
    assert "'=HYPERLINK" in text[1] and ",'+1," in text[2] and ",'-2," in text[2]


def test_search_params_follow_filters():
    filters = {"q": "", "status": "non_deleted", "ecosystem": "pypi", "deployment": "remote_only", "repository": "declared", "github": True,
               "assessment": "findings_recorded", "tool_info": "known", "tool_hints": "no", "sort": "relevance"}
    params = ui.search_params(filters, 3, 50)
    assert params == {"q": None, "status": "non_deleted", "sort": "name", "page": 3, "page_size": 50, "ecosystem": "pypi",
                      "deployment": "remote_only", "has_repository": True, "github": True, "assessment": "findings_recorded",
                      "tool_info": ("listed", "count_observed"), "tool_hints": False}
    assert ui.page_range(48673, 4, 25) == (76, 100) and ui.page_range(0, 1, 25) == (0, 0) and ui.page_range(30, 2, 25) == (26, 30)


def test_503_message_does_not_claim_the_api_is_down():
    error = ui.http_error(503, {"reason": "database_busy", "detail": "busy"}, "abc123")
    assert error.kind == "http_503" and "API is up" in error.message and "not reachable" not in error.message
    assert "abc123" in ui.error_message(error) and "kept" in ui.error_message(error)
    assert ui.http_error(500, {"detail": "boom"}).kind == "http_error"


def test_resize_page_keeps_first_visible_row():
    assert ui.PAGE_SIZES == (10, 25, 50, 100)
    assert ui.resize_page(3, 25, 10) == 6 and ui.resize_page(6, 10, 25) == 3 and ui.resize_page(1, 100, 10) == 1 and ui.resize_page(4, 10, 100) == 1
    assert ui.resize_page(0, 25, 50) == 1


def test_scope_caption_shows_effective_and_ignored_scope():
    result = {"scope": [{"server_id": 3, "registry_name": "ac.snag/snag"}], "scope_source": "question", "not_found": [],
              "ignored_scope": [{"server_id": 1, "registry_name": "ai.azquo/azquo"}, {"server_id": 2, "registry_name": "ai.leadmcp/leadmcp"}]}
    assert ui.scope_caption(result) == ("Scope used: ac.snag/snag (named in the question) · Selected but not used for this answer: "
                                     "ai.azquo/azquo, ai.leadmcp/leadmcp")
    assert ui.scope_caption({"scope": [], "scope_source": "question", "not_found": ["zz.x/y"], "ignored_scope": []}) == \
        "Scope used: all servers · Not in the registry snapshot: zz.x/y"
    assert ui.scope_caption({}) == "Scope used: all servers"


def test_answer_notes_are_deduplicated_into_one_list():
    result = {"status": "insufficient_evidence", "coverage_notes": ["a/b: not applicable."], "limitations": ["A/B: not applicable", "Other."]}
    assert ui.answer_notes(result) == ["The available evidence is insufficient for a complete answer.", "a/b: not applicable.", "Other."]
    assert ui.answer_notes({"status": "insufficient_evidence", "not_found": ["x.y/z"], "limitations": []}) == []
