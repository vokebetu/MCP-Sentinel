import math

import pandas as pd
import pytest

from src import etl, sources


@pytest.mark.parametrize("value", ["", "   ", "N/A", "null", "None", " - ", "unknown"])
def test_placeholders_become_null(value):
    assert etl.normalize_null(value) is None


def test_real_values_and_whitespace_are_kept_but_trimmed():
    assert etl.normalize_null("Git") == "Git"
    assert etl.normalize_null(math.nan) is None
    assert etl.normalize_whitespace("  Tools   to\nread  ") == "Tools to read"


def test_description_cleaning_removes_list_markers_and_punctuation_only_values():
    assert etl.clean_description(" - Tools to read Git repositories") == "Tools to read Git repositories"
    assert etl.clean_description(").") is None
    assert etl.clean_description(".") is None
    assert etl.description_quality(" - Tools to read Git repositories", "Tools to read Git repositories") == "ok"
    assert etl.description_quality("Skip to main content Log In", "Skip to main content Log In") == "web_boilerplate"
    assert etl.description_quality(".", None) == "missing"


@pytest.mark.parametrize("url, owner, repo, subpath", [
    ("https://github.com/GongRzhe/Gmail-MCP-Server", "GongRzhe", "Gmail-MCP-Server", None),
    ("https://github.com/aekanun2020/mcp-server/", "aekanun2020", "mcp-server", None),
    ("https://www.github.com/owner/repo.git", "owner", "repo", None),
    ("https://github.com/modelcontextprotocol/servers/tree/main/src/git", "modelcontextprotocol", "servers", "src/git"),
    ("https://github.com/quarkiverse/quarkus-mcp-servers/tree/main/jdbc#supported", "quarkiverse", "quarkus-mcp-servers", "jdbc"),
])
def test_github_url_parsing(url, owner, repo, subpath):
    parsed = etl.parse_github_url(url)
    assert (parsed["github_owner"], parsed["github_repo"], parsed["github_subpath"]) == (owner, repo, subpath)
    assert parsed["repository_id"] == f"github:{owner.lower()}/{repo.lower()}"


def test_github_url_parsing_keeps_monorepo_servers_distinct_but_same_repository():
    git = etl.parse_github_url("https://github.com/modelcontextprotocol/servers/tree/main/src/git")
    time = etl.parse_github_url("https://github.com/modelcontextprotocol/servers/tree/main/src/time")
    assert git["repository_id"] == time["repository_id"]
    assert git["github_subpath"] != time["github_subpath"]
    assert git["github_ref"] == "main"


def test_owner_only_and_non_github_urls_are_not_mapped():
    assert etl.parse_github_url("https://github.com/opentoolsteam")["github_url_type"] == "owner_only"
    assert etl.parse_github_url("https://github.com/opentoolsteam")["repository_id"] is None
    assert etl.parse_github_url("https://www.agentrpc.com/")["github_url_type"] == "not_github"


@pytest.mark.parametrize("value", [
    "git+https://github.com/Owner/Repo.git",
    "git@github.com:owner/repo.git",
    "github:owner/repo",
    "owner/repo",
    {"type": "git", "url": "git+ssh://git@github.com/owner/repo.git"},
])
def test_registry_repository_references_resolve_to_one_repository(value):
    assert etl.registry_repository_id(value) == "github:owner/repo"


def test_url_normalization_and_validation():
    assert etl.normalize_url("HTTPS://WWW.Example.com/path/#section") == "https://example.com/path"
    assert etl.is_valid_url("https://example.com")
    assert not etl.is_valid_url("example.com")
    assert not etl.is_valid_url(None)


def test_nested_json_is_flattened_into_snake_case_columns():
    frame = etl.flatten_records([
        {"content_name": "A", "statistic": {"Bing Rank": 50.0}},
        {"content_name": "B", "statistic": {}},
    ])
    assert list(frame.columns) == ["content_name", "statistic_bing_rank"]
    assert frame.loc[0, "statistic_bing_rank"] == 50.0
    assert pd.isna(frame.loc[1, "statistic_bing_rank"])


def test_json_lines_and_json_array_are_both_parsed():
    lines = '{"a": 1}\n{"a": 2}\nnot json\n{"a": 3}{"a": 4}\n'
    records, malformed = etl.parse_json_records(lines)
    assert [record["a"] for record in records] == [1, 2, 3, 4]
    assert malformed == 1
    assert etl.parse_json_records('[{"a": 1}, {"a": 2}]') == ([{"a": 1}, {"a": 2}], 0)


def test_exact_and_semantic_duplicates_are_detected():
    raw = pd.DataFrame({
        "content_name": ["Git", "Git", "MSSQL", "MSSQL-MCP"],
        "website": ["https://github.com/a/git", "https://github.com/a/git", "https://github.com/x/mssql", "https://github.com/y/mssql-mcp"],
        "source_record_number": [1, 2, 3, 4],
    })
    assert etl.exact_duplicates(raw).tolist() == [False, True, False, False]
    frame = pd.DataFrame({
        "server_name": ["MSSQL", "MSSQL-MCP", "Git"],
        "website_normalized": ["https://github.com/x/mssql", "https://github.com/y/mssql-mcp", "https://github.com/a/git"],
    })
    groups = etl.possible_duplicate_groups(frame)
    assert groups.tolist()[:2] == ["name:mssql", "name:mssql"]
    assert pd.isna(groups.iloc[2])


@pytest.mark.parametrize("value, expected", [("PyPI", "PyPI"), ("python", "PyPI"), (" NPM ", "npm"), ("TypeScript", "npm"), ("cargo", None), (None, None)])
def test_package_ecosystem_normalization(value, expected):
    assert etl.normalize_ecosystem(value) == expected


def test_package_name_normalization():
    assert etl.normalize_package_name("MCP_Server.Git", "PyPI") == "mcp-server-git"
    assert etl.normalize_package_name(" @Scope/Pkg ", "npm") == "@scope/pkg"


def test_exact_versions_are_detected_and_ranges_are_not():
    assert etl.python_dependency("mcp==1.3.0")["pinned_version"] == "1.3.0"
    assert etl.python_dependency("mcp>=1.3.0")["pinned_version"] is None
    assert etl.python_dependency("httpx[http2]==0.27.0 ; python_version >= '3.10'")["dependency_name"] == "httpx"
    assert etl.exact_version("1.2.3") == "1.2.3"
    assert etl.exact_version("^1.2.3") is None
    assert etl.exact_version("workspace:*") is None


def test_manifest_parsing_ignores_private_npm_packages():
    package, dependencies = etl.parse_manifest("package.json", '{"name": "root", "private": true, "dependencies": {"zod": "3.24.1"}}')
    assert package is None
    assert dependencies[0]["pinned_version"] == "3.24.1"
    package, dependencies = etl.parse_manifest(
        "pyproject.toml", '[project]\nname = "mcp-server-git"\nversion = "0.6.2"\ndependencies = ["mcp>=1.0.0"]\n'
    )
    assert package == {"ecosystem": "PyPI", "declared_name": "mcp-server-git", "declared_version": "0.6.2"}
    assert dependencies[0]["dependency_name"] == "mcp"


def test_unknown_package_version_handling():
    assert etl.identify_version("0.6.2", {"0.6.2", "0.6.1"}, "0.6.2") == ("0.6.2", "repository_manifest")
    assert etl.identify_version("9.9.9", {"0.6.2"}, "0.6.2") == ("0.6.2", "registry_latest")
    assert etl.identify_version(None, set(), None) == (None, None)
    assert etl.vulnerability_status("verified", None) == "unknown_version"


def test_package_mapping_requires_registry_link_to_the_same_repository():
    accepted = {"github:owner/repo"}
    assert etl.package_mapping_status("found", {"github:owner/repo"}, accepted) == "verified"
    assert etl.package_mapping_status("found", {"github:someone/else"}, accepted) == "ambiguous"
    assert etl.package_mapping_status("found", set(), accepted) == "ambiguous"
    assert etl.package_mapping_status("not_found", set(), accepted) == "not_published"
    assert etl.package_mapping_status("lookup_failed", set(), accepted) == "lookup_failed"


@pytest.mark.parametrize("mapping, version, osv, expected", [
    ("verified", "1.0.0", "known_vulnerabilities_found", "known_vulnerabilities_found"),
    ("verified", "1.0.0", "no_known_vulnerabilities_found", "no_known_vulnerabilities_found"),
    ("verified", "1.0.0", "api_failed", "api_failed"),
    ("verified", "1.0.0", None, "not_assessed"),
    ("declared", None, None, "unknown_version"),
    ("ambiguous", "1.0.0", None, "ambiguous_mapping"),
    ("not_published", "1.0.0", None, "unknown_package_identity"),
    ("lookup_failed", "1.0.0", None, "api_failed"),
])
def test_vulnerability_lookup_status_handling(mapping, version, osv, expected):
    assert etl.vulnerability_status(mapping, version, osv) == expected


def test_failed_or_skipped_lookups_never_report_zero_vulnerabilities():
    frame = pd.DataFrame({
        "ecosystem": ["PyPI", "PyPI", "PyPI"], "package_name": ["a", "b", "c"],
        "pinned_version": ["1.0", "1.0", None], "mapping_status": ["declared", "declared", "declared"],
    })
    results = {("PyPI", "a", "1.0"): {"osv_status": "no_known_vulnerabilities_found", "osv_queried_at": "t"},
               ("PyPI", "b", "1.0"): {"osv_status": "api_failed", "osv_queried_at": "t"}}
    annotated = etl.annotate_osv(frame, "package_name", "pinned_version", results, {})
    assert annotated["osv_status"].tolist() == ["no_known_vulnerabilities_found", "api_failed", "unknown_version"]
    assert annotated.loc[0, "known_vulnerability_count"] == 0
    assert pd.isna(annotated.loc[1, "known_vulnerability_count"])
    assert pd.isna(annotated.loc[2, "known_vulnerability_count"])


def test_aliases_of_the_same_vulnerability_are_grouped():
    groups = etl.group_vulnerability_aliases({
        "GHSA-aaaa": {"CVE-2024-1"},
        "PYSEC-2024-1": {"CVE-2024-1", "GHSA-aaaa"},
        "GHSA-bbbb": set(),
    })
    assert groups["GHSA-aaaa"] == groups["PYSEC-2024-1"] == "GHSA-aaaa"
    assert groups["GHSA-bbbb"] == "GHSA-bbbb"


def test_strongest_status_prefers_findings_over_missing_information():
    assert etl.strongest_status(["unknown_version", "known_vulnerabilities_found"]) == "known_vulnerabilities_found"
    assert etl.strongest_status(["unknown_version", "no_known_vulnerabilities_found"]) == "no_known_vulnerabilities_found"
    assert etl.strongest_status([]) is None


def test_package_listed_in_mcp_registry_is_verified_without_back_link():
    assert etl.package_mapping_status("found", set(), {"github:owner/repo"}, listed_in_mcp_registry=True) == "verified"
    assert etl.package_mapping_status("not_found", set(), set(), listed_in_mcp_registry=True) == "not_published"


@pytest.mark.parametrize("name, version, ecosystem, valid_name, valid_version", [
    ("mcp-server-git", "2026.10.10", "PyPI", True, True),
    ("bad name", "not-a-version", "PyPI", False, False),
    ("@scope/pkg", "1.2.3", "npm", True, True),
    ("Upper", "1.2", "npm", False, False),
])
def test_package_name_and_version_validation(name, version, ecosystem, valid_name, valid_version):
    assert etl.is_valid_package_name(name, ecosystem) is valid_name
    assert etl.is_valid_version(version, ecosystem) is valid_version


def test_markdown_cleaning_keeps_text_and_removes_markup():
    text = "# Title\n[![badge](https://x/b.svg)](https://x) <img src='a.png'>\nSee the [docs](https://d) and `API_KEY`.\n<!-- hidden -->\n| a | b |\n|---|---|"
    assert etl.clean_markdown(text) == "Title See the docs and API_KEY . a | b"
    assert etl.clean_markdown("![logo](x.png)") is None


def test_page_count_reads_the_last_page_from_the_link_header():
    link = '<https://api.github.com/x?per_page=1&page=2>; rel="next", <https://api.github.com/x?per_page=1&page=57>; rel="last"'
    assert etl.page_count({"status": 200, "body": [{}], "link": link}) == 57
    assert etl.page_count({"status": 200, "body": [], "link": None}) == 0
    assert etl.page_count({"status": 409, "body": None}) is None


@pytest.mark.parametrize("value, expected", [
    ('["Search", "web"]', (["search", "web"], "json_array")),
    ("time,timezone, mcp-server", (["time", "timezone", "mcp-server"], "comma_separated")),
    ("", ([], "empty")),
    (None, ([], "empty")),
])
def test_corpus_tags_in_mixed_formats_are_parsed(value, expected):
    assert sources.parse_tags(value) == expected


def test_corpus_tools_are_parsed_from_json_text():
    assert sources.parse_tool_names('[{"name": "deploy"}, {"name": "status"}]') == (["deploy", "status"], "json_array")
    assert sources.parse_tool_names("[{broken") == (None, "invalid_json")
    assert sources.parse_tool_names(None) == (None, "missing")


def test_schema_extraction_reports_paths_types_and_coverage():
    schema = sources.extract_schema([{"a": 1, "b": {"c": "x"}}, {"a": "1", "d": [{"e": None}]}], "test").set_index("field_path")
    assert schema.loc["a", "value_types"] == "int; str"
    assert schema.loc["b.c", "record_coverage_pct"] == 50.0
    assert schema.loc["d[].e", "value_types"] == "null"


def test_cross_source_matching_uses_repository_and_subdirectory():
    servers = pd.DataFrame({
        "server_id": ["s-git", "s-time", "s-root"],
        "repository_id": ["github:org/servers", "github:org/servers", "github:old/name"],
        "github_subpath": ["src/git", "src/time", None],
    })
    repositories = pd.DataFrame({"repository_id": ["github:org/servers", "github:old/name"], "full_name": ["org/servers", "New/Name"]})
    registry = pd.DataFrame({
        "registry_name": ["io.github.org/git", "io.github.new/name", "com.other/name"],
        "repository_id": ["github:org/servers", "github:new/name", "github:new/name"],
        "repository_subfolder": ["src/git", None, None],
    })
    links = sources.match_sources(servers, repositories, registry, "official_mcp_registry", "registry_name", "repository_subfolder")
    assert links.loc[links["server_id"] == "s-git", "linked_record_id"].tolist() == ["io.github.org/git"]
    assert "s-time" not in links["server_id"].tolist()
    assert set(links.loc[links["server_id"] == "s-root", "match_status"]) == {"multiple_matches"}
