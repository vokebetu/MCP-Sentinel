import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def client(seed_database_url):
    from fastapi.testclient import TestClient
    mp = pytest.MonkeyPatch()
    mp.setenv("DATABASE_URL", seed_database_url)
    sys.path.insert(0, str(ROOT / "backend"))
    for name in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[name]
    main = importlib.import_module("app.main")
    with TestClient(main.app) as test_client:
        yield test_client
    mp.undo()


def server_id(client, name):
    items = client.get("/api/servers", params={"q": name, "status": "all"}).json()["items"]
    return next(item["server_id"] for item in items if item["registry_name"] == name)


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["servers"] > 0 and "001_initial" in body["schema_versions"]


def test_search_pagination_and_validation(client):
    page = client.get("/api/servers", params={"page_size": 5}).json()
    assert len(page["items"]) == 5 and page["total"] > 5
    assert client.get("/api/servers", params={"page_size": 101}).status_code == 422
    assert client.get("/api/servers", params={"status": "bogus"}).status_code == 422
    hit = client.get("/api/servers", params={"q": "praisonai"}).json()
    assert [i["registry_name"] for i in hit["items"]] == ["io.github.MervinPraison/praisonai"]


def test_filters(client):
    pypi = client.get("/api/servers", params={"ecosystem": "pypi", "page_size": 100}).json()["items"]
    assert pypi and all("pypi" in i["ecosystems"] for i in pypi)
    remote = client.get("/api/servers", params={"deployment": "remote_only", "page_size": 100}).json()["items"]
    assert remote and all(i["package_count"] == 0 and i["remote_count"] > 0 for i in remote)
    norepo = client.get("/api/servers", params={"has_repository": "false", "page_size": 100}).json()["items"]
    assert all(not i["has_github_repository"] for i in norepo)
    deleted = client.get("/api/servers", params={"status": "deleted"}).json()["items"]
    assert deleted and all(i["registry_status"] == "deleted" for i in deleted)


def test_concern_sort_puts_unknown_after_assessed(client):
    items = client.get("/api/servers", params={"sort": "concerns", "page_size": 100, "status": "all"}).json()["items"]
    assert items[0]["registry_name"] == "io.github.MervinPraison/praisonai"
    counts = [i["distinct_advisories"] for i in items]
    first_unknown = next((n for n, c in enumerate(counts) if c is None), len(counts))
    assert all(c is not None for c in counts[:first_unknown]) and all(c is None for c in counts[first_unknown:])


def test_security_endpoint_separates_direct_and_dependency(client):
    body = client.get(f"/api/servers/{server_id(client, 'io.github.MervinPraison/praisonai')}/security").json()
    assert body["summary"]["direct_advisories"] == 81 and body["summary"]["dependency_advisories"] >= 1
    labels = {f["finding_category"]: f["evidence_label"] for f in body["findings"]}
    assert "Modeled dependency exposure" in labels["resolved_dependency"] and "not proof of installation" in labels["resolved_dependency"]
    assert all(f["cves"] for f in body["findings"] if any(i.startswith("CVE-") for i in f["identifiers"]))


def test_coverage_keeps_unknown_apart_from_zero(client):
    remote = server_id(client, "ai.agentplaybooks/agentplaybooks")
    summary = client.get(f"/api/servers/{remote}/security").json()["summary"]
    assert summary["vulnerability_assessment_state"] == "no_package_vulnerability_path" and summary["distinct_advisories"] is None
    coverage = {c["check_type"]: c for c in client.get(f"/api/servers/{remote}/coverage").json()["check_types"]}
    assert coverage["direct_package_advisories"]["outcomes"] == {"not_applicable": 1}
    deleted = client.get("/api/servers", params={"status": "deleted", "assessment": "not_assessed", "page_size": 1}).json()["items"][0]
    assert client.get(f"/api/servers/{deleted['server_id']}/coverage").json()["not_assessed_check_types"]


def test_compare_warns_about_unequal_coverage(client):
    a = server_id(client, "io.github.MervinPraison/praisonai")
    b = server_id(client, "ai.agentplaybooks/agentplaybooks")
    body = client.get("/api/compare", params={"server_ids": f"{a},{b}"}).json()
    assert len(body["servers"]) == 2
    assert any("not necessarily more secure" in note for note in body["notes"])
    assert not any("unknown rather than zero" in note for note in body["notes"])
    incomplete = client.get("/api/servers", params={"assessment": "checks_could_not_complete", "status": "all", "page_size": 1}).json()["items"]
    if incomplete:
        named = client.get("/api/compare", params={"server_ids": f"{a},{incomplete[0]['server_id']}"}).json()["notes"]
        assert any(note.startswith(incomplete[0]["registry_name"]) and "unknown rather than zero" in note for note in named)
    assert client.get("/api/compare", params={"server_ids": f"{a},{a}"}).status_code == 422
    assert client.get("/api/compare", params={"server_ids": "1;DROP TABLE servers"}).status_code == 422


def test_detail_stats_and_errors(client):
    sid = server_id(client, "io.github.neo4j-contrib/mcp-neo4j-cypher")
    detail = client.get(f"/api/servers/{sid}").json()
    assert detail["packages"][0]["identifier"] == "mcp-neo4j-cypher" and detail["repositories"][0]["servers_sharing"] >= 2
    assert client.get("/api/servers/999999999").status_code == 404
    stats = client.get("/api/stats").json()
    assert stats["totals"]["all"] == stats["totals"]["non_deleted"] + stats["totals"].get("deleted", 0)
    assert stats["snapshot_collected_at"].startswith("2026-10-23")


def test_keyword_is_parameterized(client):
    before = client.get("/health").json()["servers"]
    response = client.get("/api/servers", params={"q": "x'; DROP TABLE servers; --"})
    assert response.status_code == 200
    assert client.get("/health").json()["servers"] == before


def test_ai_configuration_and_request_limits(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert client.get("/api/ai/status").json()["configured"] is False
    assert client.post("/api/ai/chat", json={"question": ""}).status_code == 422
    assert client.post("/api/ai/chat", json={"question": "   "}).status_code == 422
    assert client.post("/api/ai/chat", json={"question": "hello", "top_k": 11}).status_code == 422
    assert client.post("/api/ai/chat", json={"question": "hello", "strategy": "bogus"}).status_code == 422
    assert client.post("/api/ai/chat", json={"question": "hello", "use_retrieval": False}).status_code == 503
    ai = importlib.import_module("app.ai")
    assert ai.fetch_one("SHOW transaction_read_only")["transaction_read_only"] == "on"


def test_ai_rejects_fabricated_citations_and_handles_timeouts(client, monkeypatch):
    import json
    import httpx
    from fastapi import HTTPException
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    source = {"citation_id": "server:1:0", "title": "test", "content": "not_assessed"}
    monkeypatch.setattr(ai, "retrieve", lambda *args: [source])

    def result(citation):
        return {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({
            "answer": "The count is unknown.", "status": "grounded", "citation_ids": [citation], "limitations": []})}]}]}

    monkeypatch.setattr(ai, "post", lambda *args: result("invented-source"))
    assert client.post("/api/ai/chat", json={"question": "Is it safe?"}).status_code == 502
    monkeypatch.setattr(ai, "post", lambda *args: result("server:1:0"))
    response = client.post("/api/ai/chat", json={"question": "Is it safe?"})
    assert response.status_code == 200 and response.json()["citation_ids"] == ["server:1:0"]
    monkeypatch.undo()
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")

    class Offline:
        def post(self, *args, **kwargs):
            raise httpx.ReadTimeout("simulated timeout")

    monkeypatch.setattr(ai, "provider", lambda: Offline())
    with pytest.raises(HTTPException) as caught:
        ai.post("responses", {})
    assert caught.value.status_code == 504


def test_ai_incremental_index_and_retrieval_use_only_current_versions(client, monkeypatch):
    import json
    import psycopg
    ai = importlib.import_module("app.ai")
    vector = [1.0] + [0.0] * 511
    monkeypatch.setattr(ai, "embed", lambda texts: ([vector] * len(texts), len(texts)))
    monkeypatch.setattr(ai, "query_embedding", lambda text: tuple(vector))
    ai.query_embedding.cache_clear = lambda: None
    first = ai.index_corpus(workers=2)
    second = ai.index_corpus(workers=1)
    assert first["embedded"] > 0 and first["chunks"] > 131
    assert second["embedded"] == 0 and second["embedding_tokens"] == 0
    sources = ai.retrieve("praisonai", 5)
    assert sources and len(sources) <= 5
    named = ai.retrieve("Is ai.agentplaybooks/agentplaybooks safe?", 5)
    assert named[0]["title"].startswith("ai.agentplaybooks/agentplaybooks:")
    exact = ai.retrieve("What evidence connects CVE-2026-40159 to praisonai?", 5)
    assert any("CVE-2026-40159" in source["content"] for source in exact)
    with psycopg.connect(ai.database_url()) as conn:
        sid = conn.execute("SELECT server_id FROM servers WHERE registry_status = 'deleted' LIMIT 1").fetchone()[0]
        version = conn.execute("SELECT latest_version_id FROM servers WHERE server_id=%s", (sid,)).fetchone()[0]
        conn.execute("""INSERT INTO ai_chunks (chunk_key,server_id,server_version_id,kind,title,content,content_hash,
                     embedding_model,embedding,seen_run) VALUES ('deleted-test',%s,%s,'server','praisonai deleted test',
                     'praisonai deleted test','test',%s,%s::halfvec,'00000000-0000-0000-0000-000000000000')""",
                     (sid, version, ai.EMBEDDING_MODEL, json.dumps(vector)))
    assert all(s["citation_id"] != "deleted-test" for s in ai.retrieve("praisonai deleted test", 10))
    third = ai.index_corpus()
    assert third["removed"] == 1 and third["embedded"] == 0


def test_review_checklist_reports_evidence_status(client):
    keys = ["publisher_identity", "source_repository", "pinned_versions", "known_vulnerabilities", "sbom", "provenance", "tool_permissions",
            "prompt_injection_hints", "tool_fingerprint", "secrets_and_logins", "static_analysis"]
    review = client.get(f"/api/servers/{server_id(client, 'io.github.MervinPraison/praisonai')}/review").json()
    items = {i["item"]: i for i in review["items"]}
    assert list(items) == keys
    assert items["known_vulnerabilities"]["status"] == "present" and items["known_vulnerabilities"]["attention"]
    assert items["sbom"]["status"] == "present" and review["sbom_available"]
    assert items["static_analysis"]["status"] == "not_assessed"
    remote = client.get(f"/api/servers/{server_id(client, 'ai.agentplaybooks/agentplaybooks')}/review").json()
    states = {i["item"]: i["status"] for i in remote["items"]}
    assert states["pinned_versions"] == states["known_vulnerabilities"] == states["sbom"] == "not_applicable"
    assert client.get("/api/servers/999999999/review").status_code == 404


def test_sbom_is_cyclonedx_and_only_for_resolved_servers(client):
    bom = client.get(f"/api/servers/{server_id(client, 'io.github.MervinPraison/praisonai')}/sbom").json()
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["components"] and all(c["purl"].startswith("pkg:pypi/") for c in bom["components"])
    assert len({c["bom-ref"] for c in bom["components"]}) == len(bom["components"])
    assert client.get(f"/api/servers/{server_id(client, 'ai.agentplaybooks/agentplaybooks')}/sbom").status_code == 404


def test_tool_hint_filter_matches_review(client):
    flagged = client.get("/api/servers", params={"tool_hints": "true", "status": "all", "page_size": 100}).json()["items"]
    for entry in flagged:
        assert client.get(f"/api/servers/{entry['server_id']}/review").json()["tool_flags"]
    clean = client.get("/api/servers", params={"tool_hints": "false", "has_tools": "true", "page_size": 20}).json()["items"]
    for entry in clean:
        assert not client.get(f"/api/servers/{entry['server_id']}/review").json()["tool_flags"]


def test_ai_inventory_questions_get_sql_statistics(client, monkeypatch):
    import json
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(ai, "retrieve", lambda *args: [])
    seen = {}

    def answer(path, payload):
        seen["payload"] = payload
        return {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({
            "answer": "Counted from statistics.", "status": "grounded", "citation_ids": ["stats:coverage"], "limitations": []})}]}]}

    monkeypatch.setattr(ai, "post", answer)
    body = client.post("/api/ai/chat", json={"question": "How many servers have recorded findings?"}).json()
    assert [s["citation_id"] for s in body["sources"]] == ["stats:totals", "stats:coverage", "stats:ranking", "stats:advisories"]
    assert body["citation_ids"] == ["stats:coverage"] and body["sources"][0]["similarity"] is None
    evidence = json.loads(seen["payload"]["input"][0]["content"])["evidence"]
    totals = client.get("/api/stats").json()["totals"]
    assert f"{totals['all']:,}" in evidence[0]["content"]
    plain = client.post("/api/ai/chat", json={"question": "Is praisonai safe?"})
    assert plain.status_code == 200 and plain.json()["sources"] == []


def all_items(client, **params):
    items, page = [], 1
    while True:
        body = client.get("/api/servers", params={**params, "page": page, "page_size": 100}).json()
        items += body["items"]
        if page * 100 >= body["total"]:
            return items
        page += 1


def test_list_rows_match_the_database_views(client, seed_database_url):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(seed_database_url, row_factory=dict_row) as conn:
        views = {r["server_id"]: r for r in conn.execute(
            """SELECT ss.server_id, ss.vulnerability_assessment_state, ss.distinct_advisories, ss.direct_advisories, ss.dependency_advisories,
                      ss.highest_advisory_severity, p.deployment_type, p.ecosystems, p.package_count, p.remote_count
               FROM server_security_summary ss JOIN server_profiles p USING (server_id)""")}
    items = all_items(client, status="all")
    assert len(items) == len(views)
    for item in items:
        view = views[item["server_id"]]
        for field in ("vulnerability_assessment_state", "distinct_advisories", "direct_advisories", "dependency_advisories",
                      "highest_advisory_severity", "deployment_type", "ecosystems", "package_count", "remote_count"):
            assert item[field] == view[field], (item["registry_name"], field)
    for state in ("findings_recorded", "no_package_vulnerability_path", "not_assessed"):
        filtered = client.get("/api/servers", params={"assessment": state, "status": "all", "page_size": 1}).json()["total"]
        assert filtered == sum(1 for v in views.values() if v["vulnerability_assessment_state"] == state)


def test_tool_metadata_is_never_a_default_zero(client, seed_database_url):
    import psycopg
    with psycopg.connect(seed_database_url) as conn:
        listed = {r[0] for r in conn.execute("SELECT DISTINCT s.server_id FROM tool_observations t JOIN servers s ON s.latest_version_id = t.server_version_id")}
        counted = {r[0] for r in conn.execute("""SELECT DISTINCT s.server_id FROM endpoint_observations e JOIN servers s ON s.latest_version_id = e.server_version_id
                                                 WHERE e.observed_tool_count > 0""")}
    items = all_items(client, status="all")
    for item in items:
        if item["server_id"] in listed:
            assert item["tool_metadata_state"] == "listed" and item["tool_count"] > 0 and item["tool_count_source"] == "tool catalogs"
        elif item["server_id"] in counted:
            assert item["tool_metadata_state"] == "count_observed" and item["tool_count"] > 0
        elif item["tool_metadata_state"] == "not_observed":
            assert item["tool_count"] is None and item["observed_tool_count"] is None and item["valid_input_schema_count"] is None
        else:
            assert item["tool_metadata_state"] == "observed_none" and item["tool_count"] == 0
    assert any(i["tool_metadata_state"] == "not_observed" for i in items) and any(i["tool_metadata_state"] == "listed" for i in items)
    detail = client.get(f"/api/servers/{next(i['server_id'] for i in items if i['tool_metadata_state'] == 'not_observed')}").json()
    assert detail["tool_count"] is None and any("does not mean the server has no tools" in m for m in detail["missing_information"])


def test_repository_url_comes_from_declared_repositories(client, seed_database_url):
    import psycopg
    with psycopg.connect(seed_database_url) as conn:
        declared = {}
        for sid, url in conn.execute("""SELECT s.server_id, r.canonical_url FROM servers s JOIN server_repositories sr ON sr.server_version_id = s.latest_version_id
                                        JOIN repositories r ON r.repository_id = sr.repository_id"""):
            declared.setdefault(sid, set()).add(url)
    for item in all_items(client, status="all"):
        if item["server_id"] in declared:
            assert item["repository_url"] in declared[item["server_id"]]
        else:
            assert item["repository_url"] is None


def test_export_matches_paginated_results(client):
    import json
    params = {"q": "mcp", "status": "non_deleted", "sort": "concerns", "assessment": "findings_recorded"}
    pages = all_items(client, **params)
    response = client.get("/api/servers/export", params=params)
    assert response.status_code == 200 and response.headers["x-total-count"] == str(len(pages))
    exported = [json.loads(line) for line in response.text.splitlines() if line]
    assert [i["server_id"] for i in exported] == [i["server_id"] for i in pages]
    assert exported == pages
    tools = client.get("/api/servers/export", params={"tool_info": ["listed", "count_observed"], "status": "all"}).text.splitlines()
    assert tools and all(json.loads(line)["tool_metadata_state"] in ("listed", "count_observed") for line in tools)


def test_rapid_pagination_is_stable(client):
    totals = set()
    for page in (1, 2, 3, 2, 1, 2, 3, 4, 3, 2, 1, 2):
        response = client.get("/api/servers", params={"page": page, "page_size": 25, "sort": "name", "status": "non_deleted"})
        assert response.status_code == 200 and response.headers["x-request-id"]
        totals.add(response.json()["total"])
    assert len(totals) == 1


def test_database_errors_return_distinct_503_reasons(client, monkeypatch):
    import psycopg
    from psycopg_pool import PoolTimeout
    main = importlib.import_module("app.main")
    for error, reason in ((PoolTimeout("no connection"), "database_busy"), (psycopg.errors.QueryCanceled("canceled"), "query_timeout")):
        def boom(*args, **kwargs):
            raise error
        monkeypatch.setattr(main, "fetch_one", boom)
        response = client.get("/api/servers", headers={"X-Request-ID": "trace-123"})
        assert response.status_code == 503 and response.json()["reason"] == reason
        assert response.headers["retry-after"] == "1" and response.headers["x-request-id"] == "trace-123" == response.json()["request_id"]
        monkeypatch.undo()
    assert client.get("/health", headers={"X-Request-ID": "bad id; drop"}).headers["x-request-id"] != "bad id; drop"


def ai_answer(text, citations):
    import json
    return {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({
        "answer": text, "status": "grounded", "citation_ids": citations, "limitations": []})}]}]}


def test_ai_scope_filters_retrieval_and_explains_not_applicable(client, monkeypatch):
    import json
    ai = importlib.import_module("app.ai")
    vector = [1.0] + [0.0] * 511
    monkeypatch.setattr(ai, "embed", lambda texts: ([vector] * len(texts), len(texts)))
    monkeypatch.setattr(ai, "query_embedding", lambda text: tuple(vector))
    ai.query_embedding.cache_clear = lambda: None
    ai.index_corpus(workers=1)
    remote = client.get("/api/servers", params={"deployment": "remote_only", "page_size": 1}).json()["items"][0]
    praisonai = server_id(client, "io.github.MervinPraison/praisonai")
    scoped = ai.retrieve("vulnerabilities", 5, [remote["server_id"], praisonai])
    assert scoped and {s["server_id"] for s in scoped} <= {remote["server_id"], praisonai} and len({s["server_id"] for s in scoped}) == 2
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    seen = {}

    def answer(path, payload):
        seen["evidence"] = json.loads(payload["input"][0]["content"])["evidence"]
        return ai_answer("Package lookup does not apply [facts:server:%d]." % remote["server_id"], [f"facts:server:{remote['server_id']}"])

    monkeypatch.setattr(ai, "post", answer)
    body = client.post("/api/ai/chat", json={"question": "Why is there no package assessment?", "server_ids": [remote["server_id"], 999999999]}).json()
    facts = seen["evidence"][0]
    assert facts["kind"] == "server_facts" and facts["ref"] == 1 and "not applicable: no package is declared" in facts["content"]
    assert "not zero vulnerabilities" in facts["content"] and all(e["server_id"] in (None, remote["server_id"]) for e in seen["evidence"])
    assert body["answer"].endswith("[1].") and body["citation_ids"] == [f"facts:server:{remote['server_id']}"]
    assert body["scope"][0]["server_id"] == remote["server_id"] and body["missing_scope"] == [999999999]
    assert any("not applicable" in note for note in body["coverage_notes"])
    assert body["sources"][0]["cited"] and body["sources"][0]["source_name"] == "Live SQL facts for this server"


def test_ai_routes_aggregate_questions_to_sql(client, monkeypatch):
    import json
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    depth = {}

    def retrieve(text, top_k, scope=()):
        depth[text] = top_k
        return []

    monkeypatch.setattr(ai, "retrieve", retrieve)
    seen = {}

    def answer(path, payload):
        evidence = json.loads(payload["input"][0]["content"])["evidence"]
        seen["ids"] = [e["citation_id"] for e in evidence]
        seen["content"] = {e["citation_id"]: e["content"] for e in evidence}
        return ai_answer("From the statistics [1].", [evidence[0]["citation_id"]])

    monkeypatch.setattr(ai, "post", answer)
    stats = client.get("/api/stats").json()
    client.post("/api/ai/chat", json={"question": "Which servers have recorded critical-severity advisories?"})
    assert "stats:severity" in seen["ids"] and "CRITICAL" in seen["content"]["stats:severity"] and "not an overall server risk score" in seen["content"]["stats:severity"]
    client.post("/api/ai/chat", json={"question": "Which servers have not been assessed?"})
    assert "stats:assessment" in seen["ids"]
    client.post("/api/ai/chat", json={"question": "Which servers have verified tool metadata?"})
    assert "stats:tools" in seen["ids"]
    client.post("/api/ai/chat", json={"question": "How many servers have recorded findings?"})
    assert f"{stats['enrichment']['servers_with_findings']:,}" in seen["content"]["stats:coverage"]
    client.post("/api/ai/chat", json={"question": "Find three servers for PostgreSQL databases"})
    client.post("/api/ai/chat", json={"question": "Is praisonai safe?", "top_k": 5})
    assert depth["Find three servers for PostgreSQL databases"] == 8 and depth["Is praisonai safe?"] == 5 and max(depth.values()) <= 10


def test_ai_citations_are_numbered_and_verified(client, monkeypatch):
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    sources = [{"citation_id": "server:1:0", "kind": "server", "server_id": 1, "title": "x/y: server profile", "content": "x/y: server profile\n{\"a\": 1}"},
               {"citation_id": "finding:1:0", "kind": "finding", "server_id": 1, "title": "x/y: recorded findings", "content": "t\n{}"}]
    monkeypatch.setattr(ai, "retrieve", lambda *args: sources)
    monkeypatch.setattr(ai, "post", lambda *args: ai_answer("One [2]. Fake [7]. Raw [server:1:0]. Note [optional].", ["finding:1:0"]))
    body = client.post("/api/ai/chat", json={"question": "Tell me about x/y"}).json()
    assert body["answer"] == "One [2]. Fake. Raw [1]. Note [optional]."
    assert body["citation_ids"] == ["server:1:0", "finding:1:0"] and [s["ref"] for s in body["sources"]] == [1, 2]



def test_ai_named_server_gets_live_facts_without_scoping(client, monkeypatch):
    import json
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(ai, "retrieve", lambda *args: [])
    remote = client.get("/api/servers", params={"deployment": "remote_only", "page_size": 1}).json()["items"][0]
    seen = {}

    def answer(path, payload):
        seen["evidence"] = json.loads(payload["input"][0]["content"])["evidence"]
        return ai_answer("Not applicable [1].", [seen["evidence"][0]["citation_id"]])

    monkeypatch.setattr(ai, "post", answer)
    body = client.post("/api/ai/chat", json={"question": f"Is {remote['registry_name']} safe?"}).json()
    assert seen["evidence"][0]["kind"] == "server_facts" and seen["evidence"][0]["server_id"] == remote["server_id"]
    assert body["scope"] == [] and body["status"] == "grounded"


def test_ai_uncited_answers_are_not_shown_as_grounded(client, monkeypatch):
    ai = importlib.import_module("app.ai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    source = {"citation_id": "server:1:0", "kind": "server", "server_id": 1, "title": "x/y: server profile", "content": "x/y\n{}"}
    monkeypatch.setattr(ai, "retrieve", lambda *args: [source])
    monkeypatch.setattr(ai, "post", lambda *args: ai_answer("A confident claim without a citation.", []))
    body = client.post("/api/ai/chat", json={"question": "Tell me about x/y"}).json()
    assert body["status"] == "insufficient_evidence" and body["citation_ids"] == []
    assert any("did not cite" in limitation for limitation in body["limitations"])
