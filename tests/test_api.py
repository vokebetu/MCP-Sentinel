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
    assert body["summary"]["direct_advisories"] == 80 and body["summary"]["dependency_advisories"] >= 1
    labels = {f["finding_category"]: f["evidence_label"] for f in body["findings"]}
    assert "Modeled dependency exposure" in labels["resolved_dependency"] and "not proof of installation" in labels["resolved_dependency"]
    assert all(f["cves"] for f in body["findings"] if any(i.startswith("CVE-") for i in f["identifiers"]))


def test_coverage_shows_not_assessed_for_unassessed_server(client):
    items = client.get("/api/servers", params={"assessment": "not_assessed", "deployment": "packages_only", "page_size": 1}).json()["items"]
    body = client.get(f"/api/servers/{items[0]['server_id']}/coverage").json()
    assert "direct_package_advisories" in body["not_assessed_check_types"]
    security = client.get(f"/api/servers/{items[0]['server_id']}/security").json()
    assert security["summary"]["distinct_advisories"] is None


def test_compare_warns_about_unequal_coverage(client):
    a = server_id(client, "io.github.MervinPraison/praisonai")
    b = client.get("/api/servers", params={"assessment": "not_assessed", "page_size": 1}).json()["items"][0]["server_id"]
    body = client.get("/api/compare", params={"server_ids": f"{a},{b}"}).json()
    assert len(body["servers"]) == 2
    assert any("not necessarily more secure" in note for note in body["notes"])
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
