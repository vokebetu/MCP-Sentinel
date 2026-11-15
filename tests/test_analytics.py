import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "analytics" / "pipeline.py"
spec = importlib.util.spec_from_file_location("analytics_pipeline", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PROFILE_COLUMNS = ("server_id long, server_version_id long, registry_name string, registry_status string, package_count long, "
                   "remote_count long, repository_count long, observed_tool_count long, deployment_type string")
SUMMARY_COLUMNS = ("server_id long, server_version_id long, vulnerability_assessment_state string, distinct_advisories long, "
                   "direct_advisories long, dependency_advisories long, highest_advisory_severity string, completed_direct_checks long, "
                   "completed_dependency_checks long, incomplete_vulnerability_checks long, not_applicable_vulnerability_checks long, "
                   "total_checks long")


def test_analysis_queries_load():
    queries = module.load_queries()
    assert list(queries) == ["coverage_by_state", "findings_by_deployment", "top_recorded_findings", "coverage_gap"]
    assert all("gold_server_security" in query and not query.endswith(";") for query in queries.values())


def test_exports_match_expected_columns():
    for name, columns in module.EXPECTED.items():
        select = module.EXPORTS[name].split(" FROM ")[0]
        assert all(column in select for column in columns)


@pytest.fixture(scope="module")
def spark():
    pytest.importorskip("pyspark")
    from pyspark.sql import SparkSession
    session = SparkSession.builder.master("local[2]").appName("mcp-sentinel-analytics-tests").config("spark.ui.enabled", "false").getOrCreate()
    yield session
    session.stop()


def test_not_assessed_is_not_a_safe_label(spark):
    profiles = spark.createDataFrame([
        (1, 101, "server/alpha", "active", 1, 0, 1, 2, "packages_only"),
        (2, 202, "server/beta", "active", 1, 0, 0, 0, "packages_only"),
    ], PROFILE_COLUMNS)
    summary = spark.createDataFrame([
        (1, 101, "findings_recorded", 1, 1, 0, "HIGH", 1, 0, 0, 0, 1),
        (2, 202, "not_assessed", None, None, None, None, 0, 0, 0, 0, 0),
    ], SUMMARY_COLUMNS)
    gold = module.build_gold({"profiles": profiles, "summary": summary})
    rows = {row["server_id"]: row.asDict() for row in gold.collect()}
    assert rows[1]["model_eligible"] is True
    assert rows[2]["model_eligible"] is False
    assert rows[2]["distinct_advisories"] is None
    assert rows[2]["evidence_coverage"] == "not_assessed"
    assert len(rows) == 2


def test_incomplete_vulnerability_checks_are_not_eligible(spark):
    profiles = spark.createDataFrame([(7, 70, "server/gamma", "active", 2, 0, 0, 0, "packages_only")], PROFILE_COLUMNS)
    summary = spark.createDataFrame([(7, 70, "checks_could_not_complete", None, None, None, None, 0, 0, 2, 0, 2)], SUMMARY_COLUMNS)
    row = module.build_gold({"profiles": profiles, "summary": summary}).first()
    assert row["model_eligible"] is False
    assert row["distinct_advisories"] is None


def test_kmeans_trains_on_assessed_rows_only(spark, tmp_path):
    profiles = spark.createDataFrame(
        [(i, 1000 + i, f"server/{i}", "active", 1 + i % 3, i % 2, 1, i % 5, "packages_only") for i in range(40)], PROFILE_COLUMNS)
    summary = spark.createDataFrame(
        [(i, 1000 + i, "findings_recorded" if i % 4 == 0 else "no_known_findings_in_completed_checks", i % 7, 0, i % 7,
          "HIGH", 1, 1 + i % 2, 0, 0, 2) for i in range(30)]
        + [(i, 1000 + i, "not_assessed", None, None, None, None, 0, 0, 0, 0, 0) for i in range(30, 40)], SUMMARY_COLUMNS)
    gold = module.build_gold({"profiles": profiles, "summary": summary})
    metrics = module.train_model(gold, tmp_path)
    assert metrics["eligible_rows"] == 30
    assert metrics["status"] == "trained"
    assert metrics["train_rows"] + metrics["test_rows"] == 30
    assert (tmp_path / "ml" / "kmeans_pipeline").exists()
