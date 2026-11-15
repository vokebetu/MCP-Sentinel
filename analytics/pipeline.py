import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT.parent / "data" / "analytics"
EXPORTS = {
    "server_profiles": "SELECT server_id, server_version_id, registry_name, registry_status, package_count, remote_count, "
                       "repository_count, observed_tool_count, deployment_type FROM server_profiles",
    "server_security_summary": "SELECT server_id, server_version_id, vulnerability_assessment_state, distinct_advisories, "
                               "direct_advisories, dependency_advisories, highest_advisory_severity, completed_direct_checks, "
                               "completed_dependency_checks, incomplete_vulnerability_checks, not_applicable_vulnerability_checks, "
                               "total_checks FROM server_security_summary",
    "assessment_outcomes": "SELECT server_version_id, check_type, outcome, COUNT(*)::bigint AS record_count FROM assessment_checks "
                           "GROUP BY server_version_id, check_type, outcome",
    "finding_categories": "SELECT server_version_id, finding_category, finding_status, COUNT(DISTINCT advisory_id)::bigint AS "
                          "distinct_advisory_count FROM security_findings GROUP BY server_version_id, finding_category, finding_status",
}
EXPECTED = {
    "server_profiles": [
        "server_id", "server_version_id", "registry_name", "registry_status",
        "package_count", "remote_count", "repository_count",
        "observed_tool_count", "deployment_type",
    ],
    "server_security_summary": [
        "server_id", "server_version_id", "vulnerability_assessment_state",
        "distinct_advisories", "direct_advisories", "dependency_advisories",
        "highest_advisory_severity", "completed_direct_checks",
        "completed_dependency_checks", "incomplete_vulnerability_checks",
        "not_applicable_vulnerability_checks", "total_checks",
    ],
    "assessment_outcomes": ["server_version_id", "check_type", "outcome", "record_count"],
    "finding_categories": [
        "server_version_id", "finding_category", "finding_status",
        "distinct_advisory_count",
    ],
}
NUMERIC_PROFILE = ["package_count", "remote_count", "repository_count", "observed_tool_count"]
NUMERIC_SUMMARY = [
    "distinct_advisories", "direct_advisories", "dependency_advisories",
    "completed_direct_checks", "completed_dependency_checks",
    "incomplete_vulnerability_checks", "not_applicable_vulnerability_checks",
    "total_checks",
]
ML_FEATURES = [
    "package_count", "remote_count", "repository_count", "observed_tool_count",
    "completed_direct_checks", "completed_dependency_checks",
    "incomplete_vulnerability_checks", "distinct_advisories",
]


def export_views(folder):
    import psycopg
    from psycopg.conninfo import make_conninfo

    folder.mkdir(parents=True, exist_ok=True)
    conninfo = make_conninfo(host=os.environ.get("POSTGRES_HOST", "localhost"), port=os.environ.get("POSTGRES_PORT", "5432"),
                             dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
                             password=os.environ["POSTGRES_PASSWORD"], options="-c default_transaction_read_only=on")
    counts = {}
    with psycopg.connect(conninfo) as conn, conn.cursor() as cursor:
        for name, query in EXPORTS.items():
            path = folder / f"{name}.csv"
            with open(path, "wb") as handle, cursor.copy(f"COPY ({query}) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)") as copy:
                for block in copy:
                    handle.write(block)
            counts[name] = sum(1 for _ in open(path, encoding="utf-8")) - 1
            print(f"exported {name}: {counts[name]:,} rows", flush=True)
    return counts


def load_queries(path=ROOT / "analysis.sql"):
    queries, name = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("-- name:"):
            name = line.split(":", 1)[1].strip()
            queries[name] = ""
        elif name and line.strip():
            queries[name] += line + "\n"
    return {key: value.strip().rstrip(";") for key, value in queries.items()}


def normalize_frames(raw):
    from pyspark.sql import functions as F

    profiles, summary = raw["server_profiles"], raw["server_security_summary"]
    for name in ("server_id", "server_version_id"):
        profiles = profiles.withColumn(name, F.col(name).cast("long"))
        summary = summary.withColumn(name, F.col(name).cast("long"))
    for name in NUMERIC_PROFILE:
        profiles = profiles.withColumn(name, F.col(name).cast("long"))
    for name in NUMERIC_SUMMARY:
        summary = summary.withColumn(name, F.col(name).cast("long"))
    checks = raw["assessment_outcomes"].withColumn(
        "server_version_id", F.col("server_version_id").cast("long")
    ).withColumn("record_count", F.col("record_count").cast("long"))
    findings = raw["finding_categories"].withColumn(
        "server_version_id", F.col("server_version_id").cast("long")
    ).withColumn(
        "distinct_advisory_count", F.col("distinct_advisory_count").cast("long")
    )
    return {
        "profiles": profiles, "summary": summary,
        "checks": checks, "findings": findings,
    }


def build_gold(silver):
    from pyspark.sql import functions as F

    profiles, summary = silver["profiles"], silver["summary"]
    for label, frame in (("profiles", profiles), ("summary", summary)):
        if frame.groupBy("server_version_id").count().filter("count > 1").limit(1).count():
            raise ValueError("Duplicate server version IDs in " + label)
        if frame.filter("server_id IS NULL OR server_version_id IS NULL").limit(1).count():
            raise ValueError("Missing stable ID in " + label)

    gold = profiles.join(
        summary, on=["server_id", "server_version_id"], how="left"
    ).withColumn(
        "completed_vulnerability_checks",
        F.coalesce(F.col("completed_direct_checks"), F.lit(0)) +
        F.coalesce(F.col("completed_dependency_checks"), F.lit(0))
    )
    return gold.withColumn(
        "model_eligible",
        F.coalesce(
            F.col("vulnerability_assessment_state").isin(
                "findings_recorded", "no_known_findings_in_completed_checks"
            ) & (F.col("completed_vulnerability_checks") > 0),
            F.lit(False),
        ),
    ).withColumn(
        "evidence_coverage",
        F.when(F.col("model_eligible"), "completed_vulnerability_checks")
        .when(F.col("vulnerability_assessment_state").isNull(), "not_assessed")
        .otherwise(F.col("vulnerability_assessment_state")),
    )


def save_sql_outputs(spark, gold, output):
    gold.createOrReplaceTempView("gold_server_security")
    results = {}
    for name, query in load_queries().items():
        df = spark.sql(query)
        df.coalesce(1).write.mode("overwrite").option("header", True).csv(
            str(output / "sql" / name)
        )
        results[name] = [row.asDict(recursive=True) for row in df.limit(20).collect()]
    return results


def train_model(gold, output, seed=42):
    from pyspark.sql import functions as F
    from pyspark.sql.types import DoubleType
    from pyspark.ml import Pipeline
    from pyspark.ml.feature import VectorAssembler, StandardScaler
    from pyspark.ml.clustering import KMeans
    from pyspark.ml.evaluation import ClusteringEvaluator

    eligible = gold.filter(F.col("model_eligible") == True)
    for name in ML_FEATURES:
        eligible = eligible.withColumn(
            name, F.coalesce(F.col(name), F.lit(0)).cast(DoubleType())
        )
    eligible = eligible.cache()

    train, test = eligible.randomSplit([0.8, 0.2], seed=seed)
    train_n, test_n = train.count(), test.count()
    metrics = {
        "algorithm": "Spark ML K-Means (exploratory, unsupervised)",
        "target_label": None, "eligible_rows": eligible.count(),
        "train_rows": train_n, "test_rows": test_n,
        "features": ML_FEATURES, "status": "not_trained",
        "cluster_count": None, "test_silhouette": None,
    }

    if train_n < 5 or test_n < 2:
        metrics["reason"] = "Insufficient assessed train/test data"
        return metrics
    distinct = train.select(*ML_FEATURES).distinct().limit(3).count()
    if distinct < 2:
        metrics["reason"] = "No feature diversity in assessed training records"
        return metrics
    k = min(3, distinct, train_n - 1)
    pipeline = Pipeline(stages=[
        VectorAssembler(inputCols=ML_FEATURES, outputCol="unscaled_features"),
        StandardScaler(
            inputCol="unscaled_features", outputCol="features",
            withStd=True, withMean=True
        ),
        KMeans(k=k, seed=seed, featuresCol="features", predictionCol="cluster_id"),
    ])
    fitted = pipeline.fit(train)
    predicted = fitted.transform(test)
    predicted.select(
        "server_id", "server_version_id", "registry_name", "evidence_coverage",
        *ML_FEATURES, "cluster_id"
    ).coalesce(1).write.mode("overwrite").option("header", True).csv(
        str(output / "ml" / "test_predictions")
    )
    fitted.write().overwrite().save(str(output / "ml" / "kmeans_pipeline"))
    metrics["status"] = "trained"
    metrics["cluster_count"] = k
    metrics["cluster_distribution"] = {
        str(row["cluster_id"]): row["count"]
        for row in predicted.groupBy("cluster_id").count().collect()
    }

    if test_n >= 3 and predicted.select("cluster_id").distinct().count() > 1:
        try:
            metrics["test_silhouette"] = float(
                ClusteringEvaluator(
                    featuresCol="features", predictionCol="cluster_id",
                    metricName="silhouette"
                ).evaluate(predicted)
            )
        except Exception as error:
            metrics["silhouette_note"] = "Unavailable: " + type(error).__name__
    else:
        metrics["silhouette_note"] = "Test set too small or only one cluster"
    return metrics


def execute(args):
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.master(args.master).appName(
        "MCP-Sentinel-analytics"
    ).config("spark.sql.adaptive.enabled", "true").config("spark.ui.enabled", "false").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    source, output = Path(args.input), Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    raw, counts = {}, {}
    try:
        for name, required in EXPECTED.items():
            path = source / (name + ".csv")
            if not path.exists():
                raise FileNotFoundError("Missing " + str(path) + "; run without --skip-export")
            frame = spark.read.option("header", True).option(
                "mode", "FAILFAST"
            ).csv(str(path))
            missing = set(required).difference(frame.columns)
            if missing:
                raise ValueError(name + " missing fields: " + str(sorted(missing)))
            counts[name] = frame.count()
            frame.write.mode("overwrite").parquet(str(output / "bronze" / name))
            raw[name] = frame

        silver = normalize_frames(raw)
        for name, frame in silver.items():
            frame.write.mode("overwrite").parquet(str(output / "silver" / name))

        gold = build_gold(silver).cache()
        gold_count = gold.count()
        if gold_count != counts["server_profiles"]:
            raise ValueError("Gold row count mismatch: invalid version-aware join")
        gold.write.mode("overwrite").parquet(
            str(output / "gold" / "server_security_features")
        )
        sql_results = save_sql_outputs(spark, gold, output)
        model = train_model(gold, output, seed=args.seed)
        results = {
            "bronze_row_counts": counts,
            "silver_row_counts": {k: v.count() for k, v in silver.items()},
            "gold_row_count": gold_count,
            "model_eligible_rows": gold.filter("model_eligible = true").count(),
            "spark_sql_results": sql_results,
            "model": model,
            "limitations": [
                "Clusters are not security risk labels.",
                "Only assessed server versions enter training.",
                "No finding is not proof of safety.",
                "Data are a historical snapshot, not live surveillance.",
            ],
        }
        (output / "metrics.json").write_text(
            json.dumps(results, indent=2, default=str) + "\n"
        )
        print(json.dumps(results, indent=2, default=str))
    finally:
        spark.stop()


def hand_back(folder):
    if hasattr(os, "geteuid") and os.geteuid() == 0 and folder.exists():
        owner = folder.parent.stat()
        for item in [folder, *folder.rglob("*")]:
            os.chown(item, owner.st_uid, owner.st_gid)


def main():
    parser = argparse.ArgumentParser(description="Export database views and run the Spark Bronze/Silver/Gold pipeline, SQL reports and K-Means.")
    parser.add_argument("--input", default=str(DATA / "input"))
    parser.add_argument("--output", default=str(DATA / "output"))
    parser.add_argument("--master", default="local[*]")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-export", action="store_true")
    args = parser.parse_args()
    try:
        if not args.skip_export:
            export_views(Path(args.input))
        execute(args)
    finally:
        hand_back(DATA)


if __name__ == "__main__":
    main()
