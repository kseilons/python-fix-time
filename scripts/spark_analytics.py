import time
import re
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, ArrayType, MapType, IntegerType
from pyspark.ml.feature import VectorAssembler, StringIndexer, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.ml.regression import RandomForestRegressor
from pyspark.ml.evaluation import RegressionEvaluator

HDFS_RAW_PATH = "hdfs://namenode:9000/bigdata/raw/vuln_raw_stream.json"
HDFS_OUT_PATH = "hdfs://namenode:9000/bigdata/processed/ttf_spark_final.parquet"
LOCAL_OUT_JSON = "/app/data/processed/ttf_spark_final.json"

CWE_CATEGORIES = {
    "CWE-79": "XSS (Межсайтовый скриптинг)",
    "CWE-89": "SQL-инъекции",
    "CWE-78": "OS Command Injection (Инъекция команд)",
    "CWE-94": "Code Injection (Инъекция кода)",
    "CWE-22": "Path Traversal (Обход пути)",
    "CWE-20": "Improper Input Validation (Валидация ввода)",
    "CWE-400": "DoS / Отказ в обслуживании",
    "CWE-770": "DoS / Отказ в обслуживании",
    "CWE-119": "Memory Corruption / Переполнение буфера",
    "CWE-120": "Memory Corruption / Переполнение буфера",
    "CWE-787": "Memory Corruption / Переполнение буфера",
    "CWE-200": "Information Exposure (Утечка данных)",
    "CWE-502": "Deserialization (Небезопасная десериализация)",
    "CWE-287": "Authentication / Access Control",
    "CWE-862": "Authentication / Access Control",
    "CWE-863": "Authentication / Access Control",
    "CWE-295": "Cryptography / TLS",
    "CWE-327": "Cryptography / TLS",
    "CWE-918": "SSRF (Подделка запросов)",
}


def map_cwe_category(cwes_list):
    if not cwes_list:
        return "Другое / Не указано"
    for cwe in cwes_list:
        cwe_clean = str(cwe).strip()
        if cwe_clean in CWE_CATEGORIES:
            return CWE_CATEGORIES[cwe_clean]
    return "Прочие CWE"


def version_key(v):
    nums = [int(x) for x in re.findall(r"\d+", str(v))]
    return tuple(nums) if nums else (0,)


def match_fix_udf(fixed_vers, pkg_releases):
    if not fixed_vers or not pkg_releases:
        return (None, None, len(pkg_releases) if pkg_releases else 0)
    valid = []
    for v in fixed_vers:
        if v in pkg_releases and pkg_releases[v]:
            is_pre = bool(re.search(r"(a|b|rc|dev|alpha|beta)\d*$", str(v), re.I))
            valid.append((is_pre, version_key(v), v, pkg_releases[v]))
    if not valid:
        return (None, None, len(pkg_releases))
    valid.sort()
    _, _, best_v, best_dt = next(iter(valid))
    return (best_v, best_dt, len(pkg_releases))


def parse_cvss_score(vector_str):
    if not vector_str or "CVSS:3" not in str(vector_str):
        return None
    try:
        parts = dict(p.split(":") for p in str(vector_str).split("/") if ":" in p)
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV"), 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC"), 0.77)
        ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI"), 0.85)
        s_changed = parts.get("S") == "C"
        pr_map = {"N": 0.85, "L": 0.68 if s_changed else 0.62, "H": 0.50 if s_changed else 0.27}
        pr = pr_map.get(parts.get("PR"), 0.85)
        imp = {"N": 0.0, "L": 0.22, "H": 0.56}
        isc_base = 1 - ((1 - imp.get(parts.get("C"), 0)) * (1 - imp.get(parts.get("I"), 0)) * (1 - imp.get(parts.get("A"), 0)))
        if isc_base <= 0:
            return 0.0
        isc = (7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)) if s_changed else (6.42 * isc_base)
        expl = 8.22 * av * ac * pr * ui
        raw = min(1.08 * (isc + expl), 10.0) if s_changed else min(isc + expl, 10.0)
        return round(raw + 0.049, 1)
    except Exception:
        return None

def main():
    timings = []

    print("\n--- [1/5] Инициализация Apache Spark (Linux / HDFS) ---")
    t0 = time.time()
    spark = (
        SparkSession.builder.appName("PyPI-Vulnerability-Lifecycle-Analytics")
        .config("spark.hadoop.fs.defaultFS", "hdfs://namenode:9000")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    timings.append(("Инициализация Spark Session", time.time() - t0))

    print("\n--- [2/5] Чтение из HDFS и расчет Time-to-Fix в Apache Spark ---")
    t0 = time.time()
    raw_schema = StructType([
        StructField("vuln_id", StringType(), True),
        StructField("package_name", StringType(), True),
        StructField("published_at", StringType(), True),
        StructField("modified_at", StringType(), True),
        StructField("cwes", ArrayType(StringType()), True),
        StructField("cvss_score", StringType(), True),
        StructField("cvss_vector", StringType(), True),
        StructField("fixed_versions", ArrayType(StringType()), True),
        StructField("pypi_releases", MapType(StringType(), StringType()), True),
    ])
    cvss_udf = F.udf(parse_cvss_score, DoubleType())

    raw_df = (
        spark.read.schema(raw_schema)
        .json(HDFS_RAW_PATH)
        .dropDuplicates(["vuln_id", "package_name"])
        .withColumn("cvss_num", cvss_udf(F.col("cvss_vector")))
    )

    match_schema = StructType([
        StructField("matched_fixed_version", StringType(), True),
        StructField("fixed_release_datetime", StringType(), True),
        StructField("package_releases_count", IntegerType(), True),
    ])
    match_udf = F.udf(match_fix_udf, match_schema)
    cwe_udf = F.udf(map_cwe_category, StringType())

    sdf = (
        raw_df.withColumn("match_res", match_udf(F.col("fixed_versions"), F.col("pypi_releases")))
        .withColumn("matched_fixed_version", F.col("match_res.matched_fixed_version"))
        .withColumn("fixed_release_datetime", F.col("match_res.fixed_release_datetime"))
        .withColumn("package_releases_count", F.col("match_res.package_releases_count"))
        .withColumn("has_fixed_versions", F.size(F.col("fixed_versions")) > 0)
        .withColumn("cwe_category", cwe_udf(F.col("cwes")))
        .withColumn("cwes_str", F.when(F.size(F.col("cwes")) > 0, F.concat_ws(",", F.col("cwes"))).otherwise("UNKNOWN"))
        .withColumn("pub_ts", F.to_timestamp("published_at"))
        .withColumn("fix_ts", F.to_timestamp("fixed_release_datetime"))
        .withColumn("ttf_days", (F.unix_timestamp("fix_ts") - F.unix_timestamp("pub_ts")) / 86400.0)
        .withColumn("fixed_before_published", F.col("ttf_days") < 0)
        .withColumn("cvss_score", F.col("cvss_num"))
        .withColumn(
            "severity_level",
            F.when(F.col("cvss_num") >= 9.0, "Critical (9.0-10.0)")
            .when(F.col("cvss_num") >= 7.0, "High (7.0-8.9)")
            .when(F.col("cvss_num") >= 4.0, "Medium (4.0-6.9)")
            .when(F.col("cvss_num") > 0.0, "Low (0.1-3.9)")
            .otherwise("Unknown"),
        )
        .drop("match_res", "pypi_releases", "fixed_versions", "cwes", "cvss_num")
    )
    sdf.cache()
    total_records = sdf.count()
    has_fix_count = sdf.filter(F.col("has_fixed_versions") == True).count()
    valid_ttf_df = sdf.filter(F.col("ttf_days").isNotNull())
    valid_count = valid_ttf_df.count()
    timings.append(("Чтение HDFS и расчет TTF в Spark", time.time() - t0))
    print(f"Всего уникальных пар: {total_records} | С указанным фиксом: {has_fix_count} | С датой патча (TTF): {valid_count}")

    print("\n--- [3/5] Кластеризация уязвимостей (Spark MLlib K-Means) ---")
    t0 = time.time()
    ml_base = valid_ttf_df.filter(
        (F.col("cvss_score").isNotNull()) & (F.col("ttf_days") >= -365) & (F.col("ttf_days") <= 1500)
    )

    cat_indexer = StringIndexer(inputCol="cwe_category", outputCol="cwe_idx", handleInvalid="keep")
    ml_indexed = cat_indexer.fit(ml_base).transform(ml_base)

    assembler = VectorAssembler(
        inputCols=["cvss_score", "cwe_idx", "package_releases_count", "ttf_days"],
        outputCol="raw_features",
        handleInvalid="skip",
    )
    ml_vec = assembler.transform(ml_indexed)
    scaler = StandardScaler(inputCol="raw_features", outputCol="features", withStd=True, withMean=True)
    ml_scaled = scaler.fit(ml_vec).transform(ml_vec)

    kmeans = KMeans(k=4, seed=42, featuresCol="features", predictionCol="cluster_id")
    km_model = kmeans.fit(ml_scaled)
    clustered_df = km_model.transform(ml_scaled)
    timings.append(("Кластеризация K-Means (Spark MLlib)", time.time() - t0))

    print("\n[Результаты кластеризации K-Means (k=4)]:")
    clustered_df.groupBy("cluster_id").agg(
        F.count("*").alias("count"),
        F.round(F.avg("cvss_score"), 2).alias("avg_cvss"),
        F.round(F.avg("package_releases_count"), 1).alias("avg_releases"),
        F.round(F.percentile_approx("ttf_days", 0.5), 2).alias("median_ttf_days"),
    ).orderBy("cluster_id").show(truncate=False)

    print("\n--- [4/5] Сравнительный анализ скорости устранения (Spark SQL) ---")
    t0 = time.time()
    post_disclosure_df = valid_ttf_df.filter(F.col("ttf_days") >= 0)

    print("\n[4.1. Скорость устранения (TTF в днях) по уровню критичности CVSS (после раскрытия)]:")
    sev_stats = post_disclosure_df.groupBy("severity_level").agg(
        F.count("*").alias("vulns_count"),
        F.round(F.percentile_approx("ttf_days", 0.5), 2).alias("median_ttf_days"),
        F.round(F.avg("ttf_days"), 2).alias("mean_ttf_days"),
        F.round(F.percentile_approx("ttf_days", 0.25), 2).alias("q25_days"),
        F.round(F.percentile_approx("ttf_days", 0.75), 2).alias("q75_days"),
    ).orderBy(F.desc("vulns_count"))
    sev_stats.show(truncate=False)

    print("\n[4.2. Скорость устранения (TTF в днях) по категориям CWE (Топ-10)]:")
    cwe_stats = post_disclosure_df.groupBy("cwe_category").agg(
        F.count("*").alias("vulns_count"),
        F.round(F.percentile_approx("ttf_days", 0.5), 2).alias("median_ttf_days"),
        F.round(F.avg("ttf_days"), 2).alias("mean_ttf_days"),
    ).orderBy(F.desc("vulns_count"))
    cwe_stats.show(10, truncate=False)
    timings.append(("Сравнительный анализ (Spark SQL)", time.time() - t0))

    print("\n--- [5/5] Обучение регрессионной модели (Spark MLlib Random Forest) ---")
    t0 = time.time()
    reg_base = post_disclosure_df.filter((F.col("cvss_score").isNotNull()) & (F.col("ttf_days") <= 730))
    reg_indexed = cat_indexer.fit(reg_base).transform(reg_base)
    reg_assembler = VectorAssembler(
        inputCols=["cvss_score", "cwe_idx", "package_releases_count"],
        outputCol="features",
    )
    reg_data = reg_assembler.transform(reg_indexed).select("features", F.col("ttf_days").alias("label"))

    train_data, test_data = reg_data.randomSplit([0.8, 0.2], seed=42)

    rf = RandomForestRegressor(featuresCol="features", labelCol="label", numTrees=50, maxDepth=6, seed=42)
    rf_model = rf.fit(train_data)
    predictions = rf_model.transform(test_data)

    eval_rmse = RegressionEvaluator(labelCol="label", predictionCol="prediction", metricName="rmse").evaluate(predictions)
    eval_mae = RegressionEvaluator(labelCol="label", predictionCol="prediction", metricName="mae").evaluate(predictions)
    eval_r2 = RegressionEvaluator(labelCol="label", predictionCol="prediction", metricName="r2").evaluate(predictions)
    timings.append(("Обучение Random Forest (Spark MLlib)", time.time() - t0))

    print(f"[Метрики Random Forest Regressor]: RMSE = {eval_rmse:.2f} дн. | MAE = {eval_mae:.2f} дн. | R2 = {eval_r2:.4f}")
    print(f"Важность признаков (CVSS, CWE, Кол-во релизов): {rf_model.featureImportances}")

    final_sdf = sdf.drop("pub_ts", "fix_ts").join(
        clustered_df.select("vuln_id", "cluster_id").dropDuplicates(["vuln_id"]),
        on="vuln_id",
        how="left",
    )
    final_sdf.write.mode("overwrite").parquet(HDFS_OUT_PATH)
    final_sdf.coalesce(1).write.mode("overwrite").json(LOCAL_OUT_JSON)

    print("\n" + "=" * 65)
    print(f"{'Этап аналитики (Apache Spark / MLlib)':<45} | {'Время (сек)'}")
    print("-" * 65)
    for step_name, sec in timings:
        print(f"{step_name:<45} | {sec:.2f}")
    print("=" * 65)

    spark.stop()


if __name__ == "__main__":
    main()
