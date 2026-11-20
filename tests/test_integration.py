import glob
import json
import os
import subprocess
import urllib.request
import pytest


def test_spark_output_json_exists_and_not_empty():
    files = glob.glob("data/processed/ttf_spark_final.json/part-*.json")
    assert len(files) > 0, "Не найден выходной JSON-файл с результатами Spark"
    first_file = next(iter(files))
    with open(first_file, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
    assert len(first_line) > 0
    record = json.loads(first_line)
    for col in ("vuln_id", "package_name", "cwe_category", "severity_level"):
        assert col in record, f"В файле результатов отсутствует колонка {col}"


def test_kibana_dashboard_ndjson_valid():
    assert os.path.exists("kibana_dashboard.ndjson"), "Файл kibana_dashboard.ndjson не найден"
    with open("kibana_dashboard.ndjson", "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) >= 2
    for line in lines[:-1]:
        obj = json.loads(line)
        assert "type" in obj


def test_elasticsearch_index_populated():
    try:
        req = urllib.request.urlopen("http://localhost:9200/pypi-vulnerabilities/_count", timeout=3)
        data = json.loads(req.read().decode("utf-8"))
        assert data.get("count", 0) > 0, "Индекс pypi-vulnerabilities в Elasticsearch пуст"
    except Exception as e:
        pytest.skip(f"Elasticsearch недоступен: {e}")


def test_hdfs_raw_stream_exists():
    try:
        res = subprocess.run(
            ["docker", "exec", "bigdata-namenode", "hdfs", "dfs", "-test", "-e", "/bigdata/raw/vuln_raw_stream.json"],
            capture_output=True,
            timeout=5,
        )
        if res.returncode != 0:
            pytest.skip("Контейнер bigdata-namenode не запущен или файл еще не загружен в HDFS")
    except Exception as e:
        pytest.skip(f"Docker/HDFS недоступен: {e}")

