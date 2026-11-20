import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.spark_analytics import parse_cvss_score, map_cwe_category, version_key, match_fix_udf


def test_parse_cvss_score_valid():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_score(vector)
    assert score == 9.8


def test_parse_cvss_score_invalid():
    assert parse_cvss_score(None) is None
    assert parse_cvss_score("INVALID_VECTOR") is None


def test_map_cwe_category():
    assert map_cwe_category(["CWE-79"]) == "XSS (Межсайтовый скриптинг)"
    assert map_cwe_category(["CWE-89"]) == "SQL-инъекции"
    assert map_cwe_category(["CWE-9999"]) == "Прочие CWE"
    assert map_cwe_category([]) == "Другое / Не указано"


def test_version_key():
    assert version_key("1.2.10") > version_key("1.2.2")
    assert version_key("2.0.0") > version_key("1.9.9")


def test_match_fix_udf_prefers_stable_over_prerelease():
    fixed_versions = ["1.2.0rc1", "1.2.0"]
    releases = {
        "1.2.0rc1": "2024-01-01T10:00:00Z",
        "1.2.0": "2024-01-05T10:00:00Z",
        "1.1.0": "2023-12-01T10:00:00Z",
    }
    matched_ver, matched_dt, total_rel = match_fix_udf(fixed_versions, releases)
    assert matched_ver == "1.2.0"
    assert matched_dt == "2024-01-05T10:00:00Z"
    assert total_rel == 3
