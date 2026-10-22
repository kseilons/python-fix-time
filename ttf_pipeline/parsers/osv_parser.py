import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from tqdm import tqdm

from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("osv_parser")
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def extract_cwes(data: Dict[str, Any]) -> List[str]:
    cwes = set()

    db_specific = data.get("database_specific")
    if isinstance(db_specific, dict):
        cwe_ids = db_specific.get("cwe_ids")
        if isinstance(cwe_ids, list):
            for cwe in cwe_ids:
                if isinstance(cwe, str) and cwe.strip():
                    cwes.add(cwe.strip().upper())

    for ref in data.get("references", []):
        if isinstance(ref, dict):
            url = ref.get("url", "")
            for m in CWE_PATTERN.findall(url):
                cwes.add(m.upper())

    summary = data.get("summary", "") or ""
    details = data.get("details", "") or ""
    for m in CWE_PATTERN.findall(f"{summary} {details}"):
        cwes.add(m.upper())

    return sorted(list(cwes))


def extract_cvss(data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    severities = data.get("severity", [])
    if isinstance(severities, list):
        for item in severities:
            if isinstance(item, dict) and item.get("type") in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
                vector = item.get("score")
                score = None

                db_specific = data.get("database_specific", {})
                if isinstance(db_specific, dict):
                    sev = db_specific.get("severity")
                    if isinstance(sev, (int, float)):
                        score = float(sev)

                return score, vector

    return None, None


def parse_osv_record(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    vuln_id = data.get("id")
    if not vuln_id:
        return []

    published_at = data.get("published")
    modified_at = data.get("modified")
    cwes = extract_cwes(data)
    cvss_score, cvss_vector = extract_cvss(data)

    affected_list = data.get("affected", [])
    if not isinstance(affected_list, list):
        return []

    parsed_records = []

    for aff in affected_list:
        if not isinstance(aff, dict):
            continue

        pkg_info = aff.get("package", {})
        if not isinstance(pkg_info, dict):
            continue

        pkg_name = pkg_info.get("name")
        pkg_eco = pkg_info.get("ecosystem", "")

        if not pkg_name or (pkg_eco and pkg_eco.lower() != "pypi"):
            continue

        fixed_versions = []
        ranges = aff.get("ranges", [])
        if isinstance(ranges, list):
            for r in ranges:
                if isinstance(r, dict):
                    events = r.get("events", [])
                    if isinstance(events, list):
                        for ev in events:
                            if isinstance(ev, dict) and "fixed" in ev:
                                f_ver = ev["fixed"]
                                if f_ver and f_ver not in fixed_versions:
                                    fixed_versions.append(f_ver)

        parsed_records.append(
            {
                "vuln_id": vuln_id,
                "package_name": pkg_name.strip().lower(),
                "published_at": published_at,
                "modified_at": modified_at,
                "cwes": cwes,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "fixed_versions": fixed_versions,
            }
        )

    return parsed_records


def parse_osv_directory(source_dir: Path) -> pd.DataFrame:
    json_files = list(source_dir.glob("*.json"))
    logger.info("Parsing %d OSV files in %s", len(json_files), source_dir)

    all_records = []
    for fpath in tqdm(json_files, desc="Parsing OSV records"):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = parse_osv_record(data)
            all_records.extend(records)
        except Exception:
            continue

    df = pd.DataFrame(all_records)
    if not df.empty:
        df["published_at"] = pd.to_datetime(df["published_at"], format="mixed", errors="coerce", utc=True)
        df["modified_at"] = pd.to_datetime(df["modified_at"], format="mixed", errors="coerce", utc=True)

    logger.info("Parsed %d records", len(df))
    return df
