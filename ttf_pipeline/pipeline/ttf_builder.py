from pathlib import Path
from typing import Dict

import pandas as pd
from tqdm import tqdm

from ttf_pipeline.config import TTF_DATASET_PARQUET_PATH
from ttf_pipeline.parsers.version_matcher import select_best_fixed_version
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("ttf_builder")


def build_ttf_dataset(
    osv_df: pd.DataFrame,
    pypi_releases_cache: Dict[str, Dict[str, str]],
    output_path: Path = TTF_DATASET_PARQUET_PATH,
) -> pd.DataFrame:
    matched_versions = []
    fixed_release_dates = []

    for _, row in tqdm(osv_df.iterrows(), total=len(osv_df), desc="Calculating TTF"):
        pkg = str(row["package_name"]).lower()
        fixed_vers = list(row.get("fixed_versions", []))

        pkg_releases = pypi_releases_cache.get(pkg, {})
        if not pkg_releases:
            pkg_alt = pkg.replace("-", "_") if "-" in pkg else pkg.replace("_", "-")
            pkg_releases = pypi_releases_cache.get(pkg_alt, {})

        best_ver, best_date = select_best_fixed_version(fixed_vers, pkg_releases)
        matched_versions.append(best_ver)
        fixed_release_dates.append(best_date)

    df = osv_df.copy()
    df["matched_fixed_version"] = matched_versions
    df["fixed_release_datetime"] = pd.to_datetime(fixed_release_dates, errors="coerce", utc=True)
    df["published_at"] = pd.to_datetime(df["published_at"], errors="coerce", utc=True)
    df["modified_at"] = pd.to_datetime(df["modified_at"], errors="coerce", utc=True)

    time_diff = (df["fixed_release_datetime"] - df["published_at"]).dt.total_seconds()
    df["ttf_days"] = time_diff / 86400.0
    df["fixed_before_published"] = df["ttf_days"] < 0

    columns_order = [
        "vuln_id",
        "package_name",
        "published_at",
        "modified_at",
        "cwes",
        "cvss_score",
        "cvss_vector",
        "fixed_versions",
        "matched_fixed_version",
        "fixed_release_datetime",
        "ttf_days",
        "fixed_before_published",
    ]
    existing_cols = [c for c in columns_order if c in df.columns]
    df = df[existing_cols]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False)

    total = len(df)
    matched = df["matched_fixed_version"].notna().sum()
    logger.info("Saved TTF dataset to %s (%d records, %d matched fixes)", output_path, total, matched)
    return df
