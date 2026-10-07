import argparse
import sys
import pandas as pd

from ttf_pipeline.clients.pypi_client import PyPIClient
from ttf_pipeline.config import OSV_PARQUET_PATH
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("fetch_pypi")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch PyPI release dates")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    if not OSV_PARQUET_PATH.exists():
        logger.error("OSV data not found at %s", OSV_PARQUET_PATH)
        sys.exit(1)

    df = pd.read_parquet(OSV_PARQUET_PATH)
    packages = sorted(df["package_name"].dropna().unique().tolist())
    logger.info("Found %d packages", len(packages))

    if args.limit and args.limit > 0:
        packages = packages[: args.limit]
        logger.info("Limited run to %d packages", len(packages))

    client = PyPIClient(delay=args.delay)
    client.fetch_all(packages)


if __name__ == "__main__":
    main()
