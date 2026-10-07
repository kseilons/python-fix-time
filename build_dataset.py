import sys
import pandas as pd

from ttf_pipeline.clients.pypi_client import PyPIClient
from ttf_pipeline.config import OSV_PARQUET_PATH, TTF_DATASET_PARQUET_PATH
from ttf_pipeline.pipeline.ttf_builder import build_ttf_dataset
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("build_dataset")


def main() -> None:
    if not OSV_PARQUET_PATH.exists():
        logger.error("OSV data not found at %s", OSV_PARQUET_PATH)
        sys.exit(1)

    logger.info("Reading OSV dataset from %s", OSV_PARQUET_PATH)
    osv_df = pd.read_parquet(OSV_PARQUET_PATH)

    client = PyPIClient()
    pypi_cache = client.load_cached_releases_map()

    build_ttf_dataset(osv_df, pypi_cache, output_path=TTF_DATASET_PARQUET_PATH)


if __name__ == "__main__":
    main()
