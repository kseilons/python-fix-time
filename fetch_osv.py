import sys
from ttf_pipeline.clients.osv_client import download_osv_archive, extract_osv_archive
from ttf_pipeline.config import (
    DATA_RAW_DIR,
    OSV_PARQUET_PATH,
    OSV_RAW_DIR,
    OSV_ZIP_PATH,
)
from ttf_pipeline.parsers.osv_parser import parse_osv_directory
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("fetch_osv")


def main() -> None:
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)

    if not OSV_ZIP_PATH.exists():
        download_osv_archive()
    else:
        logger.info("Found existing OSV zip archive at %s", OSV_ZIP_PATH)

    if not OSV_RAW_DIR.exists() or not any(OSV_RAW_DIR.glob("*.json")):
        extract_osv_archive()
    else:
        logger.info("OSV raw records already extracted in %s", OSV_RAW_DIR)

    df = parse_osv_directory(OSV_RAW_DIR)
    if df.empty:
        logger.error("Parsed dataframe is empty. Aborting.")
        sys.exit(1)

    df.to_parquet(OSV_PARQUET_PATH, index=False)
    logger.info("Saved %d records to %s", len(df), OSV_PARQUET_PATH)


if __name__ == "__main__":
    main()
