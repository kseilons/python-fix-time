import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

from ttf_pipeline.config import OSV_PYPI_URL, OSV_RAW_DIR, OSV_ZIP_PATH
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("osv_client")


def download_osv_archive(url: str = OSV_PYPI_URL, dest_path: Path = OSV_ZIP_PATH) -> Path:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading OSV archive from %s to %s", url, dest_path)

    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()

    total_size = int(response.headers.get("content-length", 0))
    chunk_size = 1024 * 1024

    with open(dest_path, "wb") as f, tqdm(
        desc="OSV Archive Download",
        total=total_size,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
    ) as pbar:
        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))

    logger.info("Downloaded OSV archive (%.2f MB)", dest_path.stat().st_size / (1024 * 1024))
    return dest_path


def extract_osv_archive(zip_path: Path = OSV_ZIP_PATH, extract_dir: Path = OSV_RAW_DIR) -> Path:
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s to %s", zip_path, extract_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)

    json_count = len(list(extract_dir.glob("*.json")))
    logger.info("Extracted %d JSON records", json_count)
    return extract_dir
