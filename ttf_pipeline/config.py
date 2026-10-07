from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"

OSV_PYPI_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
OSV_RAW_DIR = DATA_RAW_DIR / "osv"
OSV_ZIP_PATH = DATA_RAW_DIR / "osv_pypi_all.zip"
OSV_PARQUET_PATH = DATA_RAW_DIR / "osv_pypi_parsed.parquet"

PYPI_API_BASE_URL = "https://pypi.org/pypi/{package}/json"
PYPI_RELEASES_CACHE_DIR = DATA_RAW_DIR / "pypi_releases"
PYPI_USER_AGENT = "Time-to-Fix-Research/1.0 (University Big Data Project; safonov.ai@edu.spbstu.ru)"
DEFAULT_REQUEST_TIMEOUT = 15
DEFAULT_REQUEST_DELAY = 0.05
DEFAULT_MAX_RETRIES = 3

TTF_DATASET_PARQUET_PATH = DATA_PROCESSED_DIR / "ttf_dataset.parquet"
