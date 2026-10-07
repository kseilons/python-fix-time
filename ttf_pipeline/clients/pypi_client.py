import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from tqdm import tqdm

from ttf_pipeline.config import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_DELAY,
    DEFAULT_REQUEST_TIMEOUT,
    PYPI_API_BASE_URL,
    PYPI_RELEASES_CACHE_DIR,
    PYPI_USER_AGENT,
)
from ttf_pipeline.utils.logging_utils import setup_logger

logger = setup_logger("pypi_client")


class PyPIClient:
    def __init__(
        self,
        cache_dir: Path = PYPI_RELEASES_CACHE_DIR,
        user_agent: str = PYPI_USER_AGENT,
        delay: float = DEFAULT_REQUEST_DELAY,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.delay = delay
        self.timeout = timeout
        self.max_retries = max_retries

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def _get_cache_path(self, package_name: str) -> Path:
        safe_name = package_name.strip().lower().replace("/", "_").replace("\\", "_")
        return self.cache_dir / f"{safe_name}.json"

    def get_package_json(self, package_name: str) -> Optional[Dict[str, Any]]:
        cache_file = self._get_cache_path(package_name)
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        url = PYPI_API_BASE_URL.format(package=package_name)

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 404:
                    payload = {"error": 404, "package": package_name}
                    with open(cache_file, "w", encoding="utf-8") as f:
                        json.dump(payload, f)
                    return payload

                if response.status_code >= 500:
                    time.sleep(1.0 * attempt)
                    continue

                response.raise_for_status()
                data = response.json()

                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)

                if self.delay > 0:
                    time.sleep(self.delay)

                return data

            except requests.exceptions.RequestException:
                time.sleep(1.0 * attempt)

        return None

    def fetch_all(self, package_names: List[str]) -> Tuple[int, int]:
        success_count = 0
        error_count = 0

        for pkg in tqdm(package_names, desc="Fetching PyPI metadata"):
            data = self.get_package_json(pkg)
            if data and "error" not in data:
                success_count += 1
            else:
                error_count += 1

        logger.info("PyPI fetch complete: %d ok, %d errors", success_count, error_count)
        return success_count, error_count

    def load_cached_releases_map(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = {}

        for fpath in self.cache_dir.glob("*.json"):
            pkg_name = fpath.stem.lower()
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict) or "releases" not in data:
                    continue

                ver_map = {}
                for ver, files in data.get("releases", {}).items():
                    if not isinstance(files, list):
                        continue
                    timestamps = []
                    for file_info in files:
                        if isinstance(file_info, dict):
                            ts = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                            if ts:
                                timestamps.append(ts)
                    if timestamps:
                        ver_map[ver] = min(timestamps)

                result[pkg_name] = ver_map
            except Exception:
                continue

        logger.info("Loaded metadata for %d packages from cache", len(result))
        return result
