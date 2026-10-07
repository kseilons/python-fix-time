from typing import Dict, List, Optional, Tuple
from packaging.version import InvalidVersion, Version


def select_best_fixed_version(
    fixed_versions: List[str], pypi_versions: Dict[str, str]
) -> Tuple[Optional[str], Optional[str]]:
    if not fixed_versions or not pypi_versions:
        return None, None

    candidate_versions = [v for v in fixed_versions if v in pypi_versions]
    if not candidate_versions:
        pypi_lower_map = {k.lower(): k for k in pypi_versions}
        candidate_versions = [
            pypi_lower_map[v.lower()] for v in fixed_versions if v.lower() in pypi_lower_map
        ]

    if not candidate_versions:
        return None, None

    parsed_versions = []
    unparsed_versions = []

    for v_str in candidate_versions:
        try:
            parsed_v = Version(v_str)
            is_prerelease = parsed_v.is_prerelease or parsed_v.is_devrelease
            parsed_versions.append((is_prerelease, parsed_v, v_str))
        except InvalidVersion:
            unparsed_versions.append(v_str)

    if parsed_versions:
        parsed_versions.sort(key=lambda item: (item[0], item[1]))
        selected_version = parsed_versions[0][2]
    else:
        selected_version = sorted(unparsed_versions)[0]

    return selected_version, pypi_versions.get(selected_version)
