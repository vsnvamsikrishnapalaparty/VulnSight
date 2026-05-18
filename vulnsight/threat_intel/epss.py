import requests
from vulnsight.threat_intel.threat_sources import EPSS_API_BASE
from .cache import (
    load_cache, save_cache,
    EPSS_CACHE, TTL_EPSS_SECONDS
)

# Load EPSS cache
_epss_cached = load_cache(EPSS_CACHE, ttl_seconds=TTL_EPSS_SECONDS)
EPSS_LOCAL = _epss_cached if isinstance(_epss_cached, dict) else {}


def fetch_epss_batch(cve_list):
    missing = [cve for cve in cve_list if cve not in EPSS_LOCAL]
    if not missing:
        return

    params = [("cve", cve) for cve in missing]

    try:
        resp = requests.get(EPSS_API_BASE, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        epss_data = data.get("data", {})

        if isinstance(epss_data, list):
            for item in epss_data:
                cve = item.get("cve")
                if cve:
                    EPSS_LOCAL[cve] = float(item.get("epss", 0.0))

        elif isinstance(epss_data, dict):
            for cve, info in epss_data.items():
                EPSS_LOCAL[cve] = float(info.get("epss", 0.0))

        save_cache(EPSS_CACHE, EPSS_LOCAL)

    except Exception:
        for cve in missing:
            EPSS_LOCAL[cve] = 0.0
        save_cache(EPSS_CACHE, EPSS_LOCAL)
