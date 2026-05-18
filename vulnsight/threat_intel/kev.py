import requests
from vulnsight.threat_intel.threat_sources import KEV_FEED_URL
from .cache import (
    load_cache, save_cache,
    KEV_CACHE, TTL_KEV_SECONDS
)

def load_kev_list():
    cached = load_cache(KEV_CACHE, ttl_seconds=TTL_KEV_SECONDS)
    if cached:
        return set(cached)

    try:
        resp = requests.get(KEV_FEED_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        kev_entries = data.get("vulnerabilities", [])
        kev_set = {item.get("cveID") for item in kev_entries if item.get("cveID")}

        save_cache(KEV_CACHE, list(kev_set))
        return kev_set

    except Exception:
        return set()
