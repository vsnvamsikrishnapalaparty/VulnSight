from datetime import datetime

from .kev import load_kev_list
from .epss import fetch_epss_batch, EPSS_LOCAL
from .nvd import fetch_nvd_data

def get_threat_intel(cve_id: str, debug: bool = False):
    kev_set = load_kev_list()

    fetch_epss_batch([cve_id])
    nvd = fetch_nvd_data(cve_id, debug=debug)
    epss = EPSS_LOCAL.get(cve_id, 0.0)

    age_days = None
    if nvd.get("published"):
        try:
            published_dt = datetime.fromisoformat(
                nvd["published"].replace("Z", "+00:00")
            )
            age_days = (datetime.utcnow() - published_dt.replace(tzinfo=None)).days
        except Exception:
            age_days = None

    return {
        "cve": cve_id,
        "cvss": nvd.get("cvss"),
        "cwe": nvd.get("cwe"),
        "vendor_severity": nvd.get("vendor_severity"),
        "published": nvd.get("published"),
        "modified": nvd.get("modified"),
        "age_days": age_days,
        "epss": epss,
        "kev": cve_id in kev_set,
        "title": nvd.get("title") or "Title not provided in NVD",
        "description": nvd.get("description"),
    }
