import requests
from vulnsight.threat_intel.threat_sources import NVD_API_BASE, NVD_API_KEY
from .cache import (
    load_cache, save_cache,
    NVD_CACHE, TTL_NVD_SECONDS
)

# Load NVD cache
_nvd_cached = load_cache(NVD_CACHE, ttl_seconds=TTL_NVD_SECONDS)
NVD_LOCAL = _nvd_cached if isinstance(_nvd_cached, dict) else {}


def _build_nvd_headers():
    headers = {
        "User-Agent": "ImageScanner/1.0",
        "Accept": "application/json",
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_nvd_data(cve_id: str, debug: bool = False):
    if cve_id in NVD_LOCAL:
        return NVD_LOCAL[cve_id]

    url = f"{NVD_API_BASE}?cveId={cve_id}"

    try:
        resp = requests.get(url, headers=_build_nvd_headers(), timeout=10)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            result = {
                "cvss": None,
                "cwe": None,
                "vendor_severity": None,
                "published": None,
                "modified": None,
            }
            NVD_LOCAL[cve_id] = result
            save_cache(NVD_CACHE, NVD_LOCAL)
            return result

        vuln = vulns[0].get("cve", {})
        metrics = vuln.get("metrics", {})

        # Extract CVE Title (Name)
        title = None
        titles = vuln.get("titles", [])
        if titles and isinstance(titles, list):
            title = titles[0].get("title")

        # Extract CVE Description
        description = None
        descriptions = vuln.get("descriptions", [])
        if descriptions and isinstance(descriptions, list):
            description = descriptions[0].get("value")

        # Fallback Title
        if not title and description:
            first_sentence = description.split(".")[0].strip()
            if len(first_sentence) > 120:
                first_sentence = first_sentence[:117] + "..."
            title = first_sentence

        cvss = None
        vendor_severity = None

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss = m.get("cvssData", {}).get("baseScore")
            vendor_severity = m.get("baseSeverity")

        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            cvss = m.get("cvssData", {}).get("baseScore")
            vendor_severity = m.get("baseSeverity")

        weaknesses = vuln.get("weaknesses", [])
        if weaknesses and weaknesses[0].get("description"):
            cwe = weaknesses[0]["description"][0].get("value")
        else:
            cwe = None

        published = vuln.get("published")
        modified = vuln.get("lastModified")

        result = {
            "cvss": cvss,
            "cwe": cwe,
            "vendor_severity": vendor_severity,
            "published": published,
            "modified": modified,
            "title": title,
            "description": description,
        }

        NVD_LOCAL[cve_id] = result
        save_cache(NVD_CACHE, NVD_LOCAL)
        return result

    except Exception:
        result = {
            "cvss": None,
            "cwe": None,
            "vendor_severity": None,
            "published": None,
            "modified": None,
        }
        NVD_LOCAL[cve_id] = result
        save_cache(NVD_CACHE, NVD_LOCAL)
        return result
