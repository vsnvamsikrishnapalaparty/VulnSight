"""
diagnose_threat_intel.py
═════════════════════════

Quick probe: hit EPSS and NVD with three known CVEs (one new, one mid-age,
one ancient) and print exactly what came back. Tells us whether the
problem is on the wire or in the parser.

Run from project root:
  python3 diagnose_threat_intel.py
"""
import os
import sys
import json
import requests

# Load .env if dotenv is available, so NVD_API_KEY gets picked up.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Three test CVEs spanning eras and severities
TEST_CVES = [
    "CVE-2024-38475",   # recent, high-profile (Apache mod_rewrite)
    "CVE-2020-11023",   # the KEV from your centos:6 run
    "CVE-2007-4559",    # old (CVSS v2 only — likely no v3 score)
]


def section(label):
    print(f"\n{'='*60}\n{label}\n{'='*60}")


# ── EPSS bulk probe ──────────────────────────────────────────────────
def probe_epss():
    section("EPSS bulk probe")
    params = [("cve", cve) for cve in TEST_CVES]
    print(f"URL:    {EPSS_API_BASE}")
    print(f"Params: {params}")
    print()
    try:
        resp = requests.get(EPSS_API_BASE, params=params, timeout=15)
        print(f"Status: {resp.status_code}")
        print(f"Final URL: {resp.url}")
        print(f"Headers: Content-Type={resp.headers.get('Content-Type')}")
        print()
        print("Body (first 800 chars):")
        print(resp.text[:800])

        if resp.status_code == 200:
            try:
                data = resp.json()
                print(f"\nParsed top-level keys: {list(data.keys())}")
                epss_data = data.get("data")
                if epss_data is None:
                    print("[!] No 'data' field in response")
                elif isinstance(epss_data, list):
                    print(f"\n'data' is a list with {len(epss_data)} entries.")
                    for item in epss_data:
                        cve = item.get("cve")
                        epss = item.get("epss")
                        print(f"  {cve}: epss={epss}")
                else:
                    print(f"\n'data' is a {type(epss_data).__name__}: {epss_data}")
            except json.JSONDecodeError as e:
                print(f"\n[!] JSON decode failed: {e}")
    except Exception as e:
        print(f"[!] Request failed: {type(e).__name__}: {e}")


# ── NVD single-CVE probe ─────────────────────────────────────────────
def probe_nvd(cve_id):
    section(f"NVD probe: {cve_id}")
    headers = {
        "User-Agent": "VulnSightDiag/1.0",
        "Accept": "application/json",
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        print(f"Using NVD_API_KEY (length {len(NVD_API_KEY)} chars)")
    else:
        print("No NVD_API_KEY set — using anonymous quota")
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    print(f"URL: {url}")
    print()
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Body (first 400 chars): {resp.text[:400]}")
            return

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        print(f"vulnerabilities count: {len(vulns)}")
        if not vulns:
            print("[!] Empty vulnerabilities array.")
            return

        vuln = vulns[0].get("cve", {})
        metrics = vuln.get("metrics", {})
        print(f"Available metric versions: {list(metrics.keys())}")
        for k in metrics:
            entry = metrics[k][0]
            score = entry.get("cvssData", {}).get("baseScore")
            sev   = entry.get("baseSeverity") or entry.get("cvssData", {}).get("baseSeverity")
            print(f"  {k}: baseScore={score}, severity={sev}")
        weaknesses = vuln.get("weaknesses", [])
        if weaknesses:
            print(f"CWE: {weaknesses[0]['description'][0].get('value')}")
        descs = vuln.get("descriptions", [])
        if descs:
            print(f"Description (first 120 chars): {descs[0].get('value','')[:120]}...")
    except Exception as e:
        print(f"[!] Request failed: {type(e).__name__}: {e}")


# ── Run ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Python: {sys.version.split()[0]}")
    print(f"requests: {requests.__version__}")

    probe_epss()
    for cve in TEST_CVES:
        probe_nvd(cve)
