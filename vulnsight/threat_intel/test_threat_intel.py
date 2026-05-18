# test_threat_intel.py

from vulnsight.threat_intel.cve_info import get_threat_intel

def test_single_cve(cve_id):
    print(f"\n=== Testing {cve_id} ===")
    info = get_threat_intel(cve_id)

    for key, value in info.items():
        print(f"{key:20} : {value}")

if __name__ == "__main__":
    # Try a few well-known CVEs
    test_single_cve("CVE-2021-44228")   # Log4Shell
    test_single_cve("CVE-2023-44487")   # HTTP/2 Rapid Reset
    test_single_cve("CVE-2022-22965")   # Spring4Shell
