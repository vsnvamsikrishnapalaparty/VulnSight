"""
benchmark_threat_intel.py
═════════════════════════

Measures the threat-intel enrichment phase across N cold-cache runs on
the same image, so we can distinguish "NVD is flaky" from "we have a
specific bug."

What this script does:
  1. Reads the CVE list from an existing grype.json (no Syft, no Grype,
     no report generation -- only the threat intel phase).
  2. For each iteration:
     - Clears the NVD + EPSS caches on disk.
     - Reloads the threat_intel modules so NVD_LOCAL / EPSS_LOCAL start
       empty in memory too.
     - Runs the EPSS bulk fetch + NVD parallel fetch.
     - Records timing, success/failure counts, and the set of CVE IDs
       that failed.
  3. Prints a comparison table at the end.

Usage (from project root):
  python3 benchmark_threat_intel.py [--iterations 3] [--grype PATH]

By default it uses artifacts/centos_6_955133/grype.json and 3 iterations.

The comparison table tells us four things:
  - Throughput variance run-to-run
  - Whether the same CVEs fail each time (deterministic bug) or
    different CVEs fail (network/NVD flake)
  - How many CVEs have an EPSS score (FIRST.org coverage)
  - Whether NVD_API_KEY is being used
"""
import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path


def restore_threat_intel_modules():
    """Force-reload the threat_intel package so module-level caches
    (NVD_LOCAL, EPSS_LOCAL, _KEV_SET) re-initialize from disk."""
    for modname in [
        "files.threat_intel.cve_info",
        "files.threat_intel.nvd",
        "files.threat_intel.epss",
        "files.threat_intel.kev",
        "files.threat_intel.cache",
    ]:
        if modname in sys.modules:
            importlib.reload(sys.modules[modname])


def clear_cache_files(cache_dir):
    """Delete cached NVD + EPSS JSON files so the next run starts cold.
    We leave the KEV cache alone -- it's a single ~200 KB fetch and
    not part of what we're measuring."""
    nvd = cache_dir / "nvd_cache.json"
    epss = cache_dir / "epss_cache.json"
    for p in (nvd, epss):
        if p.exists():
            p.unlink()


def load_cve_list_from_grype(grype_path):
    """Same logic as ScanEngine._extract_cves -- pull unique CVE IDs."""
    data = json.loads(Path(grype_path).read_text())
    cves = set()
    for match in data.get("matches", []):
        cve = match.get("vulnerability", {}).get("id")
        if cve and cve.startswith("CVE-"):
            cves.add(cve)
    return sorted(cves)


def run_iteration(cve_list, iter_num):
    """Run one cold-cache enrichment, return a dict of measurements."""
    print(f"\n{'='*60}\nIteration {iter_num}: starting (cold cache, {len(cve_list)} CVEs)\n{'='*60}")

    # Force module reload so the in-memory caches reset
    restore_threat_intel_modules()
    from vulnsight.threat_intel.epss import fetch_epss_batch, EPSS_LOCAL
    from vulnsight.threat_intel.nvd import prefetch_nvd_bulk, NVD_LOCAL

    measurements = {"iteration": iter_num, "cve_count": len(cve_list)}

    # --- EPSS phase ---
    t0 = time.time()
    fetch_epss_batch(cve_list)
    measurements["epss_seconds"] = round(time.time() - t0, 2)
    measurements["epss_with_score"] = sum(1 for c in cve_list if EPSS_LOCAL.get(c, 0.0) > 0)
    measurements["epss_in_cache"]   = sum(1 for c in cve_list if c in EPSS_LOCAL)

    # --- NVD phase ---
    t0 = time.time()
    fetched, failed = prefetch_nvd_bulk(cve_list)
    measurements["nvd_seconds"] = round(time.time() - t0, 2)
    measurements["nvd_fetched"] = fetched
    measurements["nvd_failed"] = failed

    # Capture which specific CVEs failed
    failed_cves = sorted([c for c in cve_list if c not in NVD_LOCAL])
    measurements["nvd_failed_cves"] = failed_cves

    # Compute throughput
    if measurements["nvd_seconds"] > 0:
        measurements["nvd_throughput"] = round(fetched / measurements["nvd_seconds"], 2)
    else:
        measurements["nvd_throughput"] = 0

    print(f"  EPSS  : {measurements['epss_seconds']:>6.2f}s  | {measurements['epss_with_score']}/{len(cve_list)} have score")
    print(f"  NVD   : {measurements['nvd_seconds']:>6.2f}s  | {fetched} fetched, {failed} failed | {measurements['nvd_throughput']} CVEs/s")
    return measurements


def print_comparison(results):
    """Side-by-side table + overlap analysis of failed CVEs."""
    print(f"\n{'='*60}\nCOMPARISON ACROSS {len(results)} ITERATIONS\n{'='*60}\n")

    # Side-by-side timing
    print(f"{'Metric':<25}" + "".join(f"Run {r['iteration']:>3}      " for r in results))
    print("-" * (25 + 12 * len(results)))
    for key, label in [
        ("epss_seconds",   "EPSS seconds"),
        ("epss_with_score","EPSS with score"),
        ("nvd_seconds",    "NVD seconds"),
        ("nvd_fetched",    "NVD fetched"),
        ("nvd_failed",     "NVD failed"),
        ("nvd_throughput", "NVD CVEs/sec"),
    ]:
        row = f"{label:<25}"
        for r in results:
            row += f"{str(r[key]):<12}"
        print(row)

    # Failed-CVE overlap analysis
    print(f"\n{'-'*60}\nFAILED-CVE OVERLAP\n{'-'*60}")
    failed_sets = [set(r["nvd_failed_cves"]) for r in results]
    all_failed = set().union(*failed_sets) if failed_sets else set()
    print(f"\nTotal distinct CVEs that failed in ANY run: {len(all_failed)}")

    if len(results) >= 2:
        # In all runs
        always_failed = set.intersection(*failed_sets) if all(failed_sets) else set()
        print(f"CVEs that failed in EVERY run: {len(always_failed)}")
        if always_failed and len(always_failed) <= 20:
            print("  -> deterministic failures (always these):")
            for c in sorted(always_failed):
                print(f"     {c}")

        # In some but not all
        sometimes_failed = all_failed - always_failed
        print(f"CVEs that failed in SOME runs but not others: {len(sometimes_failed)}")
        if sometimes_failed:
            print("  -> flaky failures (transient network/rate-limit)")

    # Verdict
    print(f"\n{'-'*60}\nVERDICT\n{'-'*60}")
    if not all_failed:
        print("  All runs succeeded fully. Performance is the only remaining concern.")
    else:
        always = set.intersection(*failed_sets) if failed_sets and all(failed_sets) else set()
        flaky = all_failed - always
        if always and not flaky:
            print(f"  DETERMINISTIC: same {len(always)} CVEs fail every run.")
            print("  -> likely a specific bug (these CVE IDs have something in common)")
            print("  -> investigate the failing IDs directly")
        elif flaky and not always:
            print(f"  FLAKY: different CVEs fail each run ({len(flaky)} total across runs).")
            print("  -> NVD rate-limit / network noise, not a bug")
            print("  -> mitigation: retry-with-backoff in a second pass within each scan,")
            print("     OR document that the first scan is partial and tells the user")
            print("     to re-run for full enrichment")
        else:
            print(f"  MIXED: {len(always)} always-fail (bug?) + {len(flaky)} flaky (network)")


# ── Main ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--grype",  default="artifacts/centos_6_955133/grype.json")
    parser.add_argument("--cache-dir", default="cache")
    args = parser.parse_args()

    # Sanity checks
    grype_path = Path(args.grype)
    if not grype_path.exists():
        print(f"ERROR: grype.json not found at {grype_path}", file=sys.stderr)
        print("  Pass --grype <path> or run a scan first.", file=sys.stderr)
        sys.exit(1)

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(exist_ok=True)

    # Report environment
    from dotenv import load_dotenv
    load_dotenv()
    has_key = bool(os.getenv("NVD_API_KEY"))
    print(f"NVD_API_KEY: {'set' if has_key else 'NOT SET (will be slow!)'}")
    print(f"Grype source: {grype_path}")
    print(f"Cache dir:    {cache_dir}")

    cve_list = load_cve_list_from_grype(grype_path)
    print(f"CVE count:    {len(cve_list)}")

    results = []
    for i in range(1, args.iterations + 1):
        clear_cache_files(cache_dir)
        # Sleep between iterations so NVD's rolling rate-limit window
        # has a chance to clear; otherwise iteration 2 starts in a hole.
        if i > 1:
            print(f"\nSleeping 30s to let NVD rate-limit window reset...")
            time.sleep(30)
        results.append(run_iteration(cve_list, i))

    print_comparison(results)


if __name__ == "__main__":
    main()
