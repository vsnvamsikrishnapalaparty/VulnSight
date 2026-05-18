import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, List
from tqdm import tqdm
from vulnsight.sbom_generator import SyftSBOMGenerator
from vulnsight.grype import GrypeScanner
from vulnsight.threat_intel.cve_info import get_threat_intel
from vulnsight.risk_engine.risk_engine import RiskEngine
from vulnsight.container_context import detect_context

logger = logging.getLogger(__name__)

"""
Unified scan engine:
   1. Syft SBOM generation
   2. Grype vulnerability scanning
   3. Threat-intel enrichment (NVD + EPSS + KEV)
   4. Timing instrumentation for each stage
"""
class ScanEngine:

    def __init__(self, mode: str) -> None:
        self.sbom_generator = SyftSBOMGenerator()
        self.grype_scanner = GrypeScanner()
        self.risk_engine = RiskEngine()
        self.mode = mode

    def _debug_suffix(self, debug: bool, name: str) -> str:
        return f"debug_{name}" if debug else name

    def _extract_cves(self, grype_results: Dict[str, Any]) -> List[str]:
        cves = set()
        for match in grype_results.get("matches", []):
            vuln = match.get("vulnerability", {})
            cve = vuln.get("id")
            if cve and cve.startswith("CVE-"):
                cves.add(cve)
        return sorted(cves)

    def _enrich_threat_intel(
        self,
        cve_list: List[str],
        debug: bool = False,
        use_progress: bool = True,
    ) -> Dict[str, Any]:
        intel: Dict[str, Any] = {}

        if use_progress and cve_list:
            iterator = tqdm(cve_list, desc="Enriching CVEs", unit="cve")
        else:
            iterator = cve_list

        for cve in iterator:
            info = get_threat_intel(cve, debug=debug)
            intel[cve] = info

        return intel

    def _normalize_components(self, sbom: Dict[str, Any]) -> None:

        if "components" not in sbom and "artifacts" in sbom:
            sbom["components"] = sbom["artifacts"]

    def scan_filesystem(
        self,
        fs_path: Path,
        artifacts_dir: Path,
        debug: bool = False,
    ) -> Dict[str, Any]:
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        sbom_path = artifacts_dir / f"{self._debug_suffix(debug, 'sbom')}.json"
        grype_path = artifacts_dir / f"{self._debug_suffix(debug, 'grype')}.json"

        timings: Dict[str, float] = {}

        # Syft SBOM
        logger.info("Running Syft on filesystem: %s", fs_path)
        t0 = time.time()
        if debug:
            sbom = self.sbom_generator.generate_sbom(
                fs_path,
                output_path=sbom_path,
                debug=debug,
            )
        else:
            with tqdm(total=1, desc="Generating SBOM", unit="step") as p:
                sbom = self.sbom_generator.generate_sbom(
                    fs_path,
                    output_path=sbom_path,
                    debug=debug,
                )
                p.update(1)
        timings["sbom_seconds"] = round(time.time() - t0, 4)

        # Normalize components for metadata.py compatibility
        self._normalize_components(sbom)

        # Pretty & Deterministic SBOM
        sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True))
        logger.info("Deterministic SBOM written to: %s", sbom_path)

        # Grype
        logger.info("Running Grype on SBOM: %s", sbom_path)
        t1 = time.time()
        if debug:
            grype_results = self.grype_scanner.scan_sbom(
                sbom_path,
                output_path=grype_path,
                debug=debug,
            )
        else:
            with tqdm(total=1, desc="Running Grype", unit="step") as p:
                grype_results = self.grype_scanner.scan_sbom(
                    sbom_path,
                    output_path=grype_path,
                    debug=debug,
                )
                p.update(1)
        timings["grype_seconds"] = round(time.time() - t1, 4)

        # Pretty grype.json
        grype_path.write_text(json.dumps(grype_results, indent=2))
        logger.info("Grype results written to: %s", grype_path)

        vuln_count = len(grype_results.get("matches", []))

        # Threat intel
        cve_list = self._extract_cves(grype_results)
        logger.info("Enriching threat intel for %d CVEs", len(cve_list))
        t2 = time.time()
        threat_intel = self._enrich_threat_intel(
            cve_list,
            debug=debug,
            use_progress=not debug,
        )
        timings["threat_intel_seconds"] = round(time.time() - t2, 4)

        # Detect container + cloud context
        context = detect_context(self.mode, fs_path)

        # Risk scoring
        risk = self.risk_engine.compute(
            grype_results=grype_results,
            threat_intel=threat_intel,
            context=context["container"],
            cloud_context=context["cloud"],
        )

        return {
            "sbom_path": sbom_path,
            "grype_path": grype_path,
            "sbom": sbom,
            "grype": grype_results,
            "vulnerability_count": vuln_count,
            "cve_list": cve_list,
            "threat_intel": threat_intel,
            "risk": risk,
            "context": context,
            "timings": timings,
        }
