import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Scans SBOM and returns vulnerability results directly into a JSON File
class GrypeScanner:

    def scan_sbom(
        self,
        sbom_path: Path,
        output_path: Path,
        debug: bool = False,
    ) -> Dict[str, Any]:
        cmd = [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
        ]

        if debug:
            logger.info("Running Grype command: %s", " ".join(cmd))

        # Writing directly to grype.json file
        with output_path.open("w") as f:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=None if debug else subprocess.DEVNULL,
                text=True,
                check=True,
            )

        try:
            grype_results = json.loads(output_path.read_text())
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Grype JSON output: %s", e)
            raise

        return grype_results
