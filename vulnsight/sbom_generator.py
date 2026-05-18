import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Wrapper Function around Syft to generate Software Bill of Materials for given filesystem path 
class SyftSBOMGenerator:

    def generate_sbom(
        self,
        fs_path: Path,
        output_path: Path,
        debug: bool = False,
    ) -> Dict[str, Any]:
        cmd = [
            "syft",
            f"dir:{fs_path}",
            "-o",
            "syft-json",
        ]

        if debug:
            logger.info("Running Syft command: %s", " ".join(cmd))

        # Writing directly to file to avoid large stdout issues
        with output_path.open("w") as f:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=None if debug else subprocess.DEVNULL,
                text=True,
                check=True,
            )

        # Read and parse
        try:
            sbom = json.loads(output_path.read_text())
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Syft JSON output: %s", e)
            raise

        return sbom
