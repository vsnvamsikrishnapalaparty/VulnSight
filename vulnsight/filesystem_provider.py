import logging
import time
from pathlib import Path
import docker
import subprocess

logger = logging.getLogger(__name__)
client = docker.from_env()

# Extracting Docker filesystem using Docker export
def get_docker_filesystem(image_ref: str, base_extract_dir: Path, debug: bool = False):
    t0 = time.time()

    img = client.images.get(image_ref)
    image_id = img.id

    safe_name = image_ref.replace("/", "_").replace(":", "_")
    extract_dir = base_extract_dir / safe_name
    extract_dir.mkdir(parents=True, exist_ok=True)

    if debug:
        logger.debug(f"[DEBUG] Creating container from image: {image_ref}")

    container = client.containers.create(image_ref, command="/bin/true")

    try:
        if debug:
            logger.debug("[DEBUG] Exporting container filesystem using Docker tar stream")

        export_stream = container.export()

        tar_proc = subprocess.Popen(
            ["tar", "-xf", "-", "-C", str(extract_dir)],
            stdin=subprocess.PIPE,
        )

        for chunk in export_stream:
            tar_proc.stdin.write(chunk)

        tar_proc.stdin.close()
        tar_proc.wait()

        if tar_proc.returncode != 0:
            raise RuntimeError("tar extraction failed")

    finally:
        container.remove(force=True)

    t1 = time.time()

    return {
        "fs_path": extract_dir,
        "image_id": image_id,
        "timings": {
            "docker_extract_seconds": round(t1 - t0, 4)
        }
    }


def get_host_filesystem(debug: bool = False):
    if debug:
        logger.debug("[DEBUG] Using host filesystem: /")

    return {
        "fs_path": Path("/"),
        "timings": {}
    }
