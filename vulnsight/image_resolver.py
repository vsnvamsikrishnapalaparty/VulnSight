import logging
import os
from pathlib import Path
import docker

logger = logging.getLogger(__name__)

client = docker.from_env()


def _is_tar_file(path: str) -> bool:
    return path.endswith(".tar") and Path(path).exists()

# Loads tar file into Docker and returns canonical image reference
def _load_tar_image(path: str, debug: bool = False) -> str:

    if debug:
        logger.debug(f"[DEBUG] Loading tarball: {path}")

    with open(path, "rb") as f:
        images = client.images.load(f.read())

    if not images:
        raise ValueError("Tarball did not contain a valid Docker image")

    img = images[0]
    tags = img.tags

    if debug:
        logger.debug(f"[DEBUG] Loaded image ID: {img.id}")
        logger.debug(f"[DEBUG] Tags: {tags}")

    # If tar has no tags, create a synthetic one
    if not tags:
        synthetic = f"loaded:{img.short_id.replace('sha256:', '')}"
        img.tag(synthetic)
        return synthetic

    return tags[0]


def _is_local_image(ref: str) -> bool:
    try:
        client.images.get(ref)
        return True
    except docker.errors.ImageNotFound:
        return False


def _pull_remote_image(ref: str, debug: bool = False) -> str:
    if debug:
        logger.debug(f"[DEBUG] Pulling remote image: {ref}")

    img = client.images.pull(ref)
    return img.tags[0] if img.tags else img.id


def resolve_image(input_ref: str, debug: bool = False) -> str:

    # Tarball
    if _is_tar_file(input_ref):
        logger.info("Detected tarball image: %s", input_ref)
        return _load_tar_image(input_ref, debug=debug)

    # Local image
    if _is_local_image(input_ref):
        logger.info("Detected local Docker image: %s", input_ref)
        return input_ref

    # Remote image
    logger.info("Pulling remote Docker image: %s", input_ref)
    return _pull_remote_image(input_ref, debug=debug)
