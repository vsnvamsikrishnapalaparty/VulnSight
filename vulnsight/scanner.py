import argparse
import json
import logging
import shutil
import time
import platform
from pathlib import Path
import docker
import subprocess

from vulnsight.scan_engine import ScanEngine
from vulnsight.metadata import write_metadata, _summarize_threat_intel
from vulnsight.report_generator.report_pipeline import parse, build_html
from vulnsight.report_generator.report_pipeline import (
    parse, build_html, build_print_html, generate_pdf, encode_pdf_data_uri,
)
from vulnsight.utils.cli_summary import render as render_summary

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Host OS detection (for --root-path mode) - Reads /etc/os-release from the scan target and return identity fields
def detect_host_os(root_path: Path = Path("/")) -> dict:
    osrel = root_path / "etc" / "os-release"
    fields = {"id": "unknown", "pretty": "Linux (unknown)", "version": ""}
    if not osrel.exists():
        return fields
    try:
        for line in osrel.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            if key == "ID":
                fields["id"] = value.lower()
            elif key == "PRETTY_NAME":
                fields["pretty"] = value
            elif key == "VERSION_ID":
                fields["version"] = value
    except Exception:
        pass
    return fields

# Graceful Docker image resolution
def resolve_docker_image(image_ref: str, debug: bool = False):
    client = docker.from_env()

    try:
        img = client.images.get(image_ref)
        if debug:
            logger.info("Using local Docker image: %s", image_ref)
        img._pull_seconds = None
        pulled = False

    except docker.errors.ImageNotFound:
        logger.info("Image not found locally, pulling: %s", image_ref)
        t0 = time.time()

        try:
            img = client.images.pull(image_ref)
        except docker.errors.ImageNotFound:
            print(f"\nERROR: Docker cannot find the image '{image_ref}'.")
            print("       This tag does not exist on Docker Hub.")
            print("       Example valid tags: php:7.4-apache, php:8.2-cli\n")
            print("HINT: Try running:")
            print(f"      docker pull {image_ref}\n")
            raise SystemExit(1)

        except docker.errors.APIError as e:
            print(f"\nERROR: Docker API error while pulling '{image_ref}'.")
            print(f"DETAILS: {str(e).strip()}\n")
            raise SystemExit(1)

        pull_seconds = time.time() - t0
        img._pull_seconds = pull_seconds
        pulled = True

        if debug:
            logger.info("Image pulled in %.4fs", pull_seconds)

    except docker.errors.APIError as e:
        print(f"\nERROR: Docker API error while inspecting '{image_ref}'.")
        print(f"DETAILS: {str(e).strip()}\n")
        raise SystemExit(1)

    digest = img.attrs["RepoDigests"][0].split("@")[1]
    return img, digest, pulled

# Docker-native filesystem extraction
def extract_docker_fs(image_ref: str, extraction_root: Path, debug: bool = False):
    safe_name = image_ref.replace("/", "_").replace(":", "_")
    target = extraction_root / safe_name

    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)

    container_name = f"scan_tmp_{safe_name}"

    subprocess.run(
        ["docker", "create", "--name", container_name, image_ref],
        check=True,
        capture_output=not debug,
        text=True,
    )

    t0 = time.time()
    try:
        extract_cmd = f"docker export {container_name} | tar -C {target} -xf -"
        if debug:
            logger.info("Extracting filesystem with: %s", extract_cmd)

        subprocess.run(
            extract_cmd,
            shell=True,
            check=True,
            executable="/bin/bash",
            text=True,
        )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            capture_output=True,
            text=True,
        )

    extract_seconds = time.time() - t0
    if debug:
        logger.info("Filesystem extracted in %.4fs", extract_seconds)

    return target, extract_seconds

# Tarball extraction
def extract_tar_fs(tar_path: Path, extraction_root: Path, debug: bool = False):
    safe_name = tar_path.stem.replace("/", "_").replace(":", "_")
    target = extraction_root / safe_name

    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    extract_cmd = f"tar -C {target} -xf {tar_path}"
    if debug:
        logger.info("Extracting tarball with: %s", extract_cmd)

    subprocess.run(
        extract_cmd,
        shell=True,
        check=True,
        executable="/bin/bash",
        text=True,
    )
    extract_seconds = time.time() - t0
    if debug:
        logger.info("Tarball extracted in %.4fs", extract_seconds)

    return target, extract_seconds

def force_delete(path: Path):
    """
    Deletes stubborn extracted filesystems (CentOS 6, RHEL 6, etc.)
    using a temporary Docker container running as root.
    """
    if not path.exists():
        return

    logger.info("Detected immutable or protected files in the extracted dilesystem — Need root privileges for cleanup.")
    subprocess.run(["sudo", "chattr", "-i", "-R", str(path)], 
                   stderr=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL,
                   check=False)
    subprocess.run(["sudo", "rm", "-rf", str(path)], check=False)

# Core scan orchestrator
def run_scan(image=None, tar_path=None, root_path=None, host=False, debug=False):
    artifacts_base = Path("artifacts")
    artifacts_base.mkdir(exist_ok=True)

    extraction_root = Path("container_fs")
    extraction_root.mkdir(exist_ok=True)

    mode = None
    fs_path: Path
    artifact_dir: Path
    image_digest = None
    pull_seconds = None
    extract_seconds = None

    # Mode detection
    if host:
        mode = "host"
        fs_path = Path(root_path or "/").resolve()
        safe_name = f"host_{fs_path.as_posix().strip('/').replace('/', '_') or 'root'}"
        artifact_dir = artifacts_base / safe_name
        logger.info("Host mode selected. Root: %s", fs_path)

    elif root_path is not None:
        mode = "host"
        fs_path = Path(root_path or "/").resolve()
        if not fs_path.exists():
            raise ValueError(f"Host root does not exist: {fs_path}")

        host_os = detect_host_os(fs_path)
        safe_name = f"host_{host_os['id']}_root"
        artifact_dir = artifacts_base / safe_name

        logger.info("Host mode selected. Root: %s (OS: %s)", fs_path, host_os["pretty"])

    elif image:
        if image.endswith(".tar") and Path(image).is_file():
            mode = "tar"
            tar_p = Path(image).resolve()

            logger.info("Tarball mode selected. Tar: %s", tar_p)

            fs_path, extract_seconds = extract_tar_fs(tar_p, extraction_root, debug=debug)
            safe_name = tar_p.stem.replace("/", "_").replace(":", "_")
            artifact_dir = artifacts_base / safe_name

        else:
            mode = "docker"
            logger.info("Docker mode selected. Resolving image: %s", image)

            img, image_digest, pulled = resolve_docker_image(image, debug=debug)
            pull_seconds = getattr(img, "_pull_seconds", None)

            digest_short = image_digest.split(":")[1][-6:]
            safe_name = image.replace("/", "_").replace(":", "_")
            artifact_dir = artifacts_base / f"{safe_name}_{digest_short}"

            logger.info("Using image digest: %s", image_digest)

            fs_path, extract_seconds = extract_docker_fs(image, extraction_root, debug=debug)

    else:
        mode = "host"
        fs_path = Path("/").resolve()
        safe_name = "host_root"
        artifact_dir = artifacts_base / safe_name
        logger.info("Host mode selected by default. Root: %s", fs_path)

    try:
        # Run ScanEngine
        engine = ScanEngine(mode)

        total_start = time.time()
        scan_result = engine.scan_filesystem(
            fs_path=fs_path,
            artifacts_dir=artifact_dir,
            debug=debug,
        )
        total_end = time.time()
        total_seconds = round(total_end - total_start, 4)

        # Write threat_intel.json
        ti_filename = "debug_threat_intel.json" if debug else "threat_intel.json"
        ti_path = artifact_dir / ti_filename
        ti_path.write_text(json.dumps(scan_result["threat_intel"], indent=2))
        logger.info("Threat intel written to: %s", ti_path)

        # Build metadata object
        if mode == "docker":
            image_val = image
            digest_val = image_digest
        elif mode == "tar":
            image_val = image
            digest_val = None
        else:
            image_val = host_os["pretty"]
            digest_val = f"host:{platform.release()}/{platform.machine()}"

        timings_for_metadata = {
            "pull": pull_seconds,
            "extract": extract_seconds,
            "sbom": scan_result["timings"].get("sbom_seconds"),
            "grype": scan_result["timings"].get("grype_seconds"),
            "threat_intel": scan_result["timings"].get("threat_intel_seconds"),
            "total": total_seconds,
        }

        result = {
            "mode": mode,
            "image": image_val,
            "digest": digest_val,
            "sbom": scan_result["sbom"],
            "vulnerability_count": scan_result["vulnerability_count"],
            "threat_intel": scan_result["threat_intel"],
            "risk": scan_result.get("risk"),
            "context": scan_result["context"],
            "paths": {
                "sbom": str(scan_result["sbom_path"]),
                "grype": str(scan_result["grype_path"]),
                "threat_intel": str(ti_path),
            },
            "timings": timings_for_metadata,
        }

        metadata_path = write_metadata(artifact_dir, result)
        logger.info("Metadata written to: %s", metadata_path)

        scan_result["metadata"] = result

        # Build HTML report
        data = parse(
            grype_path=str(scan_result["grype_path"]),
            sbom_path=str(scan_result["sbom_path"]),
            threat_path=str(ti_path),
            meta_path=str(metadata_path),
        )

        pdf_data_uri = None
        pdf_path = artifact_dir / "report.pdf"
        try:
            print_html = build_print_html(data)
            if generate_pdf(print_html, str(pdf_path)) is not None:
                pdf_size_kb = pdf_path.stat().st_size / 1024
                logger.info("PDF report written to: %s (%.1f KB)", pdf_path, pdf_size_kb)
                pdf_data_uri = encode_pdf_data_uri(str(pdf_path))
            else:
                logger.warning(
                    "weasyprint not installed - skipping PDF generation. "
                    "Install with: pip install weasyprint"
                )
        except Exception as exc:
            logger.warning("PDF generation failed: %s", exc)

        html = build_html(data, pdf_data_uri=pdf_data_uri)
        output_path = artifact_dir / "report.html"
        output_path.write_text(html, encoding="utf-8")
        logger.info("HTML report written to: %s", output_path)

    finally:
        # Cleanup extracted filesystem
        if mode in ("docker", "tar") and fs_path and fs_path.exists():
            shutil.rmtree(fs_path, ignore_errors=True)
            if fs_path.exists():
                force_delete(fs_path)

    # Timing summary
    logger.info("\n=== Timing Summary ===")
    for phase, secs in scan_result["timings"].items():
        logger.info("%s: %.4fs", phase, secs)
    logger.info("Total Scan Time: %.4fs", total_seconds)

    # Old-style console summary
    ti_summary = _summarize_threat_intel(scan_result["threat_intel"])

    risk = scan_result.get("risk") or {}
    overall_score = risk.get("overall_score")
    risk_level = risk.get("risk_level")

    container_ctx = scan_result["context"]["container"]
    cloud_ctx = scan_result["context"]["cloud"]

    render_summary(
        metadata_path=metadata_path,
        scan_result=scan_result,
        total_seconds=total_seconds,
        artifact_dir=artifact_dir,
    )

    return metadata_path

# CLI entrypoint
def main():
    parser = argparse.ArgumentParser(description="Unified container/host scanner")
    parser.add_argument(
        "-i",
        "--image",
        "--input",
        dest="input",
        required=False,
        help="Docker image (local/remote) or tarball",
    )
    parser.add_argument(
        "--host",
        action="store_true",
        help="Scan the host filesystem (default root is / unless --root-path is provided)",
    )
    parser.add_argument(
        "--root-path",
        nargs="?",
        const="",
        help="Host filesystem root path (if omitted or empty, defaults to /)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()
    debug = args.debug

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    run_scan(
        image=args.input,
        tar_path=args.input if args.input and args.input.endswith(".tar") else None,
        host=args.host,
        root_path=args.root_path,
        debug=debug,
    )


if __name__ == "__main__":
    main()
