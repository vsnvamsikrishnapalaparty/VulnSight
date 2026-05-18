import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from vulnsight.utils.summary import (
    generate_executive_summary,
    generate_remediation_summary,
    generate_static_recommendations,
)

# Helper: Safe Command Execution
def _run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return None

# Helper: Extract image name & tag
def _split_image(image: str):
    if ":" in image:
        name, tag = image.split(":", 1)
    else:
        name, tag = image, "latest"
    return name, tag

# Helper: Threat Intel Summary
def _summarize_threat_intel(threat_intel: dict):
    if not threat_intel:
        return {
            "cve_count": 0,
            "kev_count": 0,
            "high_risk_cve_count": 0,
            "max_cvss": None,
            "avg_cvss": None,
        }

    cvss_scores = []
    kev_count = 0
    high_risk = 0

    for cve, info in threat_intel.items():
        cvss = info.get("cvss")
        if cvss is not None:
            cvss_scores.append(cvss)
            if cvss >= 7.0:
                high_risk += 1

        if info.get("kev"):
            kev_count += 1

    max_cvss = max(cvss_scores) if cvss_scores else None
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None

    return {
        "cve_count": len(threat_intel),
        "kev_count": kev_count,
        "high_risk_cve_count": high_risk,
        "max_cvss": max_cvss,
        "avg_cvss": avg_cvss,
    }

# Helper: Environment Info
def _environment_info():
    return {
        "host_os": platform.system(),
        "python_version": platform.python_version(),
        "docker_version": _run_cmd(["docker", "--version"]),
        "syft_version": _run_cmd(["syft", "--version"]),
        "grype_version": _run_cmd(["grype", "--version"]),
    }

def _extract_kev_details(threat_intel: dict):
    kev_list = []
    today = datetime.utcnow().date()

    for cve_id, info in threat_intel.items():
        if not info.get("kev"):
            continue

        pub_date_str = info.get("published")
        kev_meta = info.get("kev_meta", {})
        kev_date_str = kev_meta.get("dateAdded")

        def parse_date(d):
            try:
                return datetime.strptime(d, "%Y-%m-%d").date()
            except:
                return None

        pub_date = parse_date(pub_date_str)
        kev_date = parse_date(kev_date_str)

        kev_entry = {
            "cve": cve_id,
            "name": info.get("title") or "No name provided in NVD",
            "description": info.get("description") or "No description provided in NVD",
            "cvss": info.get("cvss"),
            "epss": info.get("epss"),
            "cwe": info.get("cwe"),
            "age_days": (today - pub_date).days if pub_date else None,
        }

        kev_list.append(kev_entry)

    return {
        "total_kev_cves": len(kev_list),
        "kev_vulnerabilities": kev_list
    }

# Metadata Builder: Builds the full metadata.json structure from the unified result dict
def build_metadata(result: dict):

    image = result.get("image")
    digest = result.get("digest")
    sbom = result.get("sbom", {})
    vuln_count = result.get("vulnerability_count", 0)
    timings = result.get("timings", {})
    threat_intel = result.get("threat_intel", {})
    paths = result.get("paths", {})
    context = result.get("context", {})

    if result.get("mode") == "host":
        image_name, image_tag = image, ""
    else:
        image_name, image_tag = _split_image(image)
    digest_short = None if digest == "hostfs" else digest[-6:]


    risk = result.get("risk", {})

    metadata = {
        "mode": result.get("mode", "docker"),
        "image": image,
        "digest": digest,
        "digest_short": digest_short,
        "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scanner_version": "1.0.0",

        "image_metadata": {
            "name": image_name,
            "tag": image_tag,
        },

        "sbom_components": len(sbom.get("components", [])),
        "vulnerability_count": vuln_count,

        "threat_intel_summary": _summarize_threat_intel(threat_intel),
        "risk": {
            "overall_score": risk.get("overall_score"),
            "risk_level": risk.get("risk_level"),
            "top_cves": risk.get("per_cve", [])[:10],
            "per_cve":  risk.get("per_cve", []),
        },
        "kev_summary": _extract_kev_details(threat_intel),
        "remediation_plan": [
            {
                "package":         g["package"],
                "current_version": g["current_version"],
                "fix_version":     g["fix_version"],
                "total_fixable": g.get("total_fixable", 0),
                "critical": g.get("critical", 0),
                "high": g.get("high", 0),
                "kev_count": g.get("kev_count", 0),
                "max_cvss": g.get("max_cvss", 0.0),
           }
           for g in risk.get("remediation_plan", [])
        ],
        "remediation_summary": risk.get("remediation_summary", {}),

        "context": context,

        "timing": {
            "pull_seconds": timings.get("pull"),
            "extract_seconds": timings.get("extract"),
            "sbom_seconds": timings.get("sbom"),
            "grype_seconds": timings.get("grype"),
            "threat_intel_seconds": timings.get("threat_intel"),
            "total_seconds": timings.get("total"),
        },

        "environment": _environment_info(),

        "artifacts": {
            "sbom_path": paths.get("sbom"),
            "grype_path": paths.get("grype"),
            "threat_intel_path": paths.get("threat_intel"),
        },
    }

    return metadata

# Metadata Writer
def write_metadata(artifact_dir: Path, result: dict):
    metadata = build_metadata(result)
    metadata["executive_summary"] = generate_executive_summary(metadata)
    metadata["remediation_summary_text"] = generate_remediation_summary(metadata)
    metadata["recommendations"] = generate_static_recommendations(metadata)

    json_text = json.dumps(
        metadata,
        indent=2,
        separators=(",", ": ")
    )

    json_text = (
        json_text.replace("\u2011", "-")
                 .replace("\u2013", "-")
                 .replace("\u2014", "-")
    )

    out_path = artifact_dir / "metadata.json"
    out_path.write_text(json_text)
    return out_path
