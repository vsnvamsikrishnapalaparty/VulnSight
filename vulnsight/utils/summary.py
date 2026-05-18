
#  Helpers

# Detect host filesystem mode
def _is_host_mode(metadata: dict) -> bool:
    return metadata.get("mode") == "host"


def _subject(metadata: dict) -> str:
    return "system" if _is_host_mode(metadata) else "container"


def _dedupe_packages(plan: list) -> list:
    merged: dict = {}
    for p in plan:
        key = (p.get("package"), p.get("fix_version"))
        if key not in merged:
            merged[key] = dict(p)
        else:
            merged[key]["total_fixable"] = (
                merged[key].get("total_fixable", 0) + p.get("total_fixable", 0)
            )
            merged[key]["critical"] = (
                merged[key].get("critical", 0) + p.get("critical", 0)
            )
            merged[key]["high"] = (
                merged[key].get("high", 0) + p.get("high", 0)
            )
            merged[key]["kev_count"] = (
                merged[key].get("kev_count", 0) + p.get("kev_count", 0)
            )
            if p.get("max_cvss", 0) > merged[key].get("max_cvss", 0):
                merged[key]["max_cvss"] = p.get("max_cvss", 0)
    return list(merged.values())

#  Recommendations
def generate_static_recommendations(metadata: dict):
    recs = []

    rem = metadata.get("remediation_summary", {})
    plan = metadata.get("remediation_plan", [])
    ctx  = metadata.get("context", {}).get("container", {})
    is_host = _is_host_mode(metadata)

    total_fixable = rem.get("total_fixable_cves", 0)
    pkgs_to_update = rem.get("packages_to_update", 0)
    kev_pkgs = rem.get("kev_linked_packages", 0)
    critical_high = rem.get("critical_high_cves", 0)

    # Dedupe before picking top 3 so duplicate-named packages collapse.
    deduped = _dedupe_packages(plan)
    sorted_pkgs = sorted(deduped, key=lambda p: p.get("total_fixable", 0), reverse=True)
    top_pkgs = sorted_pkgs[:3]

    # High-impact package upgrades
    if top_pkgs:
        pkg_lines = []
        for p in top_pkgs:
            pkg_lines.append(
                f"{p['package']} -> upgrade to {p['fix_version']} "
                f"({p['total_fixable']} CVEs fixed)"
            )
        recs.append(
            "Prioritise upgrading the highest-impact packages:\n- " +
            "\n- ".join(pkg_lines)
        )

    # KEV-linked packages
    if kev_pkgs > 0:
        recs.append(
            f"{kev_pkgs} packages are linked to actively exploited (KEV) vulnerabilities. "
            "Upgrade these immediately to reduce real-world exploitation risk."
        )

    # Critical/High CVEs
    if critical_high > 0:
        recs.append(
            f"Address the {critical_high} Critical and High-severity CVEs with available fixes. "
            "These represent the highest likelihood of compromise."
        )

    # 4. Generic upgrade guidance — phrasing differs for host vs container
    if pkgs_to_update > 0:
        if is_host:
            recs.append(
                f"{pkgs_to_update} packages have newer versions available that resolve "
                f"{total_fixable} fixable CVEs. "
                "Update these packages using your system package manager "
                "(e.g., apt, dnf, yum, zypper, apk)."
            )
        else:
            recs.append(
                f"{pkgs_to_update} packages have newer versions available that resolve "
                f"{total_fixable} fixable CVEs. "
                "Update these packages using the package manager appropriate for your base image "
                "(e.g., apk, apt, yum, dnf, zypper, microdnf)."
            )

    # System hardening recommendations
    if ctx.get("runs_as_root"):
        if is_host:
            recs.append("Avoid running services as root where possible to limit post-exploitation impact.")
        else:
            recs.append("Run the container as a non-root user to limit post-exploitation impact.")

    if ctx.get("dangerous_tools"):
        tools = ", ".join(ctx["dangerous_tools"])
        if is_host:
            recs.append(f"Audit and restrict access to interactive tools ({tools}) to reduce attack surface.")
        else:
            recs.append(f"Remove unnecessary interactive tools ({tools}) to reduce attack surface.")

    if ctx.get("suid_binaries"):
        suids = ", ".join(ctx["suid_binaries"][:5])
        more = "..." if len(ctx["suid_binaries"]) > 5 else ""
        recs.append(f"Remove or replace SUID binaries ({suids}{more}).")

    if ctx.get("base_image_eol") and not is_host:
        recs.append("Upgrade the base image to a supported version to eliminate inherited vulnerabilities.")

    return recs

#  Executive Summary
def generate_executive_summary(metadata):
    risk = metadata["risk"]
    tis  = metadata["threat_intel_summary"]
    rem  = metadata["remediation_summary"]
    ctx  = metadata["context"].get("container", {})

    score      = risk["overall_score"]
    level      = risk["risk_level"]
    total_cves = metadata["vulnerability_count"]
    unique     = tis["cve_count"]
    kev        = tis["kev_count"]
    fixable    = rem["total_fixable_cves"]
    pkgs       = rem["packages_to_update"]
    top_pkgs_raw = rem.get("top_packages", [])
    runs_root  = ctx.get("runs_as_root", False)
    shells     = ctx.get("dangerous_tools", [])

    subject = _subject(metadata)  # "system" or "container"

    level_phrase = {
        "CRITICAL": f"This {subject} presents a critical security posture",
        "HIGH":     f"This {subject} presents a high security risk",
        "MEDIUM":   f"This {subject} presents a moderate security risk",
        "LOW":      f"This {subject} presents a low security risk",
    }.get(level, f"This {subject} has been scanned")

    s1 = f"{level_phrase} with an overall risk score of {score:.1f}/100."

    # Vulnerability Volume
    s2 = (f"Grype identified {total_cves} total vulnerability matches "
          f"across {unique} unique CVEs.")

    # KEV context
    if kev == 0:
        s3 = "None of the identified CVEs are currently listed in the CISA Known Exploited Vulnerabilities catalogue."
    elif kev == 1:
        cve_id = next((p["cve"] for p in metadata["risk"].get("top_cves", []) if p.get("kev")), "")
        s3 = (f"One CVE ({cve_id}) is actively exploited in the wild "
              f"according to the CISA KEV catalogue and should be prioritised immediately.")
    else:
        kev_ids = [p["cve"] for p in metadata["risk"].get("top_cves", []) if p.get("kev")][:3]
        ids_str = ", ".join(kev_ids)
        s3 = (f"{kev} CVEs are actively exploited in the wild per the CISA KEV catalogue "
              f"({ids_str}{'...' if kev > 3 else ''}) and require immediate attention.")

    # Fixability
    fix_pct = int(fixable / unique * 100) if unique else 0
    s4 = (f"Of the {unique} unique CVEs, {fixable} ({fix_pct}%) have upstream fixes available "
          f"and can be resolved by upgrading {pkgs} packages.")

    # Top packages (deduped)
    deduped_top = _dedupe_packages(top_pkgs_raw)
    deduped_top.sort(key=lambda p: p.get("total_fixable", 0), reverse=True)
    top_pkgs = deduped_top[:3]
    if top_pkgs:
        pkg_parts = [
            f"{p['package']} ({p['total_fixable']} CVEs -> {p['fix_version']})"
            for p in top_pkgs
        ]
        s5 = "The highest-priority packages to upgrade are: " + ", ".join(pkg_parts) + "."
    else:
        s5 = ""

    # Contextual Risk Factors
    factors = []
    if runs_root:
        factors.append("runs services as root" if _is_host_mode(metadata) else "runs as root")
    if shells:
        factors.append(f"exposes interactive shells ({', '.join(shells)})")
    if ctx.get("suid_binaries"):
        factors.append(f"contains {len(ctx['suid_binaries'])} SUID binaries")

    factor_prefix = ("Additional system-level risk factors include: "
                     if _is_host_mode(metadata)
                     else "Additional container-level risk factors include: ")
    if factors:
        s6 = factor_prefix + "; ".join(factors) + "."
    else:
        s6 = "No additional system-level risk factors were identified." if _is_host_mode(metadata) else "No additional container-level risk factors were identified."

    return " ".join(filter(None, [s1, s2, s3, s4, s5, s6]))

#  Remediation Summary
def generate_remediation_summary(metadata):
    rem = metadata["remediation_summary"]
    kev_pkgs = rem["kev_linked_packages"]

    s1 = (f"Upgrading {rem['packages_to_update']} packages will resolve "
          f"{rem['total_fixable_cves']} fixable CVEs.")

    s2 = (
        f"{kev_pkgs} of those packages are linked to actively exploited vulnerabilities "
        f"and should be upgraded first."
        if kev_pkgs > 0 else
        "No packages are linked to actively exploited vulnerabilities."
    )

    ch = rem.get("critical_high_cves", 0)
    s3 = (
        f"Prioritise the {ch} Critical and High severity CVEs with available fixes."
        if ch else
        ""
    )

    return " ".join(filter(None, [s1, s2, s3]))
