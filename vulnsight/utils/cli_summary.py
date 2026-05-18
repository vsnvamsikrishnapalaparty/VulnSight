import json
import shutil
import sys
import textwrap
from pathlib import Path


# ANSI escape codes
_COLOR = sys.stdout.isatty()


def _wrap(code):
    if not _COLOR:
        return lambda s: str(s)
    return lambda s: f"\033[{code}m{s}\033[0m"


bold       = _wrap("1")
dim        = _wrap("2")
red        = _wrap("31")
green      = _wrap("32")
yellow     = _wrap("33")
blue       = _wrap("34")
magenta    = _wrap("35")
cyan       = _wrap("36")
bold_red   = _wrap("1;31")
bold_green = _wrap("1;32")
bold_yellow= _wrap("1;33")
bold_cyan  = _wrap("1;36")


# Layout Helpers
def _term_width():
    try:
        w = shutil.get_terminal_size((96, 24)).columns
    except Exception:
        w = 96
    return max(78, min(110, w))


def _rule(label, width):
    label = f" {label} "
    fill = "─" * max(3, width - 3 - len(label))
    return bold_cyan(f"─── {label.strip()} {fill}")


def _row(label, value, label_width=22, value_style=None):
    label_str = dim(label.ljust(label_width))
    val_str = value_style(str(value)) if value_style else str(value)
    return f"  {label_str}{val_str}"


def _risk_color(level):
    lvl = (level or "").lower()
    if "critical" in lvl: return bold_red
    if "high"     in lvl: return bold_yellow
    if "medium"   in lvl: return yellow
    if "low"      in lvl: return bold_green
    return bold


def _sev_color(sev):
    s = (sev or "").lower()
    if "critical" in s: return red
    if "high"     in s: return red
    if "medium"   in s: return yellow
    if "low"      in s: return green
    return dim


# Section Renderers
def _section_header(meta, scan_result, total_seconds, width):
    img       = meta.get("image_metadata", {})
    image_str = f"{img.get('name','?')}:{img.get('tag','')}".rstrip(":")
    digest    = meta.get("digest") or "n/a"
    digest_disp = f"{digest[:18]}\u2026{digest[-6:]}" if len(digest) > 30 else digest
    scan_ts   = meta.get("scan_timestamp", "")
    if len(scan_ts) > 18:
        scan_ts = f"{scan_ts[:10]} at {scan_ts[11:19]} UTC"

    lines = [
        "",
        _rule("SCAN SUMMARY", width),
        "",
        _row("Image",    bold(image_str)),
        _row("Digest",   dim(digest_disp)),
        _row("Scanned",  scan_ts),
        _row("Duration", f"{total_seconds:.2f}s"),
    ]
    return lines


def _section_risk(meta, width):
    """Risk posture: score, CVE counts, severity breakdown."""
    risk = meta.get("risk", {}) or {}
    ti_summary = meta.get("threat_intel_summary", {}) or {}
    rs = meta.get("remediation_summary", {}) or {}

    score = risk.get("overall_score", 0)
    level = risk.get("risk_level", "UNKNOWN")
    score_color = _risk_color(level)
    score_str   = f"{score_color(f'{score:.2f}')}   {score_color(bold(level))}"

    unique_cves = ti_summary.get("cve_count", 0)
    max_cvss    = ti_summary.get("max_cvss", 0)
    avg_cvss    = round(ti_summary.get("avg_cvss", 0), 1) if ti_summary.get("avg_cvss") else 0
    kev_count   = ti_summary.get("kev_count", 0)
    fixable     = rs.get("total_fixable_cves", 0)

    # Severity breakdown - count CVEs by severity from threat_intel_summary
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    for entry in risk.get("per_cve", []):
        sev = (entry.get("severity") or "Unknown").title()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Unknown"] += 1

    # Compose severity breakdown line with each tier colored
    sev_parts = []
    for sev, count in sev_counts.items():
        if count > 0:
            label = _sev_color(sev)(sev)
            sev_parts.append(f"{label} {bold(count)}")
    sev_line = "    ".join(sev_parts) or dim("None")

    lines = [
        "",
        _rule("RISK POSTURE", width),
        "",
        _row("VulnSight Risk Score", score_str),
        _row("Unique CVEs",          bold(unique_cves)),
        _row("Max CVSS",             red(max_cvss) if max_cvss >= 7 else str(max_cvss)),
        _row("Avg CVSS",             avg_cvss),
        _row("CISA KEV listed",
             f"{bold_red(kev_count) if kev_count else green(0)} "
             f"{dim('actively exploited' if kev_count else 'none in catalog')}"),
        _row("Fixable",              f"{bold(fixable)} / {unique_cves}"),
        "",
        f"  {dim('Severity breakdown')}",
        f"    {sev_line}",
    ]
    return lines

# Wrapped executive summary paragraph
def _section_exec_summary(meta, width):
    summary = meta.get("executive_summary", "").strip()
    if not summary:
        return []
    wrapped = textwrap.fill(
        summary,
        width=width - 4,
        initial_indent="  ",
        subsequent_indent="  ",
    )
    return [
        "",
        _rule("EXECUTIVE SUMMARY", width),
        "",
        wrapped,
    ]

# Table of top N CVEs by VulnSight Risk Score
def _section_top_cves(meta, width, limit=5):
    per_cve = meta.get("risk", {}).get("per_cve", [])
    if not per_cve:
        return []

    top = sorted(per_cve, key=lambda c: c.get("contribution", 0), reverse=True)[:limit]

    # Header Row
    header = (
        f"  {dim('CVE ID'.ljust(20))}"
        f"{dim('VulnSight Risk'.ljust(18))}"
        f"{dim('CVSS'.ljust(8))}"
        f"{dim('Severity'.ljust(14))}"
        f"{dim('Fix')}"
    )

    rows = [header]
    for c in top:
        cid = (c.get("cve") or "")[:18].ljust(20)
        risk_val = c.get("contribution") or c.get("raw_risk_score") or 0
        risk_color = bold_red if risk_val >= 25 else bold_yellow if risk_val >= 10 else dim
        risk_str = risk_color(f"{risk_val:.1f}")
        risk_padded = risk_str + " " * max(0, 18 - len(f"{risk_val:.1f}"))
        cvss = str(c.get("cvss", "")).ljust(8)
        sev = (c.get("severity") or "").title()
        sev_str = _sev_color(sev)(sev.ljust(14))
        fix = bold_green("Yes") if c.get("fix_available") else dim("No")
        rows.append(f"  {cid}{risk_padded}{cvss}{sev_str}{fix}")

    return [
        "",
        _rule(f"TOP {limit} CVES BY RISK", width),
        "",
        *rows,
    ]


def _section_kev(meta, width, limit=5):
    """List CISA Known Exploited Vulnerabilities, if any."""
    kev_summary = meta.get("kev_summary", {}) or {}
    kevs = kev_summary.get("kev_vulnerabilities", [])
    if not kevs:
        return []

    n = len(kevs)
    count_phrase = "CVE actively exploited in the wild" if n == 1 else "CVEs actively exploited in the wild"

    lines = [
        "",
        _rule("CISA KNOWN EXPLOITED VULNERABILITIES", width),
        "",
        f"  {bold_red(n)} {dim(count_phrase)}",
        "",
    ]
    for k in kevs[:limit]:
        cid = k.get("cve", "")
        cvss = k.get("cvss") or "?"
        epss = k.get("epss")
        epss_str = f"EPSS {epss:.2f}" if isinstance(epss, (int, float)) else "EPSS ?"
        title = k.get("name") or k.get("vulnerability_name") or k.get("description") or ""
        if title:
            max_title = max(0, width - len(cid) - 30)
            if len(title) > max_title:
                cut = title[:max_title].rstrip()
                last_space = cut.rfind(" ")
                if last_space > max_title * 0.6:
                    cut = cut[:last_space]
                title = cut.rstrip(",.;:") + "\u2026"
            lines.append(f"  {bold(cid.ljust(18))} {dim(title)}")
            lines.append(f"  {' ' * 18} {dim(f'CVSS {cvss}  ·  {epss_str}')}")
            lines.append("")
        else:
            lines.append(f"  {bold(cid)}  {dim(f'CVSS {cvss}  ·  {epss_str}')}")
    if n > limit:
        lines.append(f"  {dim(f'... and {n - limit} more')}")
    return lines


def _section_recommendations(meta, width, limit=4):
    """Top remediation recommendations."""
    recs = meta.get("recommendations", []) or []
    if not recs:
        return []
    lines = [
        "",
        _rule("TOP RECOMMENDATIONS", width),
        "",
    ]
    for i, rec in enumerate(recs[:limit], 1):
        first, *rest = (rec or "").splitlines()
        wrapped = textwrap.fill(
            first.strip(),
            width=width - 6,
            initial_indent="",
            subsequent_indent="     ",
        )
        lines.append(f"  {bold(f'{i}.')} {wrapped}")
        for cont in rest:
            cont_wrapped = textwrap.fill(
                cont.strip(),
                width=width - 6,
                initial_indent="     ",
                subsequent_indent="     ",
            )
            if cont_wrapped.strip():
                lines.append(dim(cont_wrapped))
        lines.append("")
    return lines


def _section_context(meta, width):
    """Container or host context findings."""
    ctx = meta.get("context", {}) or {}
    container = ctx.get("container", {}) or {}

    if not container:
        return []

    is_host = meta.get("mode") == "host"

    runs_as_root = container.get("runs_as_root")
    suid_count   = len(container.get("suid_binaries") or []) if isinstance(container.get("suid_binaries"), list) else container.get("suid_binaries", 0)
    dangerous    = container.get("dangerous_tools") or []
    eol          = container.get("base_image_eol")

    def yesno_risk(val, danger_word):
        if val is True:
            return f"{bold_red('Yes')}  {dim(f'\u00b7 {danger_word}')}"
        if val is False:
            return bold_green("No")
        return dim("unknown")

    section_label = "SYSTEM CONTEXT" if is_host else "CONTAINER CONTEXT"
    lines = [
        "",
        _rule(section_label, width),
        "",
        _row("Runs as root",   yesno_risk(runs_as_root, "privilege escalation risk")),
        _row("Dangerous tools",
             f"{red(', '.join(dangerous))}  {dim('\u00b7 attack surface')}" if dangerous else green("none detected")),
        _row("SUID binaries",  bold_red(suid_count) if suid_count else green(0)),
    ]
    if not is_host:
        lines.append(_row("Base image EOL", yesno_risk(eol, "security updates may be unavailable")))
    return lines


def _section_artifacts(meta, artifact_dir, width):
    """Pointers to the generated files."""
    artifacts = meta.get("artifacts", {}) or {}
    base = Path(artifact_dir)

    # Standard Files
    items = [
        ("HTML report", base / "report.html"),
        ("PDF report",  base / "report.pdf"),
        ("Metadata",    base / "metadata.json"),
        ("SBOM",        base / "sbom.json"),
        ("Grype",       base / "grype.json"),
        ("Threat intel", base / "threat_intel.json"),
    ]
    lines = [
        "",
        _rule("ARTIFACTS", width),
        "",
    ]
    for label, p in items:
        if p.exists():
            lines.append(_row(label, dim(str(p))))
    return lines


def _bookend_top(width):
    """Strong opening: double-rule + centered title + double-rule."""
    title = "VULNSIGHT SCAN REPORT"
    pad = max(0, (width - len(title)) // 2)
    return [
        "",
        bold_cyan("\u2550" * width),
        bold_cyan(" " * pad + title),
        bold_cyan("\u2550" * width),
    ]


def _bookend_bottom(meta, total_seconds, width):
    """Strong closing: double-rule + summary line + double-rule."""
    risk = meta.get("risk", {}) or {}
    ti_summary = meta.get("threat_intel_summary", {}) or {}
    cve_count = ti_summary.get("cve_count", 0)
    score = risk.get("overall_score")
    closing_bits = [f"{total_seconds:.2f}s", f"{cve_count} CVEs"]
    if score is not None:
        closing_bits.append(f"score {score}")
    closing = "Report complete  \u00b7  " + "  \u00b7  ".join(closing_bits)
    pad = max(0, (width - len(closing)) // 2)
    return [
        "",
        bold_cyan("\u2550" * width),
        bold_cyan(" " * pad + closing),
        bold_cyan("\u2550" * width),
        "",
    ]


# Public Entry Point
def render(metadata_path, scan_result, total_seconds, artifact_dir=None):
    metadata_path = Path(metadata_path)
    if artifact_dir is None:
        artifact_dir = metadata_path.parent

    try:
        meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"\n[!] Could not render scan summary: {exc}", file=sys.stderr)
        return

    width = _term_width()

    lines = []
    lines += _bookend_top(width)
    lines += _section_header(meta, scan_result, total_seconds, width)
    lines += _section_risk(meta, width)
    lines += _section_exec_summary(meta, width)
    lines += _section_top_cves(meta, width)
    lines += _section_kev(meta, width)
    lines += _section_recommendations(meta, width)
    lines += _section_context(meta, width)
    lines += _section_artifacts(meta, artifact_dir, width)
    lines += _bookend_bottom(meta, total_seconds, width)

    print("\n".join(lines))
