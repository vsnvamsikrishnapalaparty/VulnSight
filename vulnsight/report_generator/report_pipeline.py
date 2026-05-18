#!/usr/bin/env python3
import json
import argparse
import sys
from pathlib import Path
from collections import Counter

#  STEP 1 — PARSE RAW FILES INTO vulnsight_data DICT
def parse(grype_path, sbom_path, threat_path, meta_path):
    print("[+] Loading input files...")
    with open(grype_path,  encoding="utf-8") as f: grype  = json.load(f)
    with open(sbom_path,   encoding="utf-8") as f: sbom   = json.load(f)
    with open(threat_path, encoding="utf-8") as f: threat = json.load(f)
    with open(meta_path,   encoding="utf-8") as f: meta   = json.load(f)

    # Helpers
    def sev_norm(s):
        mapping = {"critical":"Critical","high":"High","medium":"Medium",
                   "low":"Low","negligible":"Negligible","unknown":"Negligible"}
        return mapping.get((s or "").lower(), "Negligible")

    def first_license(licenses):
        for lic in (licenses or []):
            expr = lic.get("spdxExpression") or lic.get("value") or ""
            if expr:
                return expr
        return "Unknown"

    def first_path(locations):
        for loc in (locations or []):
            p = loc.get("accessPath") or loc.get("path") or ""
            if p:
                return p
        return ""

    # Metadata
    image_name   = meta.get("image", "unknown")
    digest_short = meta.get("digest_short", "")
    digest_full  = meta.get("digest", "")
    digest_disp  = digest_full[:20] + "…" + digest_short if digest_short else digest_full[:30]
    scan_ts      = meta.get("scan_timestamp", "")
    scan_date    = scan_ts[:10] if scan_ts else ""
    scan_time    = scan_ts[11:19] + " UTC" if len(scan_ts) > 18 else ""
    scanner_ver  = meta.get("scanner_version", "1.0.0")

    tis      = meta.get("threat_intel_summary", {})
    risk_obj = meta.get("risk", {})
    ctx      = meta.get("context", {}).get("container", {})
    arts_raw = meta.get("artifacts", {})

    # Severity breakdown from grype matches
    sev_counts = Counter()
    for m in grype.get("matches", []):
        sev_counts[sev_norm(m["vulnerability"].get("severity", ""))] += 1
    seen_cves = {}
    cve_packages = {}
    cve_fix_ver  = {}
    for m in grype.get("matches", []):
        v   = m["vulnerability"]
        cid = v["id"]
        if cid not in seen_cves:
            seen_cves[cid] = v
        art = m.get("artifact", {}) or {}
        pkg_name = art.get("name", "")
        pkg_ver  = art.get("version", "")
        if pkg_name:
            tag = f"{pkg_name}@{pkg_ver}" if pkg_ver else pkg_name
            cve_packages.setdefault(cid, set()).add(tag)
        fix_info = v.get("fix") or {}
        if fix_info.get("state") == "fixed" and cid not in cve_fix_ver:
            versions = fix_info.get("versions") or []
            if versions:
                cve_fix_ver[cid] = versions[0]

    sev_breakdown_order = ["Critical", "High", "Medium", "Low", "Negligible"]
    sev_breakdown = {
        s: sev_counts.get(s, 0) for s in sev_breakdown_order if sev_counts.get(s, 0) > 0
    }

    # VulnSight per-CVE Risk Lookup
    vs_risk_by_cve = {
        entry["cve"]: float(entry.get("contribution") or 0)
        for entry in (risk_obj.get("per_cve") or [])
    }

    # Build Merged CVE List (Grype + Threat Intel)
    cve_list = []
    for cid, v in seen_cves.items():
        ti   = threat.get(cid, {})
        fix  = v.get("fix", {})
        fix_available = (fix.get("state") == "fixed") if fix else False

        cvss_raw = v.get("cvss") or []
        cvss_val = 0.0
        if cvss_raw:
            scores = [c.get("metrics", {}).get("baseScore", 0) for c in cvss_raw
                      if isinstance(c.get("metrics", {}), dict)]
            cvss_val = max(scores) if scores else 0.0
        if cvss_val == 0.0 and ti.get("cvss"):
            cvss_val = float(ti["cvss"] or 0)

        # Affected packages
        pkgs = sorted(cve_packages.get(cid, set()))
        pkg_display = ", ".join(pkgs[:3]) + (f" (+{len(pkgs) - 3})" if len(pkgs) > 3 else "")

        vs_risk = vs_risk_by_cve.get(cid)
        if vs_risk is None:
            vs_risk = float(v.get("risk") or 0)

        cve_list.append({
            "id":       cid,
            "name":     ti.get("title") or v.get("description", "")[:60] or cid,
            "cvss":     round(cvss_val, 1),
            "risk": round(vs_risk, 1),
            "severity": sev_norm(v.get("severity", "")),
            "fix":      fix_available,
            "fix_version": cve_fix_ver.get(cid, ""),
            "packages": pkg_display,
            "epss": ti.get("epss") or 0,
            "kev":      ti.get("kev", False),
            "cwe":      ti.get("cwe", ""),
            "age_days": ti.get("age_days") or 0,
            "description": ti.get("description") or v.get("description", ""),
            "exploitability": "High" if cvss_val >= 7 else ("Medium" if cvss_val >= 4 else "Low"),
        })

    cve_list.sort(key=lambda x: (x["risk"], x["cvss"]), reverse=True)

    # Top CVEs from metadata.risk.top_cves
    top_raw = risk_obj.get("top_cves", [])[:10]
    top_cves = []
    for tc in top_raw:
        cid  = tc["cve"]
        ti   = threat.get(cid, {})
        summary = ti.get("description") or ""
        if not summary:
            for m in grype.get("matches", []):
                if m["vulnerability"]["id"] == cid:
                    summary = m["vulnerability"].get("description", "")
                    break
        top_cves.append({
            "id":       cid,
            "summary":  summary or cid,
            "cvss": float(tc.get("cvss") or 0),
            "risk": round(float(tc.get("contribution") or 0), 1),
            "severity": sev_norm(tc.get("severity", "")),
            "fix":      bool(tc.get("fix_available", False)),
        })

    # Metrics
    unique_cves   = len(seen_cves)
    high_sev      = tis.get("high_risk_cve_count", sum(1 for c in cve_list if c["severity"] in ("Critical","High")))
    max_cvss      = tis.get("max_cvss", max((c["cvss"] for c in cve_list), default=0))
    cves_with_cvss = [c["cvss"] for c in cve_list if c["cvss"] and c["cvss"] > 0]
    avg_cvss      = round(sum(cves_with_cvss) / max(len(cves_with_cvss), 1), 2) if cves_with_cvss else 0
    kev_count     = tis.get("kev_count", sum(1 for c in cve_list if c["kev"]))
    fixable       = sum(1 for c in cve_list if c["fix"])
    total_vulns   = meta.get("vulnerability_count", len(grype.get("matches", [])))
    sbom_comps    = meta.get("sbom_components", len(sbom.get("artifacts", [])))

    # Key Findings
    dangerous_tools = ctx.get("dangerous_tools", [])
    tools_str = ", ".join(
        f'<strong style="color:#3b82f6">{t}</strong>' for t in dangerous_tools
    ) if dangerous_tools else "none"

    key_findings = [
        {"icon": "ti-bug",          "color": "#dc2626",
         "text": f"{unique_cves} unique CVEs &middot; {total_vulns} total vulnerabilities"},
        {"icon": "ti-flame",        "color": "#dc2626",
         "text": f"{high_sev} high-severity CVEs (CVSS &ge; 7.0)"},
        {"icon": "ti-circle-check", "color": "#16a34a",
         "text": f"{kev_count} KEV-listed vulnerabilities"},
        {"icon": "ti-tool",         "color": "#94a3b8",
         "text": f"{fixable} fixable / {unique_cves - fixable} currently without fixes"},
        {"icon": "ti-user-shield",  "color": "#dc2626" if ctx.get("runs_as_root") else "#16a34a",
         "text": "Runs as root - privilege escalation risk" if ctx.get("runs_as_root")
                 else "Container does not run as root"},
        {"icon": "ti-terminal-2",   "color": "#f97316",
         "text": f"Interactive shells present: {tools_str}"},
    ]

    # Threat Intel Summary Cards
    avg_epss   = round(sum(c["epss"] for c in cve_list if c["epss"]) / max(len(cve_list), 1), 5)
    cves_with_age = [c for c in cve_list if c.get("age_days")]
    avg_age = int(sum(c["age_days"] for c in cves_with_age) / max(len(cves_with_age), 1)) if cves_with_age else 0
    oldest     = max(cve_list, key=lambda x: x.get("age_days") or 0, default={}).get("id", "N/A")
    cwe_counts = Counter(c["cwe"] for c in cve_list if c["cwe"] and c["cwe"] not in ("", "NVD-CWE-Other","NVD-CWE-noinfo"))
    top_cwe    = cwe_counts.most_common(1)
    top_cwe_id, top_cwe_n = (top_cwe[0][0], top_cwe[0][1]) if top_cwe else ("N/A", 0)

    kev_color = "#dc2626" if kev_count > 0 else "#16a34a"
    ti_summary_cards = [
        {"label": "EPSS Score (avg)",   "value": str(avg_epss),   "value_color": None,      "sub": "Exploit Prediction Scoring System"},
        {"label": "KEV Status",         "value": f"{kev_count} / {unique_cves}", "value_color": kev_color, "sub": "No actively exploited CVEs found" if kev_count == 0 else f"{kev_count} actively exploited (CISA KEV)"},
        {"label": "Exploitability",     "value": "High" if max_cvss >= 7 else "Medium", "value_color": "#dc2626" if max_cvss >= 7 else "#f97316", "sub": "Based on CVSS AV/AC metrics"},
        {"label": "Avg CVE age (days)", "value": str(avg_age),    "value_color": None,      "sub": f"Oldest: {oldest}"},
        {"label": "Top CWE",            "value": top_cwe_id,      "value_color": None,      "sub": f"{top_cwe_n} CVEs share this CWE"},
        {"label": "Vendor advisories",  "value": str(fixable),    "value_color": None,      "sub": "CVEs with upstream fixes available"},
    ]

    # Per-CVE Threat Intel Rows
    def _per_cve_row(c):
        return {
            "id":             c["id"],
            "cvss":           c["cvss"],
            "epss":           c["epss"],
            "kev":            c["kev"],
            "cwe":            c["cwe"] or "N/A",
            "age":            c["age_days"],
            "nvd_summary":    c["description"] or "",
        }
    # Top 10 by EPSS (likelihood of exploit in the wild)
    per_cve_by_epss = [
        _per_cve_row(c)
        for c in sorted(cve_list, key=lambda x: (x["epss"] or 0), reverse=True)[:10]
    ]
    # Top 10 by CVSS (technical severity)
    per_cve_by_cvss = [
        _per_cve_row(c)
        for c in sorted(cve_list, key=lambda x: x["cvss"], reverse=True)[:10]
    ]

    # ── KEV matches (from metadata.kev_summary)
    kev_summary = meta.get("kev_summary", {})
    cve_index = {c["id"]: c for c in cve_list}
    kev_matches = []
    for kv in kev_summary.get("kev_vulnerabilities", []):
        cid = kv.get("cve", "")
        enriched = cve_index.get(cid, {})
        kev_matches.append({
            "id":          cid,
            "name":        kv.get("name", ""),
            "description": kv.get("description", ""),
            "cvss":        kv.get("cvss") or enriched.get("cvss", 0),
            "epss":        kv.get("epss") or enriched.get("epss", 0),
            "severity":    enriched.get("severity", "Critical"),
            "cwe":         kv.get("cwe") or enriched.get("cwe") or "N/A",
            "age":         kv.get("age_days") or enriched.get("age_days") or 0,
            "fix":         enriched.get("fix", False),
        })
    # Sort by EPSS descending so the highest-likelihood exploit appears first
    kev_matches.sort(key=lambda k: (k["epss"] or 0), reverse=True)

    # SBOM
    pkg_cve_counts = Counter()
    pkg_kev_counts = Counter()
    for m in grype.get("matches", []):
        art_name = (m.get("artifact") or {}).get("name", "")
        if not art_name:
            continue
        pkg_cve_counts[art_name] += 1
        if (m["vulnerability"].get("knownExploited") or []):
            pkg_kev_counts[art_name] += 1
    pkg_fix_version = {
        rp["package"]: rp["fix_version"]
        for rp in meta.get("remediation_plan", [])
        if rp.get("fix_version")
    }

    sbom_list = []
    for art in sbom.get("artifacts", []):
        locs = art.get("locations", [])
        path = first_path(locs)
        name = art.get("name", "")
        sbom_list.append({
            "pkg":         name,
            "ver":         art.get("version", ""),
            "type":        art.get("type", "").lower(),
            "lic":         first_license(art.get("licenses", [])),
            "path":        path,
            "cve_count":   pkg_cve_counts.get(name, 0),
            "kev_count":   pkg_kev_counts.get(name, 0),
            "fix_version": pkg_fix_version.get(name, ""),
        })
    # Sort packages by CVE count descending so vulnerable packages float to the top.
    sbom_list.sort(key=lambda x: (-x["cve_count"], x["pkg"].lower()))

    # Remediations
    recs = meta.get("recommendations", [])

    def classify_rec(text):
        t = (text or "").lower()
        # KEV / actively exploited -> P1 Critical
        if "kev" in t or "actively exploited" in t:
            return ("rr", "ti-flame",          "P1 - Critical", "bh")
        # Critical/High severity CVE remediation -> P2 High
        if "critical and high" in t or "critical/high" in t:
            return ("ra", "ti-alert-triangle", "P2 - High",     "bm")
        # Highest-impact / top packages -> P1 Critical (large CVE counts per upgrade)
        if "highest-impact" in t or "prioritise upgrading the highest" in t:
            return ("rr", "ti-package",        "P1 - Critical", "bh")
        # General package upgrades via package manager -> P3 Medium
        if "package manager" in t or "newer versions available" in t:
            return ("rl", "ti-refresh",        "P3 - Medium",   "bn")
        # Non-root user -> P3 Medium
        if "non-root" in t or "non root" in t:
            return ("rl", "ti-user-shield",    "P3 - Medium",   "bn")
        # Remove shells / interactive tools -> P4 Low (defense-in-depth hardening)
        if "interactive tools" in t or ("remove" in t and "shell" in t) or "attack surface" in t:
            return ("rg", "ti-terminal-2",     "P4 - Low",      "bg")
        # Fallback
        return ("rl", "ti-shield-check",       "P3 - Medium",   "bn")

    # Build actions list, then sort by priority order so the page reads top-down.
    priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    raw_actions = []
    for rec in recs:
        cls, icon, prio, badge = classify_rec(rec)
        raw_actions.append({
            "class":    cls,
            "icon":     icon,
            "title":    rec,
            "detail":   "",
            "priority": prio,
            "badge":    badge,
        })
    raw_actions.sort(key=lambda a: priority_rank.get(a["priority"][:2], 9))
    actions = raw_actions

    bucket_styles = {
        "P1": {"label": "Critical", "color": "#dc2626", "bg": "#fef2f2", "border": "#fecaca"},
        "P2": {"label": "High",     "color": "#d97706", "bg": "#fffbeb", "border": "#fde68a"},
        "P3": {"label": "Medium",   "color": "#475569", "bg": "#f8fafc", "border": "#e2e8f0"},
        "P4": {"label": "Low",      "color": "#16a34a", "bg": "#f0fdf4", "border": "#bbf7d0"},
    }
    bucket_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for a in actions:
        bucket_counts[a["priority"][:2]] += 1

    priority_matrix = []
    for key in ["P1", "P2", "P3", "P4"]:
        style = bucket_styles[key]
        priority_matrix.append({
            "key":    key,
            "label":  style["label"],
            "color":  style["color"],
            "bg":     style["bg"],
            "border": style["border"],
            "count":  bucket_counts[key],
        })

    # Artifacts lLst
    from posixpath import dirname as _pp_dirname, join as _pp_join
    sbom_disp = arts_raw.get("sbom_path", "sbom.json")
    meta_disp = _pp_join(_pp_dirname(sbom_disp), "metadata.json") if sbom_disp else "metadata.json"

    artifacts_list = [
        {"icon": "ti-file-code",     "label": "SBOM",              "path": sbom_disp},
        {"icon": "ti-shield-search", "label": "Vulnerability scan", "path": arts_raw.get("grype_path", "grype.json")},
        {"icon": "ti-radar",         "label": "Threat intel",       "path": arts_raw.get("threat_intel_path", "threat_intel.json")},
        {"icon": "ti-info-circle",   "label": "Metadata",           "path": meta_disp},
    ]

    # Assembling Final Data Dict
    risk_score = risk_obj.get("overall_score", 0)
    risk_level = risk_obj.get("risk_level", "UNKNOWN").title()

    return {
        "mode": meta.get("mode", "docker"),
        "app": {
            "name":     "VulnSight",
            "subtitle": "",
            "version":  f"v{scanner_ver}",
            "tagline":  "",
        },
        "image": {
            "name":       image_name,
            "digest":     digest_disp,
            "scan_date":  scan_date,
            "scan_time":  scan_time,
            "sources":    "grype.json + threat_intel.json",
        },
        "risk": {
            "score": str(risk_score),
            "label": f"{risk_level} risk",
        },
        "metrics": {
            "unique_cves":         unique_cves,
            "high_severity":       high_sev,
            "max_cvss":            max_cvss,
            "avg_cvss":            avg_cvss,
            "kev_listed":          kev_count,
            "fixable":             fixable,
            "total_vulnerabilities": total_vulns,
            "sbom_components":     sbom_comps,
        },
        "severity_breakdown": sev_breakdown,
        "executive_summary":  meta.get("executive_summary", "No summary available."),
        "key_findings":       key_findings,
        "top_cves":           top_cves,
        "container_context":  {
            "runs_as_root":    ctx.get("runs_as_root", False),
            "suid_binaries":   len(ctx.get("suid_binaries", [])),
            "dangerous_tools": dangerous_tools,
            "base_image_eol":  ctx.get("base_image_eol", False),
        },
        "artifacts":     artifacts_list,
        "threat_intel":  {
            "summary_cards": ti_summary_cards,
            "per_cve_epss":  per_cve_by_epss,
            "per_cve_cvss":  per_cve_by_cvss,
            "kev_matches":   kev_matches,
        },
        "remediations":  {
            "ai_summary":         meta.get("remediation_summary_text", ""),
            "actions":            actions,
            "priority_matrix":    priority_matrix,
        },
        "cve_list":  cve_list,
        "sbom":      sbom_list,
    }


#  HTML GENERATOR

SEV_BADGE = {"Critical":"bh","High":"bh","Medium":"bm","Low":"bl","Negligible":"bn"}
EXPLOIT_BADGE = {"High":"bh","Medium":"bm","Low":"bn"}

def e(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def trunc(s, n):
    """Truncate `s` to <= n chars, appending an ellipsis if it was cut."""
    s = s or ""
    return s if len(s) <= n else s[: n - 1].rstrip() + "\u2026"

def bar_color(cvss):
    return "#dc2626" if cvss >= 7 else "#f97316"


# Executive / Remediation Summary Highlighter
import re as _re_summary

_RE_SCORE   = _re_summary.compile(r'\b(\d{1,3}(?:\.\d+)?)/100\b')
_RE_CVE     = _re_summary.compile(r'\b(CVE-\d{4}-\d{4,7})\b')
_RE_PKGFIX  = _re_summary.compile(r'\b([a-zA-Z0-9_.+-]+ \(\d+ CVEs? -&gt; [^)]+\))')

def highlight_summary(escaped_text):
    if not escaped_text:
        return escaped_text
    s = escaped_text
    s = _RE_SCORE.sub(
        r'<span style="color:#b91c1c;font-weight:500">\1/100</span>',
        s,
    )
    # CVE IDs
    s = _RE_CVE.sub(
        r'<span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:0.92em;'
        r'background:#fef2f2;color:#b91c1c;padding:1px 5px;border-radius:3px">\1</span>',
        s,
    )

    s = _RE_PKGFIX.sub(
        r'<span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:0.92em;'
        r'color:#0f172a">\1</span>',
        s,
    )
    return s

CHEV_SVG = (
    '<svg width="12" height="12" viewBox="0 0 12 12" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
    '<path d="M4 2 L8 6 L4 10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

def chevron_cell(detail_id):
    """A chevron button that toggles the matching detail row by id."""
    return (
        f'<td style="width:32px;padding-right:0">'
        f'<button class="chev" type="button" aria-expanded="false" aria-controls="{detail_id}" '
        f'onclick="toggleCveDetail(this,\'{detail_id}\');event.stopPropagation()">{CHEV_SVG}</button>'
        f'</td>'
    )

def detail_row(detail_id, colspan, summary_text):
    """The hidden detail row that appears when the chevron is clicked."""
    return (
        f'<tr class="detail-row" id="{detail_id}">'
        f'<td colspan="{colspan}">'
        f'<div class="detail-inner">'
        f'<div class="detail-label">CVE Summary</div>'
        f'{e(summary_text or "(no description available)")}'
        f'</div></td></tr>'
    )

CSS = """<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{height:100%}
body{margin:0;padding:0;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.sidebar{width:230px;min-width:230px;background:#1e293b;display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100}
.sb-brand{padding:20px 18px 16px;border-bottom:0.5px solid rgba(255,255,255,0.07)}
.sb-brand-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.sb-icon{width:34px;height:34px;background:rgba(248,113,113,0.16);border:0.5px solid rgba(248,113,113,0.4);border-radius:8px;display:flex;align-items:center;justify-content:center}
.sb-icon svg{display:block}
.sb-app-name{font-size:16px;font-weight:500;color:#f1f5f9}
.sb-app-sub{font-size:10px;color:#475569}
.sb-image{font-family:ui-monospace,monospace;font-size:10px;color:#64748b;background:rgba(255,255,255,0.05);border:0.5px solid rgba(255,255,255,0.07);border-radius:5px;padding:5px 8px;word-break:break-all}
.sb-section{padding:14px 12px 5px;font-size:10px;font-weight:500;color:#475569;letter-spacing:.08em;text-transform:uppercase}
.nav-item{display:flex;align-items:center;gap:9px;padding:9px 12px;margin:1px 6px;border-radius:7px;font-size:13px;color:#94a3b8;cursor:pointer;border:none;background:none;width:calc(100% - 12px);text-align:left}
.nav-item i{font-size:15px;flex-shrink:0}
.nav-item:hover{background:rgba(255,255,255,0.05);color:#cbd5e1}
.nav-item.active{background:rgba(239,68,68,0.15);color:#fca5a5}
.nav-item.active i{color:#f87171}
.sb-divider{height:0.5px;background:rgba(255,255,255,0.07);margin:8px 14px}
.sb-footer{margin-top:auto;padding:14px 14px;border-top:0.5px solid rgba(255,255,255,0.07)}
.sb-footer-label{font-size:11px;color:#cbd5e1;font-weight:500;line-height:1.4}
.sb-footer-version{color:#94a3b8;font-weight:400}
.sb-footer-val{font-size:11px;color:#94a3b8;margin-top:3px;line-height:1.4}
.sb-footer-credit{color:#64748b}
.main{margin-left:230px;display:flex;flex-direction:column;min-width:0;min-height:100vh}
.topbar{background:#fff;border-bottom:0.5px solid #e2e8f0;padding:14px 24px;display:flex;align-items:center;gap:14px;flex-shrink:0}
.topbar-left{display:flex;flex-direction:column;gap:3px;flex:1;min-width:0}
.topbar-title{font-size:15px;font-weight:500;color:#0f172a}
.topbar-sub{font-size:11px;color:#94a3b8;font-family:ui-monospace,monospace}
.dl-pdf{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border:0.5px solid #cbd5e1;border-radius:8px;background:#fff;color:#475569;font-size:12px;font-weight:500;text-decoration:none;cursor:pointer;transition:background 0.15s ease,border-color 0.15s ease,color 0.15s ease;flex-shrink:0}
.dl-pdf:hover{background:#f8fafc;border-color:#94a3b8;color:#0f172a}
.dl-pdf i{font-size:15px}
.score-pill{display:flex;align-items:center;gap:10px;background:#fef2f2;border:0.5px solid #fca5a5;border-radius:999px;padding:6px 18px 6px 16px;flex-shrink:0}
.score-caption{font-size:9.5px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;line-height:1.15;text-align:right;border-right:0.5px solid currentColor;padding-right:10px;opacity:0.85}
.score-num{font-size:20px;font-weight:500;color:#dc2626;line-height:1}
.score-label{font-size:10px;color:#ef4444;font-weight:500;text-transform:uppercase;letter-spacing:.06em}
.acc-bar{height:3px;background:linear-gradient(90deg,#dc2626,#f97316,transparent);flex-shrink:0}
.content{padding:22px 24px;display:flex;flex-direction:column;gap:14px;flex:1}
.page{display:none;flex-direction:column;gap:14px}
.page.active{display:flex}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.metric{background:#fff;border:0.5px solid #e2e8f0;border-radius:10px;padding:12px 14px}
.metric-label{font-size:11px;color:#64748b;margin-bottom:4px}
.metric-value{font-size:24px;font-weight:500;color:#0f172a}
.metric.m-red{background:#fef2f2;border-color:#fecaca}
.metric.m-red .metric-label{color:#ef4444}
.metric.m-red .metric-value{color:#dc2626}
.metric.m-green{background:#f0fdf4;border-color:#bbf7d0}
.metric.m-green .metric-label{color:#16a34a}
.metric.m-green .metric-value{color:#16a34a}
.card{background:#fff;border:0.5px solid #e2e8f0;border-radius:12px;padding:16px 18px}
.card-head{display:flex;align-items:center;gap:7px;margin-bottom:12px}
.card-head i{font-size:15px;color:#64748b}
.card-head span{font-size:13px;font-weight:500;color:#0f172a}
.card-head-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.card-head-row .card-head{margin-bottom:0}
.hint{font-size:11px;color:#94a3b8}
.two-col{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1.3fr);gap:14px}
.half-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
.charts-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
@media(max-width:900px){.two-col,.half-col,.charts-row{grid-template-columns:1fr}}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px}
.li{display:flex;align-items:center;gap:5px;font-size:11px;color:#64748b}
.sw{width:9px;height:9px;border-radius:2px;display:inline-block}
p.sum{font-size:13px;line-height:1.75;color:#334155;margin:0}
.finds{display:flex;flex-direction:column;gap:9px}
.frow{display:flex;align-items:flex-start;gap:8px;font-size:13px;color:#334155}
.frow i{font-size:14px;flex-shrink:0;margin-top:1px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:9px 10px;background:#f8fafc;border-bottom:0.5px solid #e2e8f0;text-align:left;font-size:11.5px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
td{padding:9px 10px;border-bottom:0.5px solid #f1f5f9;vertical-align:middle;color:#334155}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.cid{font-family:ui-monospace,monospace;font-size:12px;color:#3b82f6;white-space:nowrap}
.chv{color:#dc2626;font-weight:500}
.badge{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:500}
.bh{background:#fee2e2;color:#b91c1c}
.bm{background:#fef3c7;color:#92400e}
.bl{background:#dcfce7;color:#15803d}
.bn{background:#f1f5f9;color:#475569}
.by{background:#fee2e2;color:#b91c1c}
.bg{background:#dcfce7;color:#15803d}
.tag-r{background:#fee2e2;color:#b91c1c;font-size:11px;padding:2px 8px;border-radius:999px;display:inline-block;margin-right:3px}
.bw{background:#e2e8f0;border-radius:999px;height:5px;width:100%;overflow:hidden;min-width:60px}
.bf{height:5px;border-radius:999px}
.ctx{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:0.5px solid #e2e8f0;border-radius:8px;margin-bottom:7px}
.ctx:last-child{margin-bottom:0}
.cl{font-size:12px;color:#64748b}
.cv{font-size:12px;color:#0f172a;font-weight:500}
.remed{display:flex;flex-direction:column;gap:8px}
.ri{display:flex;gap:9px;align-items:flex-start;padding:10px 12px;border-radius:8px;font-size:13px;line-height:1.55}
.ri i{font-size:15px;flex-shrink:0;margin-top:1px}
.rr{background:#fef2f2;border:0.5px solid #fecaca;color:#7f1d1d}.rr i{color:#dc2626}
.ra{background:#fffbeb;border:0.5px solid #fde68a;color:#78350f}.ra i{color:#d97706}
.rl{background:#f8fafc;border:0.5px solid #e2e8f0;color:#475569}.rl i{color:#94a3b8}
.rg{background:#f0fdf4;border:0.5px solid #bbf7d0;color:#14532d}.rg i{color:#16a34a}
.art-card{display:flex;align-items:center;gap:9px;padding:9px 11px;background:#f8fafc;border:0.5px solid #e2e8f0;border-radius:8px;overflow:hidden;margin-bottom:7px}
.art-card:last-child{margin-bottom:0}
.art-card i{font-size:15px;color:#64748b;flex-shrink:0}
.al{font-size:11px;color:#94a3b8}
.ap{font-family:ui-monospace,monospace;font-size:11px;color:#3b82f6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.ti-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.ti-card{background:#f8fafc;border:0.5px solid #e2e8f0;border-radius:8px;padding:12px 14px}
.ti-label{font-size:11px;color:#64748b;margin-bottom:5px;text-transform:uppercase;letter-spacing:.05em}
.ti-value{font-size:20px;font-weight:500;color:#0f172a}
.ti-sub{font-size:11px;color:#94a3b8;margin-top:2px}
.search-bar{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.search-bar input{flex:1;padding:8px 12px;border:0.5px solid #e2e8f0;border-radius:8px;font-size:13px;color:#334155;outline:none;background:#f8fafc}
.search-bar input:focus{border-color:#94a3b8;background:#fff}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:13px;color:#64748b;flex-wrap:wrap}
.page-btn{padding:4px 10px;border:0.5px solid #e2e8f0;border-radius:6px;background:#fff;font-size:12px;cursor:pointer;color:#334155}
.page-btn:hover{background:#f8fafc}
.page-btn.active-pg{background:#1e293b;color:#fff;border-color:#1e293b}
.footer{font-size:11px;color:#94a3b8;text-align:right;padding-top:4px;padding-bottom:8px}
.nf{color:#dc2626;font-weight:500}
.epss-hi{color:#dc2626;font-weight:500;font-family:ui-monospace,monospace}
.nvd-cell{font-size:11px;color:#64748b;line-height:1.5;white-space:normal;word-break:normal;overflow-wrap:break-word}
.cve-summary{font-size:12px;color:#475569;line-height:1.5;white-space:normal;word-break:normal;overflow-wrap:break-word}
.chev{width:18px;height:18px;border:none;background:transparent;cursor:pointer;padding:0;display:inline-flex;align-items:center;justify-content:center;color:#94a3b8;transition:transform 0.15s ease,color 0.15s ease;flex-shrink:0}
.chev:hover{color:#475569}
.chev[aria-expanded="true"]{transform:rotate(90deg);color:#475569}
.chev svg{display:block;pointer-events:none}
.expandable-row{cursor:pointer}
.expandable-row:hover td{background:#f8fafc}
.detail-row{display:none}
.detail-row.show{display:table-row}
.detail-row td{background:#f8fafc;border-bottom:0.5px solid #f1f5f9;padding:0}
.detail-inner{padding:12px 18px 14px 44px;font-size:12.5px;color:#334155;line-height:1.6;border-left:3px solid #f87171}
.detail-label{font-size:10px;color:#94a3b8;letter-spacing:.05em;text-transform:uppercase;font-weight:600;margin-bottom:6px}
.risk-legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.risk-tier{display:inline-flex;align-items:center;padding:4px 12px;border:0.5px solid;border-radius:999px;font-size:11px;font-weight:500;line-height:1}
.pm-card{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;background:#fff;border:0.5px solid #e2e8f0;border-radius:10px;padding:10px 14px}
.pm-title{display:flex;align-items:center;gap:6px;font-size:12px;color:#64748b;font-weight:500;white-space:nowrap}
.pm-title i{font-size:14px;color:#94a3b8}
.pm-row{display:flex;flex-wrap:wrap;gap:8px}
.pm-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:0.5px solid #e2e8f0;border-radius:999px;font-size:11px;line-height:1}
.pm-dot{width:7px;height:7px;border-radius:50%}
.pm-key{font-weight:600;font-family:ui-monospace,monospace}
.pm-label{color:#475569}
.pm-count{margin-left:4px;padding:1px 7px;background:rgba(15,23,42,0.06);border-radius:999px;font-size:10px;font-weight:600;color:#334155;font-family:ui-monospace,monospace}
</style>"""


def build_html(d, pdf_data_uri=None):
    app = d["app"]; img = d["image"]; risk = d["risk"]; m = d["metrics"]
    sb  = d["severity_breakdown"]

    is_host = d.get("mode") == "host"
    subject_title = "System" if is_host else "Container"
    subject_lower = "system" if is_host else "container"

    # Sidebar
    logomark_svg = (
        '<svg width="20" height="20" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
        '<circle cx="16" cy="16" r="11" fill="none" stroke="#f87171" stroke-width="1.8"/>'
        '<line x1="16" y1="3" x2="16" y2="7" stroke="#f87171" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="16" y1="25" x2="16" y2="29" stroke="#f87171" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="3" y1="16" x2="7" y2="16" stroke="#f87171" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="25" y1="16" x2="29" y2="16" stroke="#f87171" stroke-width="1.8" stroke-linecap="round"/>'
        '<circle cx="24" cy="8" r="3.2" fill="#fbbf24"/>'
        '</svg>'
    )

    raw_name = app["name"]
    if "Sight" in raw_name:
        head, _, tail = raw_name.partition("Sight")
        wordmark_html = f'{e(head)}<span style="color:#f87171">Sight{e(tail)}</span>'
    else:
        wordmark_html = e(raw_name)

    def sidebar():
        return f'''<div class="sidebar">
  <div class="sb-brand">
    <div class="sb-brand-row">
      <div class="sb-icon">{logomark_svg}</div>
      <div><div class="sb-app-name">{wordmark_html}</div></div>
    </div>
    <div class="sb-image">{e(img["name"])} &middot; {e(img["digest"])}</div>
  </div>
  <div class="sb-section">Navigation</div>
  <button class="nav-item active" onclick="showPage('summary',this)"><i class="ti ti-layout-dashboard"></i>Report Summary</button>
  <button class="nav-item" onclick="showPage('cve',this)"><i class="ti ti-bug"></i>CVE List</button>
  <button class="nav-item" onclick="showPage('threat',this)"><i class="ti ti-radar"></i>Threat Intelligence</button>
  <button class="nav-item" onclick="showPage('sbom',this)"><i class="ti ti-file-code"></i>SBOM Viewer</button>
  <button class="nav-item" onclick="showPage('remed',this)"><i class="ti ti-shield-check"></i>Remediation Plan</button>
  <div class="sb-divider"></div>
  <div class="sb-section">Scan Info</div>
  <div style="padding:0 14px">
    <div class="ctx" style="margin-bottom:6px"><span class="cl">Scanned</span><span class="cv mono" style="font-size:11px">{e(img["scan_date"])}</span></div>
    <div class="ctx" style="margin-bottom:6px"><span class="cl">Components</span><span class="cv">{m["sbom_components"]}</span></div>
    <div class="ctx"><span class="cl">Total CVEs</span><span class="cv">{m["total_vulnerabilities"]}</span></div>
  </div>
  <div class="sb-footer">
    <div class="sb-footer-label">Vuln<span style="color:#f87171">Sight</span> <span class="sb-footer-version">{e(app["version"])}</span></div>
    <div class="sb-footer-val"><span class="sb-footer-credit">Built by</span> Venkata Sai Nataraja Vamsi Krishna Palaparty</div>
  </div>
</div>'''

    # Topbar
    def topbar():
        rl = (risk.get("label","") or "").lower()
        if "critical" in rl:
            pill_bg, pill_bd, pill_fg, pill_lb = "#fef2f2", "#fca5a5", "#dc2626", "#ef4444"
        elif "high" in rl:
            pill_bg, pill_bd, pill_fg, pill_lb = "#fff7ed", "#fdba74", "#ea580c", "#f97316"
        elif "medium" in rl or "moderate" in rl:
            pill_bg, pill_bd, pill_fg, pill_lb = "#fffbeb", "#fcd34d", "#b45309", "#d97706"
        elif "low" in rl:
            pill_bg, pill_bd, pill_fg, pill_lb = "#f0fdf4", "#86efac", "#15803d", "#16a34a"
        else:
            pill_bg, pill_bd, pill_fg, pill_lb = "#f1f5f9", "#cbd5e1", "#334155", "#64748b"

        pdf_filename = f'vulnsight_{e(img["name"]).replace(":", "_").replace("/", "_")}.pdf'
        pdf_btn_html = (
            f'    <a class="dl-pdf" href="{pdf_data_uri}" download="{pdf_filename}" '
            f'title="Download report as PDF">'
            f'<i class="ti ti-file-download" aria-hidden="true"></i>'
            f'<span>Download PDF</span></a>'
        ) if pdf_data_uri else ""

        return f'''  <div class="topbar">
    <div class="topbar-left">
      <div class="topbar-title" id="topbar-title">{subject_title} Security Report - {e(img["name"])}</div>
      <div class="topbar-sub">Scanned {e(img["scan_date"])} at {e(img["scan_time"])}</div>
    </div>
{pdf_btn_html}
    <div class="score-pill" style="background:{pill_bg};border-color:{pill_bd}">
      <i class="ti ti-alert-triangle" style="font-size:18px;color:{pill_lb}"></i>
      <div class="score-caption" style="color:{pill_lb}">VulnSight<br>Risk Score</div>
      <div><div class="score-num" style="color:{pill_fg}">{e(risk["score"])}</div><div class="score-label" style="color:{pill_lb}">{e(risk["label"])}</div></div>
    </div>
  </div>
  <div class="acc-bar"></div>'''

    # Summary page
    def page_summary():
        # Metrics
        metrics_html = f'''      <div class="metrics">
        <div class="metric"><div class="metric-label">Unique CVEs</div><div class="metric-value">{m["unique_cves"]}</div></div>
        <div class="metric m-red"><div class="metric-label">High severity</div><div class="metric-value">{m["high_severity"]}</div></div>
        <div class="metric m-red"><div class="metric-label">Max CVSS</div><div class="metric-value">{m["max_cvss"]}</div></div>
        <div class="metric"><div class="metric-label">Avg CVSS</div><div class="metric-value">{m["avg_cvss"]}</div></div>
        <div class="metric m-{'red' if m["kev_listed"] > 0 else 'green'}"><div class="metric-label">KEV listed</div><div class="metric-value">{m["kev_listed"]}</div></div>
        <div class="metric"><div class="metric-label">Fixable</div><div class="metric-value">{m["fixable"]} / {m["unique_cves"]}</div></div>
      </div>'''

        # Legend
        sev_colors = {"Critical":"#7c2d12","High":"#dc2626","Medium":"#f97316","Low":"#22c55e","Negligible":"#94a3b8"}
        legend_items = " ".join(
            f'<span class="li"><span class="sw" style="background:{sev_colors.get(k,"#94a3b8")}"></span>{e(k)} ({v})</span>'
            for k, v in sb.items()
        )

        top_max_risk = max((c["risk"] for c in d["top_cves"]), default=1) or 1
        top_rows = []
        for c in d["top_cves"]:
            rc   = "#dc2626" if c["risk"] >= 25 else "#f97316"
            bpct = int(min(c["risk"] / top_max_risk * 100, 100))
            sbc  = SEV_BADGE.get(c["severity"],"bn")
            cvss_td = f'<td class="chv">{c["cvss"]}</td>' if c["cvss"] >= 7 else f'<td>{c["cvss"]}</td>'
            det_id = f'top-det-{e(c["id"])}'
            top_rows.append(
                f'<tr class="expandable-row">'
                f'{chevron_cell(det_id)}'
                f'<td class="cid">{e(c["id"])}</td>'
                f'{cvss_td}'
                f'<td style="color:{rc};font-weight:500">{c["risk"]}</td>'
                f'<td><span class="badge {sbc}">{e(c["severity"])}</span></td>'
                f'<td><div class="bw"><div class="bf" style="background:{rc};width:{bpct}%"></div></div></td>'
                f'<td class="nf">{"Yes" if c["fix"] else "No"}</td>'
                f'</tr>'
                + detail_row(det_id, 7, c["summary"])
            )

        # Context
        ctx_d = d["container_context"]
        tools_html = "".join(f'<span class="tag-r">{e(t)}</span>' for t in ctx_d["dangerous_tools"]) or '<span class="cv">None</span>'

        # Findings
        findings_html = "\n".join(
            f'            <div class="frow"><i class="ti {e(f["icon"])}" style="color:{e(f["color"])}"></i><span>{f["text"]}</span></div>'
            for f in d["key_findings"]
        )

        # Artifacts
        art_html = "\n".join(
            f'            <div class="art-card"><i class="ti {e(a["icon"])}"></i>'
            f'<div style="overflow:hidden"><div class="al">{e(a["label"])}</div>'
            f'<code class="ap">{e(a["path"])}</code></div></div>'
            for a in d["artifacts"]
        )

        return f'''    <div class="page active" id="page-summary">
{metrics_html}
      <div class="charts-row">
        <div class="card">
          <div class="card-head"><i class="ti ti-chart-donut"></i><span>CVE severity breakdown</span></div>
          <div class="legend">{legend_items}</div>
          <div style="position:relative;width:100%;height:190px"><canvas id="sevChart"></canvas></div>
        </div>
        <div class="card">
          <div class="card-head"><i class="ti ti-chart-bar"></i><span>VulnSight Risk Score - top 5</span></div>
          <div class="legend">
            <span class="li"><span class="sw" style="background:#dc2626"></span>High (&ge;25)</span>
            <span class="li"><span class="sw" style="background:#f97316"></span>Medium (&lt;25)</span>
          </div>
          <div style="position:relative;width:100%;height:190px"><canvas id="cvssChart"></canvas></div>
        </div>
      </div>
      <div class="two-col">
        <div class="card">
          <div class="card-head"><i class="ti ti-file-description"></i><span>Executive summary</span></div>
          <p class="sum">{highlight_summary(e(d["executive_summary"]))}</p>
        </div>
        <div class="card">
          <div class="card-head"><i class="ti ti-list-check"></i><span>Key findings</span></div>
          <div class="finds">
{findings_html}
          </div>
        </div>
      </div>
      <div class="card" style="border-left:3px solid #3b82f6;border-radius:0 12px 12px 0">
        <div class="card-head"><i class="ti ti-info-circle" style="color:#3b82f6"></i><span>About the VulnSight Risk Score</span></div>
        <p class="sum">The image-level risk score (0&ndash;100) is computed from the <strong>top 100 highest-risk CVEs</strong> in this image, then adjusted for container context (runs-as-root, end-of-life base image, SUID binaries, dangerous interactive tools). A higher score means higher prioritisation need.</p>
        <p class="sum" style="margin-top:8px">Each CVE&rsquo;s individual risk reflects six factors: its <strong>CVSS</strong> technical severity, its <strong>EPSS</strong> real-world exploit likelihood, whether it appears in the <strong>CISA KEV</strong> catalogue (active exploitation), its <strong>age</strong> since disclosure (older unpatched CVEs carry more weight), its <strong>severity tier</strong>, its <strong>CWE category</strong> (memory-corruption, injection, and auth-bypass classes carry extra weight), and whether a <strong>fix is available</strong>. Active exploitation (KEV) is the largest single contributor.</p>
        <div class="risk-legend">
          <span class="risk-tier" style="background:#f0fdf4;color:#15803d;border-color:#bbf7d0">0&ndash;19 &middot; Low</span>
          <span class="risk-tier" style="background:#fffbeb;color:#b45309;border-color:#fde68a">20&ndash;39 &middot; Medium</span>
          <span class="risk-tier" style="background:#fff7ed;color:#c2410c;border-color:#fdba74">40&ndash;69 &middot; High</span>
          <span class="risk-tier" style="background:#fef2f2;color:#b91c1c;border-color:#fecaca">70&ndash;100 &middot; Critical</span>
        </div>
      </div>
      <div class="card">
        <div class="card-head-row">
          <div class="card-head"><i class="ti ti-table"></i><span>Top contributing CVEs</span></div>
          <span class="hint">Highest impact on overall risk score</span>
        </div>
        <div class="table-wrap">
          <table style="table-layout:fixed">
            <colgroup><col style="width:4%"><col style="width:20%"><col style="width:11%"><col style="width:21%"><col style="width:14%"><col style="width:22%"><col style="width:8%"></colgroup>
            <thead><tr><th></th><th>CVE ID</th><th>CVSS</th><th>VulnSight Risk Score</th><th>Severity</th><th>Score bar</th><th>Fix</th></tr></thead>
            <tbody>
              {''.join(top_rows)}
            </tbody>
          </table>
        </div>
      </div>
      <div class="half-col">
        <div class="card">
          <div class="card-head"><i class="ti ti-container"></i><span>{subject_title} context</span></div>
          <div class="ctx"><span class="cl">Runs as root</span><span class="badge {'by' if ctx_d['runs_as_root'] else 'bg'}">{'Yes' if ctx_d['runs_as_root'] else 'No'}</span></div>
          <div class="ctx"><span class="cl">SUID binaries</span><span class="cv">{ctx_d['suid_binaries']}</span></div>
          <div class="ctx"><span class="cl">Dangerous tools</span><div>{tools_html}</div></div>
          {('' if is_host else
            '<div class="ctx"><span class="cl">Base image EOL</span>'
            '<span class="badge ' + ('by' if ctx_d['base_image_eol'] else 'bg') + '">'
            + ('Yes' if ctx_d['base_image_eol'] else 'No') + '</span></div>')}
          <div class="ctx"><span class="cl">SBOM components</span><span class="cv">{m['sbom_components']}</span></div>
          <div class="ctx"><span class="cl">Total vulnerabilities</span><span class="cv">{m['total_vulnerabilities']}</span></div>
        </div>
        <div class="card">
          <div class="card-head"><i class="ti ti-paperclip"></i><span>Artifacts &amp; references</span></div>
{art_html}
        </div>
      </div>
    </div>'''

    # CVE List Page
    def page_cve():
        return f'''    <div class="page" id="page-cve">
      <div class="card">
        <div class="card-head-row">
          <div class="card-head"><i class="ti ti-bug"></i><span>All CVEs</span></div>
          <span class="hint">Source: {e(img["sources"])}</span>
        </div>
        <div class="search-bar">
          <i class="ti ti-search" style="font-size:15px;color:#94a3b8"></i>
          <input type="text" id="cve-search" placeholder="Search CVE ID, package, severity..." oninput="filterCVEs()"/>
          <span id="cve-count" style="font-size:12px;color:#94a3b8;white-space:nowrap">{m["unique_cves"]} CVEs</span>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th></th><th>CVE ID</th><th>Package(s)</th><th>CVSS</th><th>VulnSight Risk Score</th><th>Severity</th><th>Score Bar</th><th>Fix Version</th></tr></thead>
          <tbody id="cve-tbody"></tbody></table>
        </div>
        <div class="pagination" id="cve-pagination"></div>
      </div>
    </div>'''

    # Threat Intel Page
    def page_threat():
        ti   = d["threat_intel"]
        cards = "\n".join(
            f'          <div class="ti-card">'
            f'<div class="ti-label">{e(c["label"])}</div>'
            f'<div class="ti-value"{(" style=\"color:" + c["value_color"] + "\"") if c.get("value_color") else ""}>{e(c["value"])}</div>'
            f'<div class="ti-sub">{e(c["sub"])}</div></div>'
            for c in ti["summary_cards"]
        )

        kev_block = ""
        if ti.get("kev_matches"):
            kev_rows_list = []
            for k in ti["kev_matches"]:
                det_id = f'kev-det-{e(k["id"])}'
                kev_rows_list.append(
                    f'              <tr class="expandable-row">'
                    f'{chevron_cell(det_id)}'
                    f'<td class="cid">{e(k["id"])}</td>'
                    f'<td class="chv">{k["cvss"]}</td>'
                    f'<td class="epss-hi">{k["epss"]}</td>'
                    f'<td>{e(k["cwe"])}</td>'
                    f'<td>{"<span class=\"badge bl\">Yes</span>" if k["fix"] else "<span class=\"badge by\">No</span>"}</td>'
                    f'</tr>'
                    + detail_row(det_id, 6, k["description"] or "")
                )
            kev_rows = "\n".join(kev_rows_list)
            kev_block = f'''      <div class="card">
        <div class="card-head-row">
          <div class="card-head"><i class="ti ti-flame" style="color:#dc2626"></i><span>CISA Known Exploited Vulnerabilities</span></div>
          <span class="hint">{len(ti["kev_matches"])} CVE(s) actively exploited in the wild</span>
        </div>
        <div class="table-wrap">
          <table style="table-layout:fixed">
            <colgroup>
              <col style="width:4%"><col style="width:24%"><col style="width:14%"><col style="width:16%">
              <col style="width:24%"><col style="width:18%">
            </colgroup>
            <thead><tr><th></th><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>CWE</th><th>Fix</th></tr></thead>
            <tbody>{kev_rows}</tbody>
          </table>
        </div>
      </div>
'''

        def _per_cve_threat_rows(rows_list, table_kind):
            """Build rows for the EPSS- or CVSS-sorted per-CVE threat tables."""
            out = []
            for c in rows_list:
                det_id = f'{table_kind}-det-{e(c["id"])}'
                if table_kind == "epss":
                    # EPSS-sorted: EPSS column highlighted, CVSS plain
                    score_cells = (
                        f'<td class="epss-hi">{c["epss"]}</td>'
                        f'<td>{c["cvss"]}</td>'
                    )
                else:
                    # CVSS-sorted: CVSS column highlighted, EPSS plain
                    score_cells = (
                        f'<td class="chv">{c["cvss"]}</td>'
                        f'<td>{c["epss"]}</td>'
                    )
                out.append(
                    f'              <tr class="expandable-row">'
                    f'{chevron_cell(det_id)}'
                    f'<td class="cid">{e(c["id"])}</td>'
                    f'{score_cells}'
                    f'<td><span class="badge {"bg" if not c["kev"] else "bh"}">{"No" if not c["kev"] else "Yes"}</span></td>'
                    f'<td>{e(c["cwe"])}</td>'
                    f'<td>{c["age"]}</td>'
                    f'</tr>'
                    + detail_row(det_id, 7, c["nvd_summary"] or "")
                )
            return "\n".join(out)

        epss_rows = _per_cve_threat_rows(ti["per_cve_epss"], "epss")
        cvss_rows = _per_cve_threat_rows(ti["per_cve_cvss"], "cvss")

        per_cve_colgroup = '''<colgroup>
              <col style="width:4%"><col style="width:18%"><col style="width:14%"><col style="width:14%">
              <col style="width:10%"><col style="width:22%"><col style="width:18%">
            </colgroup>'''

        return f'''    <div class="page" id="page-threat">
      <div class="card">
        <div class="card-head"><i class="ti ti-radar"></i><span>Threat intelligence details</span></div>
        <p style="font-size:13px;color:#64748b;margin-bottom:16px">Source: threat_intel.json &middot; Enriched from NVD, EPSS, and CISA KEV</p>
        <div class="ti-grid">{cards}</div>
      </div>
{kev_block}      <div class="card">
        <div class="card-head"><i class="ti ti-table"></i><span>Per-CVE threat details (top 10 by EPSS)</span></div>
        <div class="table-wrap">
          <table style="table-layout:fixed">
            {per_cve_colgroup}
            <thead><tr><th></th><th>CVE ID</th><th>EPSS</th><th>CVSS</th><th>KEV</th><th>CWE</th><th>Age (days)</th></tr></thead>
            <tbody>{epss_rows}</tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><i class="ti ti-table"></i><span>Per-CVE threat details (top 10 by CVSS)</span></div>
        <div class="table-wrap">
          <table style="table-layout:fixed">
            {per_cve_colgroup}
            <thead><tr><th></th><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>CWE</th><th>Age (days)</th></tr></thead>
            <tbody>{cvss_rows}</tbody>
          </table>
        </div>
      </div>
    </div>'''

    # SBOM Page
    def page_sbom():
        return f'''    <div class="page" id="page-sbom">
      <div class="card">
        <div class="card-head-row">
          <div class="card-head"><i class="ti ti-file-code"></i><span>SBOM viewer</span></div>
          <span class="hint">Source: sbom.json &middot; {m["sbom_components"]} components</span>
        </div>
        <div class="search-bar">
          <i class="ti ti-search" style="font-size:15px;color:#94a3b8"></i>
          <input type="text" id="sbom-search" placeholder="Search package, version, license, path..." oninput="filterSBOM()"/>
          <span id="sbom-count" style="font-size:12px;color:#94a3b8;white-space:nowrap">{m["sbom_components"]} packages</span>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>License</th><th>CVEs</th><th>Path</th></tr></thead>
          <tbody id="sbom-tbody"></tbody></table>
        </div>
        <div class="pagination" id="sbom-pagination"></div>
      </div>
    </div>'''

    # Remediations Page
    def page_remed():
        rem = d["remediations"]
        def action_detail(a):
            detail_html = f'<div style="font-size:12px;opacity:0.8">{a["detail"]}</div>' if a["detail"] else ""
            title_html = e(a["title"]).replace("\n", "<br>")
            return (
                f'          <div class="ri {e(a["class"])}">'
                f'<i class="ti {e(a["icon"])}"></i>'
                f'<div><div style="font-weight:500;margin-bottom:3px">{title_html}</div>'
                f'{detail_html}'
                f'</div></div>'
            )
        actions_html = "\n".join(action_detail(a) for a in rem["actions"])

        pm_html = "\n".join(
            f'            <div class="pm-chip" style="background:{p["bg"]};border-color:{p["border"]}">'
            f'<span class="pm-dot" style="background:{p["color"]}"></span>'
            f'<span class="pm-key" style="color:{p["color"]}">{e(p["key"])}</span>'
            f'<span class="pm-label">{e(p["label"])}</span>'
            f'<span class="pm-count">{p["count"]}</span>'
            f'</div>'
            for p in rem["priority_matrix"]
        )
        return f'''    <div class="page" id="page-remed">
      <div class="card" style="border-left:3px solid #dc2626;border-radius:0 12px 12px 0">
        <div class="card-head"><i class="ti ti-sparkles" style="color:#f97316"></i><span>Summary</span></div>
        <p class="sum">{highlight_summary(e(rem["ai_summary"]))}</p>
      </div>
      <div class="card">
        <div class="card-head-row">
          <div class="card-head"><i class="ti ti-list-numbers"></i><span>Recommendations</span></div>
          <span class="hint">Color indicates priority (see legend below)</span>
        </div>
        <div class="remed">{actions_html}</div>
      </div>
      <div class="pm-card">
        <span class="pm-title"><i class="ti ti-checklist"></i> Priority legend</span>
        <div class="pm-row">
{pm_html}
        </div>
      </div>
    </div>'''

    # Javascript
    def javascript():
        sev_colors_map = {"Critical":"#7c2d12","High":"#dc2626","Medium":"#f97316","Low":"#22c55e","Negligible":"#94a3b8"}
        sev_labels = list(sb.keys())
        sev_values = list(sb.values())
        sev_bg     = [sev_colors_map.get(k,"#94a3b8") for k in sev_labels]

        # Top 5 by VulnSight Risk Score
        top5_src = d["top_cves"][:5] if d.get("top_cves") else sorted(
            d["cve_list"], key=lambda x: x["risk"], reverse=True
        )[:5]
        c2_labels = [c["id"] for c in top5_src]
        c2_values = [c["risk"] for c in top5_src]
        c2_colors = ["#dc2626" if c["risk"] >= 25 else "#f97316" for c in top5_src]
        c2_max    = max(c2_values + [1])

        def _js_safe(payload):
            return (payload
                    .replace("</", "<\\/")
                    .replace("<!--", "<\\!--")
                    .replace("-->", "--\\>"))

        cve_js  = _js_safe(json.dumps([{"id":c["id"],"cvss":c["cvss"],
                                "risk":c["risk"],"sev":c["severity"],"fix":c["fix"],
                                "fixv":c["fix_version"],"pkgs":c["packages"],
                                "desc":c["description"] or ""}
                               for c in d["cve_list"]], ensure_ascii=False))
        # max risk for score-bar normalisation on the CVE list page
        cve_max_risk = max((c["risk"] for c in d["cve_list"]), default=1) or 1
        sbom_js = _js_safe(json.dumps([{"pkg":s["pkg"],"ver":s["ver"],"type":s["type"],
                                "lic":s["lic"],"path":s["path"],"cves":s["cve_count"]}
                               for s in d["sbom"]], ensure_ascii=False))

        return f'''<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
const pageTitles={{
  summary:'{subject_title} Security Report - {img["name"]}',
  cve:'CVE List - {m["unique_cves"]} Vulnerabilities',
  threat:'Threat Intelligence Details',
  sbom:'SBOM Viewer - {m["sbom_components"]} Components',
  remed:'Remediation Plan'
}};
function showPage(id,btn){{
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('topbar-title').textContent=pageTitles[id]||id;
}}
function toggleCveDetail(btn,id){{
  const row=document.getElementById(id);
  if(!row) return;
  const expanded=btn.getAttribute('aria-expanded')==='true';
  btn.setAttribute('aria-expanded',expanded?'false':'true');
  row.classList.toggle('show',!expanded);
}}
// Clicking anywhere on an expandable row (except its chevron, which has its
// own handler) also toggles the detail row. event.stopPropagation on the
// chevron prevents double-toggle.
document.addEventListener('click',function(e){{
  const row=e.target.closest('.expandable-row');
  if(!row) return;
  if(e.target.closest('.chev')) return;
  const chev=row.querySelector('.chev');
  if(chev) toggleCveDetail(chev,chev.getAttribute('aria-controls'));
}});
const gc='rgba(0,0,0,0.06)',tc='#94a3b8';
new Chart(document.getElementById('sevChart'),{{
  type:'doughnut',
  data:{{labels:{json.dumps(sev_labels)},datasets:[{{data:{json.dumps(sev_values)},backgroundColor:{json.dumps(sev_bg)},borderWidth:2,borderColor:'#fff',hoverOffset:6}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'66%',plugins:{{legend:{{display:false}},tooltip:{{backgroundColor:'#1e293b',titleColor:'#f1f5f9',bodyColor:'#94a3b8'}}}}}}
}});
new Chart(document.getElementById('cvssChart'),{{
  type:'bar',
  data:{{labels:{json.dumps(c2_labels)},datasets:[{{label:'VulnSight Risk Score',data:{json.dumps(c2_values)},backgroundColor:{json.dumps(c2_colors)},borderRadius:4,borderWidth:0}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    scales:{{x:{{min:0,max:{c2_max + 5},grid:{{color:gc}},ticks:{{font:{{size:11}},color:tc}},border:{{color:'transparent'}}}},
             y:{{grid:{{display:false}},ticks:{{font:{{size:10}},color:tc}},border:{{color:'transparent'}}}}}},
    plugins:{{legend:{{display:false}},tooltip:{{backgroundColor:'#1e293b',titleColor:'#f1f5f9',bodyColor:'#94a3b8'}}}}}}
}});
const sevColor={{Critical:'bh',High:'bh',Medium:'bm',Low:'bl',Negligible:'bn'}};
const allCVEs={cve_js};
const cveMaxRisk={cve_max_risk};
// Sort by VulnSight Risk Score descending so highest-priority CVEs land first.
allCVEs.sort((a,b)=>b.risk-a.risk);
let cvePage=1,cvePageSize=15,filteredCVEs=[...allCVEs];
function esc(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
function renderCVEPage(){{
  const tbody=document.getElementById('cve-tbody');
  const slice=filteredCVEs.slice((cvePage-1)*cvePageSize,cvePage*cvePageSize);
  tbody.innerHTML=slice.map(c=>{{
    const barColor=c.risk>=25?'#dc2626':(c.risk>=10?'#f97316':'#94a3b8');
    const barPct=Math.min(100,Math.round(c.risk/cveMaxRisk*100));
    const fixCell=c.fix
      ?`<span class="mono" style="font-size:11px;color:#15803d">${{c.fixv||'Yes'}}</span>`
      :`<span class="badge bn">None</span>`;
    const detId=`cve-det-${{c.id}}`;
    const chev=`<td style="width:32px;padding-right:0"><button class="chev" type="button" aria-expanded="false" aria-controls="${{detId}}" onclick="toggleCveDetail(this,'${{detId}}');event.stopPropagation()"><svg width="12" height="12" viewBox="0 0 12 12" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M4 2 L8 6 L4 10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button></td>`;
    return `<tr class="expandable-row">
    ${{chev}}
    <td class="cid">${{c.id}}</td>
    <td style="font-size:11px;color:#64748b">${{c.pkgs||'-'}}</td>
    <td style="${{c.cvss>=7?'color:#dc2626;font-weight:500':''}}">${{c.cvss.toFixed(1)}}</td>
    <td style="color:${{c.risk>=25?'#dc2626':'#f97316'}};font-weight:500">${{c.risk.toFixed(1)}}</td>
    <td><span class="badge ${{sevColor[c.sev]||'bn'}}">${{c.sev}}</span></td>
    <td><div class="bw"><div class="bf" style="background:${{barColor}};width:${{barPct}}%"></div></div></td>
    <td>${{fixCell}}</td>
  </tr>
  <tr class="detail-row" id="${{detId}}"><td colspan="8"><div class="detail-inner"><div class="detail-label">CVE Summary</div>${{esc(c.desc)||'(no description available)'}}</div></td></tr>`;}}).join('');
  renderCVEPagination();
}}
function renderCVEPagination(){{
  const total=Math.ceil(filteredCVEs.length/cvePageSize);
  document.getElementById('cve-count').textContent=filteredCVEs.length+' CVEs';
  let html=`<span>Page ${{cvePage}} of ${{total}}</span>`;
  for(let i=1;i<=total;i++) html+=`<button class="page-btn ${{i===cvePage?'active-pg':''}}" onclick="cvePage=${{i}};renderCVEPage()">${{i}}</button>`;
  document.getElementById('cve-pagination').innerHTML=html;
}}
function filterCVEs(){{
  const q=document.getElementById('cve-search').value.toLowerCase();
  filteredCVEs=allCVEs.filter(c=>
    c.id.toLowerCase().includes(q)
    ||c.sev.toLowerCase().includes(q)
    ||(c.pkgs||'').toLowerCase().includes(q)
    ||(c.desc||'').toLowerCase().includes(q));
  cvePage=1; renderCVEPage();
}}
const typeColor={{deb:'#3b82f6',python:'#8b5cf6',binary:'#f97316',npm:'#16a34a',gem:'#dc2626'}};
const typeBg={{deb:'#eff6ff',python:'#f5f3ff',binary:'#fff7ed',npm:'#f0fdf4',gem:'#fef2f2'}};
const sbomData={sbom_js};
let sbomPage=1,sbomPageSize=15,filteredSBOM=[...sbomData];
function renderSBOMPage(){{
  const tbody=document.getElementById('sbom-tbody');
  const slice=filteredSBOM.slice((sbomPage-1)*sbomPageSize,sbomPage*sbomPageSize);
  tbody.innerHTML=slice.map(p=>{{
    const cveCell=p.cves>0
      ?`<span class="badge ${{p.cves>=10?'bh':'bm'}}">${{p.cves}}</span>`
      :`<span class="badge bg">0</span>`;
    return `<tr>
    <td style="font-weight:500;color:#0f172a">${{p.pkg}}</td>
    <td class="mono" style="font-size:12px">${{p.ver}}</td>
    <td><span class="badge" style="background:${{typeBg[p.type]||'#f1f5f9'}};color:${{typeColor[p.type]||'#475569'}}">${{p.type}}</span></td>
    <td style="font-size:12px;color:#64748b">${{p.lic}}</td>
    <td>${{cveCell}}</td>
    <td class="mono" style="font-size:11px;color:#94a3b8;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${{p.path}}</td>
  </tr>`;}}).join('');
  renderSBOMPagination();
}}
function renderSBOMPagination(){{
  const total=Math.ceil(filteredSBOM.length/sbomPageSize);
  document.getElementById('sbom-count').textContent=filteredSBOM.length+' packages';
  let html=`<span>Page ${{sbomPage}} of ${{total}}</span>`;
  for(let i=1;i<=total;i++) html+=`<button class="page-btn ${{i===sbomPage?'active-pg':''}}" onclick="sbomPage=${{i}};renderSBOMPage()">${{i}}</button>`;
  document.getElementById('sbom-pagination').innerHTML=html;
}}
function filterSBOM(){{
  const q=document.getElementById('sbom-search').value.toLowerCase();
  filteredSBOM=sbomData.filter(p=>
    p.pkg.toLowerCase().includes(q)
    ||p.ver.toLowerCase().includes(q)
    ||p.lic.toLowerCase().includes(q)
    ||p.type.toLowerCase().includes(q)
    ||(p.path||'').toLowerCase().includes(q));
  sbomPage=1; renderSBOMPage();
}}
renderCVEPage(); renderSBOMPage();
</script>'''

    # Assemble
    favicon_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="7" fill="#1e293b"/>'
        '<circle cx="16" cy="17" r="9" fill="none" stroke="#f87171" stroke-width="2.2"/>'
        '<line x1="16" y1="5" x2="16" y2="9" stroke="#f87171" stroke-width="2.2" stroke-linecap="round"/>'
        '<line x1="16" y1="25" x2="16" y2="29" stroke="#f87171" stroke-width="2.2" stroke-linecap="round"/>'
        '<line x1="3" y1="17" x2="7" y2="17" stroke="#f87171" stroke-width="2.2" stroke-linecap="round"/>'
        '<line x1="25" y1="17" x2="29" y2="17" stroke="#f87171" stroke-width="2.2" stroke-linecap="round"/>'
        '<circle cx="23" cy="10" r="3.5" fill="#fbbf24"/>'
        '</svg>'
    )
    favicon_uri = "data:image/svg+xml;utf8," + favicon_svg.replace("#", "%23")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{e(app["name"])} - {e(img["name"])}</title>
<link rel="icon" type="image/svg+xml" href="{favicon_uri}"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css"/>
{CSS}
</head>
<body>
{sidebar()}
<div class="main">
{topbar()}
  <div class="content">
{page_summary()}
{page_cve()}
{page_threat()}
{page_sbom()}
{page_remed()}
  </div>
</div>
{javascript()}
</body>
</html>"""

#  PRINT / PDF VARIANT

def build_print_html(d):
    m       = d["metrics"]
    risk    = d["risk"]
    img     = d["image"]
    app     = d["app"]
    ti      = d["threat_intel"]
    sb      = d["severity_breakdown"]
    ctx_d   = d["container_context"]
    sbom    = d["sbom"]
    cve_list = d["cve_list"]
    rem      = d["remediations"]
    artifacts = d["artifacts"]

    is_host = d.get("mode") == "host"
    subject_title = "System" if is_host else "Container"
    subject_lower = "system" if is_host else "container"

    rl = (risk.get("label","") or "").lower()
    if   "critical" in rl: pill_bg, pill_bd, pill_fg = "#fef2f2", "#fca5a5", "#b91c1c"
    elif "high"     in rl: pill_bg, pill_bd, pill_fg = "#fff7ed", "#fdba74", "#c2410c"
    elif "medium"   in rl: pill_bg, pill_bd, pill_fg = "#fefce8", "#fde047", "#a16207"
    elif "low"      in rl: pill_bg, pill_bd, pill_fg = "#f0fdf4", "#86efac", "#166534"
    else:                  pill_bg, pill_bd, pill_fg = "#f1f5f9", "#cbd5e1", "#334155"

    def severity_donut_svg(breakdown):
        """SVG donut for severity breakdown. ~140px square."""
        sev_colors = {"Critical":"#dc2626","High":"#ef4444","Medium":"#f97316",
                      "Low":"#22c55e","Negligible":"#94a3b8"}
        total = sum(breakdown.values()) or 1
        cx, cy, r, stroke = 70, 70, 50, 22
        circumference = 2 * 3.14159265 * r
        offset = 0
        segments = []
        for sev, count in breakdown.items():
            if count == 0: continue
            pct = count / total
            seg_len = circumference * pct
            gap = circumference - seg_len
            color = sev_colors.get(sev, "#94a3b8")
            segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
                f'stroke-width="{stroke}" stroke-dasharray="{seg_len:.2f} {gap:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += seg_len
        seg_html = "".join(segments)
        return (
            f'<svg viewBox="0 0 140 140" width="140" height="140" xmlns="http://www.w3.org/2000/svg" '
            f'role="img" aria-label="Severity breakdown donut">'
            f'{seg_html}'
            f'<text x="70" y="68" text-anchor="middle" font-size="22" font-weight="500" fill="#0f172a">{total}</text>'
            f'<text x="70" y="84" text-anchor="middle" font-size="9" fill="#64748b" letter-spacing="0.5">UNIQUE CVES</text>'
            f'</svg>'
        )

    def top5_risk_bars_svg(top_cves):
        """Horizontal bar chart of top-5 contributing CVEs by VulnSight Risk Score."""
        items = top_cves[:5]
        if not items:
            return '<div style="color:#94a3b8;font-size:11px">No CVE risk data</div>'
        max_risk = max((c["risk"] for c in items), default=1) or 1
        row_h = 24
        chart_h = row_h * len(items) + 8
        rows = []
        for i, c in enumerate(items):
            y = i * row_h + 4
            pct = c["risk"] / max_risk
            bar_w = int(220 * pct)
            color = "#dc2626" if c["risk"] >= 25 else "#f97316"
            rows.append(
                f'<text x="0" y="{y+13}" font-size="10" fill="#334155" font-family="ui-monospace,monospace">{e(c["id"])}</text>'
                f'<rect x="110" y="{y+4}" width="{bar_w}" height="14" fill="{color}" rx="2"/>'
                f'<text x="{110+bar_w+6}" y="{y+15}" font-size="10" fill="#0f172a" font-weight="500">{c["risk"]}</text>'
            )
        return (
            f'<svg viewBox="0 0 380 {chart_h}" width="380" height="{chart_h}" '
            f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Top 5 CVEs by VulnSight Risk Score">'
            f'{"".join(rows)}</svg>'
        )

    # Logomark for the cover page
    cover_logomark = (
        '<svg width="64" height="64" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="16" cy="16" r="11" fill="none" stroke="#dc2626" stroke-width="1.8"/>'
        '<line x1="16" y1="3" x2="16" y2="7" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="16" y1="25" x2="16" y2="29" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="3" y1="16" x2="7" y2="16" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="25" y1="16" x2="29" y2="16" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round"/>'
        '<circle cx="24" cy="8" r="3.2" fill="#d97706"/>'
        '</svg>'
    )

    # Severity Legend
    sev_colors_hex = {"Critical":"#7c2d12","High":"#dc2626","Medium":"#f97316","Low":"#22c55e","Negligible":"#94a3b8"}
    legend_items = " ".join(
        f'<span class="li"><span class="sw" style="background:{sev_colors_hex.get(k,"#94a3b8")}"></span>{e(k)} ({v})</span>'
        for k, v in sb.items()
    )

    # Section: Cover page
    cover_section = f'''<section class="cover">
  <div class="cover-logo">{cover_logomark}</div>
  <div class="cover-brand">Vuln<span class="brand-accent">Sight</span></div>
  <div class="cover-tagline">{subject_title} Security Report</div>
  <div class="cover-image">{e(img["name"])}</div>
  <div class="cover-digest">{e(img["digest"])}</div>
  <div class="cover-score-pill" style="background:{pill_bg};border-color:{pill_bd}">
    <div class="cover-score-caption" style="color:{pill_fg};opacity:0.75">VulnSight Risk Score</div>
    <div class="cover-score-num" style="color:{pill_fg}">{e(risk["score"])}</div>
    <div class="cover-score-label" style="color:{pill_fg}">{e(risk["label"].replace(" risk", "").upper())}</div>
  </div>
  <div class="cover-meta">
    <div><span class="cover-meta-label">Scanned</span> {e(img["scan_date"])} at {e(img["scan_time"])}</div>
    <div>{m["unique_cves"]} unique CVEs &middot; {m["sbom_components"]} packages</div>
  </div>
  <div class="cover-credit">Built by <strong>Venkata Sai Nataraja Vamsi Krishna Palaparty</strong></div>
</section>'''

    # Section: Executive Summary + Methodology
    exec_section = f'''<section class="page">
  <h1>Executive summary</h1>
  <p class="prose">{highlight_summary(e(d["executive_summary"]))}</p>

  <h2>Risk methodology</h2>
  <p class="prose">The <strong>VulnSight Risk Score</strong> aggregates the top 100 highest-risk CVEs into a normalized 0&ndash;100 score. Each CVE's contribution combines six factors:</p>
  <ul class="prose">
    <li><strong>CVSS base score</strong> - baseline severity rating from NVD</li>
    <li><strong>EPSS</strong> - predicted probability of exploitation within the next 30 days</li>
    <li><strong>KEV status</strong> - flagged in the CISA Known Exploited Vulnerabilities catalog</li>
    <li><strong>Age</strong> - older unpatched CVEs accrue additional risk over time</li>
    <li><strong>Severity tier</strong> - Critical, High, Medium, or Low classification</li>
    <li><strong>CWE category</strong> - weakness type, weighted by exploitability and impact</li>
    <li><strong>Fix availability</strong> - CVEs with a published fix carry additional weight, since they represent actionable, prioritized work for the team</li>
  </ul>
  <p class="prose">Container context further adjusts the score: running as root, an end-of-life base image, SUID binaries, and exposed dangerous tools each raise the final number. Risk tiers are: <strong style="color:#22c55e">0&ndash;19 Low</strong>, <strong style="color:#eab308">20&ndash;39 Medium</strong>, <strong style="color:#f97316">40&ndash;69 High</strong>, <strong style="color:#dc2626">70+ Critical</strong>.</p>
</section>'''

    # Section: Risk Overview 
    risk_overview_section = f'''<section class="page">
  <h1>Risk overview</h1>
  <div class="metrics">
    <div class="metric"><div class="metric-label">Unique CVEs</div><div class="metric-value">{m["unique_cves"]}</div></div>
    <div class="metric"><div class="metric-label">High severity</div><div class="metric-value" style="color:#dc2626">{m["high_severity"]}</div></div>
    <div class="metric"><div class="metric-label">Max CVSS</div><div class="metric-value" style="color:#dc2626">{m["max_cvss"]}</div></div>
    <div class="metric"><div class="metric-label">Avg CVSS</div><div class="metric-value">{m["avg_cvss"]}</div></div>
    <div class="metric"><div class="metric-label">KEV listed</div><div class="metric-value" style="color:{'#dc2626' if m['kev_listed']>0 else '#22c55e'}">{m["kev_listed"]}</div></div>
    <div class="metric"><div class="metric-label">Fixable</div><div class="metric-value">{m["fixable"]} / {m["unique_cves"]}</div></div>
  </div>

  <div class="two-col">
    <div class="card">
      <h3>Severity breakdown</h3>
      <div style="display:flex;justify-content:center;margin:8px 0">{severity_donut_svg(sb)}</div>
      <div class="legend">{legend_items}</div>
    </div>
    <div class="card">
      <h3>Top 5 CVEs by VulnSight Risk Score</h3>
      <div style="margin-top:8px">{top5_risk_bars_svg(d["top_cves"])}</div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3>{subject_title} context</h3>
    <table class="kv">
      <tr><td>Runs as root</td><td>{"Yes" if ctx_d.get("runs_as_root") else "No"}</td></tr>
      {'' if is_host else f'<tr><td>Base image EOL</td><td>{"Yes - security updates may not be available" if ctx_d.get("base_image_eol") else "Supported"}</td></tr>'}
      <tr><td>SUID binaries</td><td>{ctx_d.get("suid_binaries", 0)}</td></tr>
      <tr><td>Dangerous tools</td><td>{", ".join(ctx_d.get("dangerous_tools", [])) or "None detected"}</td></tr>
    </table>
  </div>
</section>'''

    # Section: Top 20 Contributing CVEs
    top_cves_full = sorted(cve_list, key=lambda c: c["risk"], reverse=True)[:20]
    top_rows = []
    for c in top_cves_full:
        sev_color = sev_colors_hex.get(c["severity"], "#94a3b8")
        risk_color = "#dc2626" if c["risk"] >= 25 else "#f97316"
        top_rows.append(
            f'<tr class="cve-row">'
            f'<td class="mono">{e(c["id"])}</td>'
            f'<td>{c["cvss"]}</td>'
            f'<td style="color:{risk_color};font-weight:500">{c["risk"]}</td>'
            f'<td><span class="sev-pill" style="background:{sev_color};color:#fff">{e(c["severity"])}</span></td>'
            f'<td>{"Yes" if c["fix"] else "No"}</td>'
            f'</tr>'
            f'<tr class="cve-detail-row"><td colspan="5"><div class="cve-summary-inline">{e(c["description"] or "(no description available)")}</div></td></tr>'
        )
    top_cves_section = f'''<section class="page">
  <h1>Top 20 CVEs by VulnSight Risk Score</h1>
  <p class="prose-small">Showing the 20 highest-contributing CVEs out of {m["unique_cves"]} total. Complete CVE list available in the HTML report.</p>
  <table class="cve-table">
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>VulnSight Risk</th><th>Severity</th><th>Fix</th></tr></thead>
    <tbody>{"".join(top_rows)}</tbody>
  </table>
</section>'''

    # CISA KEV
    kev_section = ""
    if ti.get("kev_matches"):
        kev_rows = []
        for k in ti["kev_matches"]:
            kev_rows.append(
                f'<tr class="cve-row">'
                f'<td class="mono">{e(k["id"])}</td>'
                f'<td>{k["cvss"]}</td>'
                f'<td>{k["epss"]}</td>'
                f'<td>{e(k["cwe"])}</td>'
                f'<td>{"Yes" if k["fix"] else "No"}</td>'
                f'</tr>'
                f'<tr class="cve-detail-row"><td colspan="5"><div class="cve-summary-inline">{e(k["description"] or "")}</div></td></tr>'
            )
        kev_section = f'''<section class="page">
  <h1>CISA Known Exploited Vulnerabilities</h1>
  <p class="prose-small"><strong>{len(ti["kev_matches"])}</strong> CVE(s) on the CISA KEV catalog - actively exploited in the wild and require immediate attention.</p>
  <table class="cve-table">
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>CWE</th><th>Fix</th></tr></thead>
    <tbody>{"".join(kev_rows)}</tbody>
  </table>
</section>'''

    # Section: Threat Intel (EPSS + CVSS top 10 each)
    def _ti_rows(items, primary_key):
        rows = []
        for c in items:
            if primary_key == "epss":
                primary_cell = f'<td style="font-weight:500">{c["epss"]}</td><td>{c["cvss"]}</td>'
            else:
                primary_cell = f'<td style="font-weight:500;color:#dc2626">{c["cvss"]}</td><td>{c["epss"]}</td>'
            rows.append(
                f'<tr class="cve-row">'
                f'<td class="mono">{e(c["id"])}</td>'
                f'{primary_cell}'
                f'<td>{"Yes" if c["kev"] else "No"}</td>'
                f'<td>{e(c["cwe"])}</td>'
                f'<td>{c["age"]}</td>'
                f'</tr>'
                f'<tr class="cve-detail-row"><td colspan="6"><div class="cve-summary-inline">{e(c["nvd_summary"] or "")}</div></td></tr>'
            )
        return "".join(rows)
    threat_section = f'''<section class="page">
  <h1>Threat intelligence</h1>
  <h2 class="table-section">Top 10 by EPSS - exploitation probability</h2>
  <table class="cve-table">
    <thead><tr><th>CVE ID</th><th>EPSS</th><th>CVSS</th><th>KEV</th><th>CWE</th><th>Age</th></tr></thead>
    <tbody>{_ti_rows(ti["per_cve_epss"], "epss")}</tbody>
  </table>
  <h2 class="table-section" style="margin-top:24px">Top 10 by CVSS - severity</h2>
  <table class="cve-table">
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>CWE</th><th>Age</th></tr></thead>
    <tbody>{_ti_rows(ti["per_cve_cvss"], "cvss")}</tbody>
  </table>
</section>'''

    # Section: Top 20 packages by CVE count
    from collections import Counter
    pkg_cve_count = Counter()
    pkg_fix_versions = {}
    for c in cve_list:
        pkgs_str = c.get("packages", "") or ""
        if pkgs_str:
            primary = pkgs_str.split(",")[0].split("(")[0].strip()
            if primary and primary != "-":
                pkg_cve_count[primary] += 1
                if c.get("fix") and c.get("fix_version") and primary not in pkg_fix_versions:
                    pkg_fix_versions[primary] = c["fix_version"]
    top_packages = pkg_cve_count.most_common(20)
    pkg_rows = []
    for pkg, count in top_packages:
        if "@" in pkg:
            pkg_name, _, pkg_ver = pkg.partition("@")
        else:
            pkg_name, pkg_ver = pkg, ""
        pkg_cell = f'<span class="mono">{e(pkg_name)}</span>'
        if pkg_ver:
            pkg_cell += f'<span style="color:#94a3b8;font-size:9.5px;margin-left:6px">{e(pkg_ver)}</span>'

        fix_v = pkg_fix_versions.get(pkg)
        if fix_v:
            fix_cell = f'<span class="mono" style="font-size:10px;color:#15803d">{e(fix_v)}</span>'
        else:
            fix_cell = '<span style="font-size:10px;color:#94a3b8;font-style:italic">no upstream fix</span>'

        pkg_rows.append(
            f'<tr><td>{pkg_cell}</td>'
            f'<td>{count}</td>'
            f'<td>{fix_cell}</td></tr>'
        )
    packages_section = f'''<section class="page">
  <h1>Top 20 affected packages</h1>
  <p class="prose-small">Ranked by number of CVEs affecting each package. Complete component list ({m["sbom_components"]} packages) available in the HTML report's SBOM Viewer.</p>
  <table class="cve-table">
    <thead><tr><th>Package</th><th>CVE count</th><th>Suggested fix version</th></tr></thead>
    <tbody>{"".join(pkg_rows)}</tbody>
  </table>
</section>'''

    # Section: Remediation plan
    priority_order = ["P1", "P2", "P3", "P4"]
    priority_labels = {"P1": "P1 - Critical", "P2": "P2 - High",
                       "P3": "P3 - Medium", "P4": "P4 - Low"}
    priority_colors = {"P1": "#dc2626", "P2": "#f97316", "P3": "#eab308", "P4": "#22c55e"}
    actions_by_bucket = {p: [] for p in priority_order}
    for a in rem.get("actions", []):
        bucket = (a.get("priority", "") or "")[:2]
        if bucket in actions_by_bucket:
            actions_by_bucket[bucket].append(a)

    rem_html_parts = [f'<p class="prose">{highlight_summary(e(rem.get("ai_summary", "")))}</p>']
    # Priority matrix indicator strip
    matrix_chips = []
    for p in priority_order:
        items = actions_by_bucket.get(p, [])
        label_text = priority_labels[p].replace(f"{p} - ", "")
        matrix_chips.append(
            f'<div class="pm-card" style="border-left:3px solid {priority_colors[p]}">'
            f'<span class="pm-key" style="color:{priority_colors[p]}">{p}</span>'
            f'<span class="pm-label">{label_text}</span>'
            f'<span class="pm-count">{len(items)}</span>'
            f'</div>'
        )
    rem_html_parts.append(f'<div class="pm-grid">{"".join(matrix_chips)}</div>')

    for p in priority_order:
        items = actions_by_bucket.get(p, [])
        if not items: continue
        rec_items_html = "".join(
            f'<li><strong>{e(a.get("title","")).replace(chr(10), "<br>")}</strong>'
            + (f': {e(a.get("detail",""))}' if a.get("detail") else "")
            + '</li>' for a in items
        )
        rem_html_parts.append(
            f'<h3 style="color:{priority_colors[p]};margin-top:14px">{priority_labels[p]}</h3>'
            f'<ul class="prose">{rec_items_html}</ul>'
        )
    rem_section = f'''<section class="page">
  <h1>Remediation plan</h1>
  {"".join(rem_html_parts)}
</section>'''

    # Print-tuned CSS
    PRINT_CSS = """<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:11px;line-height:1.5;color:#0f172a;background:#fff;padding:0}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px}
/* Headings — uniform sizes across the document. h1 is page title,
   h2 is section divider, h3 is card/table sub-label. All weight 600
   for a clear hierarchy that reads as "real document," not "draft." */
h1{font-size:19px;font-weight:600;margin:0 0 14px 0;color:#0f172a;letter-spacing:-0.01em}
h2{font-size:13.5px;font-weight:600;margin:18px 0 8px;color:#0f172a;letter-spacing:-0.005em}
h2.table-section{font-size:13.5px;font-weight:600;color:#0f172a;margin:18px 0 8px;padding:0;background:none;border-left:none}
h3{font-size:12px;font-weight:600;margin:0 0 6px;color:#1e293b}
section.page{padding:30px 36px;page-break-before:always;page-break-after:auto;page-break-inside:auto}
section.page:first-of-type{page-break-before:auto}
.prose{font-size:11px;line-height:1.6;color:#1e293b;margin-bottom:8px}
.prose-small{font-size:10.5px;line-height:1.5;color:#64748b;margin-bottom:12px}
.prose ul,ul.prose{padding-left:18px;margin:8px 0}
.prose li{margin-bottom:3px}
table.cve-table{width:100%;border-collapse:collapse;margin-top:6px;font-size:10.5px}
table.cve-table th{text-align:left;padding:6px 8px;border-bottom:1.5px solid #94a3b8;color:#0f172a;font-weight:600;font-size:9.5px;text-transform:uppercase;letter-spacing:0.05em;background:#f1f5f9}
table.cve-table td{padding:5px 8px;border-bottom:0.5px solid #e2e8f0;vertical-align:top}
.cve-row td{font-weight:500}
.cve-detail-row td{padding:0 8px 8px 8px;border-bottom:0.5px solid #e2e8f0}
.cve-summary-inline{font-size:10px;color:#475569;line-height:1.45;padding:4px 8px 4px 12px;border-left:2px solid #f87171;background:#fef9f9;page-break-inside:avoid}
.sev-pill{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:500;text-transform:uppercase;letter-spacing:0.04em}
table.kv{width:100%;font-size:11px;margin-top:6px}
table.kv td{padding:4px 0;border-bottom:0.5px solid #f1f5f9}
table.kv td:first-child{color:#64748b;width:30%}
table.kv td:last-child{color:#0f172a;font-weight:500}
.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:14px}
.metric{padding:10px 8px;background:#f8fafc;border-radius:4px;border:0.5px solid #e2e8f0;text-align:center}
.metric-label{font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:3px;font-weight:600}
.metric-value{font-size:18px;font-weight:600;color:#0f172a;line-height:1.1}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px}
.card{background:#fff;border:0.5px solid #e2e8f0;border-radius:6px;padding:12px 14px;page-break-inside:avoid}
.legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;font-size:10px;color:#475569}
.li{display:inline-flex;align-items:center;gap:4px}
.sw{display:inline-block;width:8px;height:8px;border-radius:2px}
/* Priority matrix — restructured as one line per priority with key,
   count, and label balanced visually instead of "huge number / tiny label". */
.pm-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0 14px}
.pm-card{background:#f8fafc;border-radius:4px;padding:10px 12px;display:flex;align-items:baseline;gap:8px}
.pm-key{font-size:11px;font-weight:600;color:#0f172a;letter-spacing:0.02em}
.pm-count{font-size:13px;font-weight:600;color:#0f172a;margin-left:auto}
.pm-label{font-size:9.5px;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;font-weight:600}
/* Cover page */
section.cover{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 42px;page-break-after:always;text-align:center;min-height:240mm}
.cover-logo{margin-bottom:20px}
.cover-brand{font-size:48px;font-weight:600;color:#0f172a;letter-spacing:-0.02em;margin-bottom:8px}
.brand-accent{color:#dc2626}
.cover-tagline{font-size:14px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.15em;margin-bottom:32px}
.cover-image{font-size:24px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#0f172a;font-weight:500;margin-bottom:6px}
.cover-digest{font-size:11px;color:#94a3b8;font-family:ui-monospace,Menlo,Consolas,monospace;margin-bottom:32px}
.cover-score-pill{display:flex;flex-direction:column;align-items:center;padding:16px 32px;border:1px solid;border-radius:12px;margin-bottom:24px;min-width:200px}
.cover-score-caption{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px}
.cover-score-num{font-size:42px;font-weight:600;line-height:1;margin-bottom:2px}
.cover-score-label{font-size:14px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em}
.cover-meta{font-size:11px;color:#64748b;line-height:1.6;margin-bottom:32px}
.cover-meta-label{color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;font-size:9.5px;font-weight:600;margin-right:4px}
.cover-credit{font-size:11px;color:#94a3b8;margin-top:24px}
.cover-credit strong{color:#475569;font-weight:600}
/* Right footer shows page N / total. Left footer suppressed.
   No top header — page numbers are enough orientation. */
@page{size:A4;margin:16mm 14mm 16mm 14mm;
  @bottom-right{content:counter(page) " / " counter(pages);font-family:sans-serif;font-size:9px;color:#94a3b8}}
@page :first{@bottom-right{content:""}}
</style>"""

    # Assemble final document
    sections = [cover_section, exec_section, risk_overview_section, top_cves_section]
    if kev_section:
        sections.append(kev_section)
    sections += [threat_section, packages_section, rem_section]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>VulnSight Report - {e(img["name"])}</title>
{PRINT_CSS}
</head>
<body>
{"".join(sections)}
</body>
</html>"""

#  PDF GENERATION
def generate_pdf(print_html, out_path):
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        return None

    HTML(string=print_html).write_pdf(out_path)
    return out_path


def encode_pdf_data_uri(pdf_path):
    import base64
    with open(pdf_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")
    return f"data:application/pdf;base64,{b64}"

#  ENTRY POINT

def main():
    parser = argparse.ArgumentParser(
        description="Parse 4 scanner output files and generate a VulnSight HTML report."
    )
    # --meta is the anchor; everything else can be auto-discovered from it.
    parser.add_argument("--meta",   default="metadata.json",
                        help="Path to metadata.json (anchor for auto-discovery)")
    parser.add_argument("--grype",  default=None,
                        help="Path to grype.json (default: from metadata.artifacts.grype_path)")
    parser.add_argument("--sbom",   default=None,
                        help="Path to sbom.json (default: from metadata.artifacts.sbom_path)")
    parser.add_argument("--threat", default=None,
                        help="Path to threat_intel.json (default: from metadata.artifacts.threat_intel_path)")
    parser.add_argument("--output", default=None,
                        help="Output HTML file path (default: vulnsight_<image>_<digest>.html)")
    parser.add_argument("--save-json", default=None,
                        help="Optional: also save the parsed data as a JSON file at this path")
    parser.add_argument("--print-html", action="store_true",
                        help="Also emit a print-optimized HTML (for PDF conversion via Cmd+P or weasyprint)")
    parser.add_argument("--no-pdf", action="store_true",
                        help="Skip PDF generation entirely (no PDF file, no Download PDF button in HTML). "
                             "Useful for fast iteration or when weasyprint isn't installed.")
    args = parser.parse_args()

    # Locate metadata.json
    if not Path(args.meta).exists():
        print(f"[ERROR] metadata file not found: {args.meta}", file=sys.stderr)
        sys.exit(1)

    with open(args.meta, encoding="utf-8") as f:
        meta_for_paths = json.load(f)
    meta_dir = Path(args.meta).resolve().parent
    art_paths = meta_for_paths.get("artifacts", {}) or {}

    # Resolve Each Input
    def resolve(flag_val, meta_key, fallback_name):
        if flag_val:
            return flag_val
        stored = art_paths.get(meta_key)
        if stored:
            for cand in (Path(stored), meta_dir / Path(stored).name, meta_dir / stored):
                if cand.exists():
                    return str(cand)
            return stored
        for cand in (meta_dir / fallback_name, Path(fallback_name)):
            if cand.exists():
                return str(cand)
        return fallback_name

    grype_path  = resolve(args.grype,  "grype_path",        "grype.json")
    sbom_path   = resolve(args.sbom,   "sbom_path",         "sbom.json")
    threat_path = resolve(args.threat, "threat_intel_path", "threat_intel.json")

    print(f"[+] Inputs resolved:")
    print(f"      metadata     : {args.meta}")
    print(f"      grype        : {grype_path}")
    print(f"      sbom         : {sbom_path}")
    print(f"      threat_intel : {threat_path}")

    for label, path in [("grype", grype_path), ("sbom", sbom_path),
                        ("threat_intel", threat_path)]:
        if not Path(path).exists():
            print(f"[ERROR] {label} file not found: {path}", file=sys.stderr)
            print(f"        Either fix metadata.artifacts.{label}_path or pass --{label} explicitly.",
                  file=sys.stderr)
            sys.exit(1)

    # Default Output Filename
    if args.output:
        output_path = args.output
    else:
        output_path = str(meta_dir / "report.html")

    data = parse(grype_path, sbom_path, threat_path, args.meta)

    if args.save_json:
        Path(args.save_json).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Intermediate JSON  : {args.save_json}")

    pdf_data_uri = None
    pdf_path = None
    if not args.no_pdf:
        print("[+] Generating PDF     ...")
        print_html_str = build_print_html(data)
        pdf_path = output_path.replace(".html", ".pdf")
        if pdf_path == output_path:
            pdf_path = output_path + ".pdf"
        result = generate_pdf(print_html_str, pdf_path)
        if result is None:
            print("[!] weasyprint not installed - skipping PDF generation.",
                  file=sys.stderr)
            print("    Install with: pip install weasyprint", file=sys.stderr)
            print("    (or pass --no-pdf to suppress this message)", file=sys.stderr)
        else:
            size_kb = Path(pdf_path).stat().st_size / 1024
            print(f"[+] PDF written to     : {pdf_path}  ({size_kb:.1f} KB)")
            pdf_data_uri = encode_pdf_data_uri(pdf_path)

    print("[+] Generating HTML    ...")
    html = build_html(data, pdf_data_uri=pdf_data_uri)
    Path(output_path).write_text(html, encoding="utf-8")
    size_kb = Path(output_path).stat().st_size / 1024
    print(f"[+] Report written to  : {output_path}  ({size_kb:.1f} KB)")
    print(f"[+] Open in browser    : file://{Path(output_path).resolve()}")

    if args.print_html:
        print("[+] Generating print HTML ...")
        try:
            print_html_str
        except NameError:
            print_html_str = build_print_html(data)
        print_path = output_path.replace(".html", "_print.html")
        if print_path == output_path:
            print_path = output_path + ".print.html"
        Path(print_path).write_text(print_html_str, encoding="utf-8")
        size_kb = Path(print_path).stat().st_size / 1024
        print(f"[+] Print HTML written  : {print_path}  ({size_kb:.1f} KB)")
        print(f"    Tip: Cmd+P (or Ctrl+P) in your browser \u2192 Save as PDF for a quick preview.")


if __name__ == "__main__":
    main()
