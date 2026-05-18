import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict, Counter


def load_jsonc(path: str) -> dict:
    text = Path(path).read_text()
    text = re.sub(r"//.*", "", text)
    return json.loads(text)


class RiskEngine:
    def __init__(self, config_path: str = None) -> None:
        if config_path is None:
            config_path = Path(__file__).parent / "risk_config.json"

        self.cfg = load_jsonc(config_path)
        self._validate_config()

        self.cve_cfg = self.cfg["cve_weights"]
        self.container_cfg = self.cfg["container_context"]
        self.cloud_cfg = self.cfg["cloud_context"]

    # Config validation
    def _validate_config(self):
        cfg = self.cfg

        for sec in ["cve_weights", "container_context", "cloud_context"]:
            if sec not in cfg:
                raise ValueError(f"Missing required config section: {sec}")

        cw = cfg["cve_weights"]

        required = [
            "cvss_multiplier", "epss_multiplier", "kev_bonus",
            "age_bonus", "fix_bonus", "severity_weights",
            "cwe_bonus", "max_cap_per_cve", "top_n",
        ]
        for key in required:
            if key not in cw:
                raise ValueError(f"Missing cve_weights.{key}")

        for key in ["older_than_365", "older_than_180", "older_than_30"]:
            if key not in cw["age_bonus"]:
                raise ValueError(f"Missing age_bonus.{key}")

        return True

    # Scoring helpers
    def _severity_weight(self, severity: Optional[str]) -> float:
        if not severity:
            return self.cve_cfg["severity_weights"]["unknown"]
        return self.cve_cfg["severity_weights"].get(
            severity.lower(),
            self.cve_cfg["severity_weights"]["unknown"],
        )

    def _age_bonus(self, age_days: Optional[int]) -> float:
        if age_days is None:
            return 0.0
        if age_days > 365:
            return self.cve_cfg["age_bonus"]["older_than_365"]
        if age_days > 180:
            return self.cve_cfg["age_bonus"]["older_than_180"]
        if age_days > 30:
            return self.cve_cfg["age_bonus"]["older_than_30"]
        return 0.0

    def _fix_bonus(self, fix_obj: Optional[Dict[str, Any]]) -> float:
        if not fix_obj:
            return 0.0
        return self.cve_cfg["fix_bonus"] if (fix_obj.get("state") == "fixed") else 0.0

    def _cwe_bonus(self, cwe: Optional[str]) -> float:
        if not cwe:
            return self.cve_cfg["cwe_bonus"]["default"]
        for hi in self.cve_cfg["cwe_bonus"]["high_impact_list"]:
            if hi in cwe:
                return self.cve_cfg["cwe_bonus"]["high_impact"]
        return self.cve_cfg["cwe_bonus"]["default"]

    def _kev_bonus(self, kev_flag: bool) -> float:
        return self.cve_cfg["kev_bonus"] if kev_flag else 0.0

    def _epss_weight(self, epss: Optional[float]) -> float:
        return float(epss) * self.cve_cfg["epss_multiplier"] if epss else 0.0

    def _cvss_weight(self, cvss: Optional[float]) -> float:
        return float(cvss) * self.cve_cfg["cvss_multiplier"] if cvss else 0.0

    def _risk_level(self, score: float) -> str:
        if score < 20:
            return "LOW"
        if score < 40:
            return "MEDIUM"
        if score < 70:
            return "HIGH"
        return "CRITICAL"

    # Remediation Plan Builder
    def build_remediation_plan(self, matches, fixable_cves):
        parsed = []

        # Flatten matches
        for m in matches:
            vuln = m.get("vulnerability", {}) or {}
            cve = vuln.get("id")
            if cve not in fixable_cves:
                continue

            artifact = m.get("artifact", {}) or {}

            cvss_score = 0.0
            for entry in vuln.get("cvss", []):
                score = entry.get("metrics", {}).get("baseScore", 0)
                cvss_score = max(cvss_score, score)

            parsed.append({
                "cve": cve,
                "severity": vuln.get("severity", "Unknown"),
                "cvss": cvss_score,
                "kev": bool(vuln.get("knownExploited")),
                "fix_versions": vuln.get("fix", {}).get("versions", []),
                "pkg_name": artifact.get("name"),
                "pkg_version": artifact.get("version"),
                "pkg_type": artifact.get("type"),
            })

        # Group by package
        buckets = defaultdict(list)
        for item in parsed:
            key = (item["pkg_name"], item["pkg_version"], item["pkg_type"])
            buckets[key].append(item)

        remediation = []

        def sev_rank(s):
            order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Negligible": 0, "Unknown": 0}
            return order.get(s, 0)

        # Build Package Entries
        for (name, version, pkg_type), cves in buckets.items():

            all_fix_versions = [v for c in cves for v in c["fix_versions"]]
            best_fix = Counter(all_fix_versions).most_common(1)[0][0] \
                       if all_fix_versions else None

            sorted_cves = sorted(
                cves,
                key=lambda c: (sev_rank(c["severity"]), c["cvss"]),
                reverse=True,
            )

            remediation.append({
                "package": name,
                "current_version": version,
                "fix_version": best_fix,
                "cves": ", ".join(c["cve"] for c in sorted_cves),
                "total_fixable": len(sorted_cves),
                "critical": sum(1 for c in sorted_cves if c["severity"] == "Critical"),
                "high": sum(1 for c in sorted_cves if c["severity"] == "High"),
                "kev_count": sum(1 for c in sorted_cves if c["kev"]),
                "max_cvss": max((c["cvss"] for c in sorted_cves), default=0.0),
            })

        return remediation

    # Main compute()
    def compute(
        self,
        grype_results: Dict[str, Any],
        threat_intel: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        cloud_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        context = context or {}
        cloud_context = cloud_context or {}

        matches = grype_results.get("matches", [])
        per_cve = {}
        fixable_cves = set()

        # Per-CVE scoring
        for m in matches:
            vuln = m.get("vulnerability", {}) or {}
            cve_id = vuln.get("id")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            sev = vuln.get("severity")
            fix_obj = vuln.get("fix") or {}

            fix_available = (fix_obj.get("state") == "fixed")
            fixed_versions = fix_obj.get("versions") or []

            if fix_available:
                fixable_cves.add(cve_id)

            ti = threat_intel.get(cve_id, {}) or {}
            cvss = ti.get("cvss")

            if cvss is None:
                grype_cvss_list = vuln.get("cvss") or []
                if isinstance(grype_cvss_list, list) and grype_cvss_list:
                    cvss = grype_cvss_list[0].get("baseScore")
                elif isinstance(grype_cvss_list, dict):
                    cvss = grype_cvss_list.get("baseScore")

            epss = ti.get("epss")
            kev_flag = bool(ti.get("kev"))
            age_days = ti.get("age_days")
            cwe = ti.get("cwe")

            base_score = (
                self._cvss_weight(cvss)
                + self._epss_weight(epss)
                + self._kev_bonus(kev_flag)
                + self._age_bonus(age_days)
                + self._severity_weight(sev)
                + self._cwe_bonus(cwe)
                + self._fix_bonus(fix_obj)
            )

            entry = per_cve.get(cve_id)
            if entry is None:
                per_cve[cve_id] = {
                    "cve": cve_id,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev_flag,
                    "age_days": age_days,
                    "severity": sev,
                    "cwe": cwe,
                    "fix_available": fix_available,
                    "fixed_versions": fixed_versions,
                    "raw_risk_score": base_score,
                    "contribution": base_score,
                }
            else:
                entry["raw_risk_score"] = max(entry["raw_risk_score"], base_score)
                entry["contribution"] = entry["raw_risk_score"]

        # Aggregate top-N into image-level score
        per_cve_list = list(per_cve.values())
        per_cve_list.sort(key=lambda x: x["contribution"], reverse=True)

        TOP_N       = self.cve_cfg["top_n"]
        MAX_PER_CVE = self.cve_cfg["max_cap_per_cve"]
        top = per_cve_list[:TOP_N]

        if not top:
            overall_score = 0.0
        else:
            capped_total = sum(min(x["contribution"], MAX_PER_CVE) for x in top)
            ceiling      = TOP_N * MAX_PER_CVE
            overall_score = min(100.0, capped_total / ceiling * 100.0)

        # Context multipliers
        if context.get("runs_as_root"):
            overall_score *= self.container_cfg["runs_as_root_multiplier"]

        if context.get("base_image_eol"):
            overall_score *= self.container_cfg["base_image_eol_multiplier"]

        if context.get("suid_binaries"):
            overall_score += self.container_cfg["suid_bonus"]

        if context.get("dangerous_tools"):
            overall_score += self.container_cfg["dangerous_tools_bonus"]

        if cloud_context.get("public_ip"):
            overall_score += self.cloud_cfg["public_ip_bonus"]

        if cloud_context.get("ssh_open"):
            overall_score += self.cloud_cfg["ssh_open_bonus"]

        if cloud_context.get("all_ports_open"):
            overall_score += self.cloud_cfg["all_ports_open_bonus"]

        if not cloud_context.get("metadata_hardening", True):
            overall_score += self.cloud_cfg["metadata_hardening_penalty"]

        if cloud_context.get("identity_attached"):
            overall_score += self.cloud_cfg["identity_attached_bonus"]

        if cloud_context.get("identity_scope_broad"):
            overall_score += self.cloud_cfg["identity_scope_broad_bonus"]

        if cloud_context.get("disk_encryption_disabled"):
            overall_score += self.cloud_cfg["disk_encryption_disabled_bonus"]

        if cloud_context.get("secure_boot_disabled"):
            overall_score += self.cloud_cfg["secure_boot_disabled_bonus"]

        if cloud_context.get("serial_port_enabled"):
            overall_score += self.cloud_cfg["serial_port_enabled_bonus"]

        overall_score = round(min(100.0, overall_score), 2)
        risk_level = self._risk_level(overall_score)

        # Building remediation plan
        remediation_plan = self.build_remediation_plan(matches, fixable_cves)

        # Build Remediation Summary
        unique_fixable = len(fixable_cves)

        kev_pkg_count = sum(1 for p in remediation_plan if p["kev_count"] > 0)
        crit_high_count = sum(p["critical"] + p["high"] for p in remediation_plan)

        top_packages = sorted(
            remediation_plan,
            key=lambda p: (p["critical"], p["high"], p["total_fixable"], p["max_cvss"]),
            reverse=True
        )[:5]

        remediation_summary = {
            "total_fixable_cves": unique_fixable,
            "packages_to_update": len(remediation_plan),
            "kev_linked_packages": kev_pkg_count,
            "critical_high_cves": crit_high_count,
            "top_packages": top_packages,
        }

        # Final return
        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "per_cve": per_cve_list,
            "remediation_plan": remediation_plan,
            "remediation_summary": remediation_summary,
        }
