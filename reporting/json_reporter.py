"""
reporting/json_reporter.py
----------------------------
Generates a structured JSON report from the Session object.

Output: reports/session_report_<session_id>.json
"""

import json
import os
import time

from core.session import Session
from core.exceptions import ReportingError


class JsonReporter:
    """
    Serialises the Session to a clean, machine-readable JSON file.

    Parameters
    ----------
    session  : Session   Completed session object.
    out_dir  : str       Output directory path.
    """

    def __init__(self, session: Session, out_dir: str = "reports"):
        self.session = session
        self.out_dir = out_dir

    def generate(self) -> str:
        """Write JSON report; return the output file path."""
        os.makedirs(self.out_dir, exist_ok=True)
        filename = f"session_{self.session.session_id}.json"
        filepath = os.path.join(self.out_dir, filename)

        report = self._build_report()

        try:
            with open(filepath, "w") as fh:
                json.dump(report, fh, indent=4, default=str)
        except IOError as exc:
            raise ReportingError(f"Failed to write JSON report: {exc}") from exc

        print(f"[JSON Report] Saved → {filepath}")
        return filepath

    def _build_report(self) -> dict:
        """Compose the final report dict."""
        session_dict = self.session.to_dict()

        # Flatten exploit hints for readability
        exploit_hints = self.session.metadata.get("exploit_hints", [])
        vulnerabilities = []
        for hint in exploit_hints:
            vulnerabilities.append({
                "port":       hint.get("port"),
                "service":    hint.get("service"),
                "version":    hint.get("version"),
                "msf_module": hint.get("msf_module"),
                "cve_hints":  hint.get("cve_hints", []),
                "severity":   hint.get("severity", "unknown"),
                "cvss_approx": _severity_to_cvss(hint.get("severity")),
            })

        # Aggregate NSE findings
        nse_findings = self.session.phases.get("scanning", {}).get("script_findings", [])
        nse_vulns = [f for f in nse_findings if f.get("is_vuln")]

        # Aggregate Nikto findings
        nikto_findings = self.session.phases.get("nikto", {}).get("findings", [])

        return {
            "meta": {
                "tool":       "Shadow-Flow",
                "version":    "1.0.0",
                "generated":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "session_id": session_dict["session_id"],
                "target":     session_dict["target"],
                "duration":   f"{session_dict['duration_seconds']}s",
            },
            "target_profile": session_dict["metadata"],
            "vulnerabilities": vulnerabilities,
            "nse_vulnerabilities": nse_vulns,
            "web_findings": nikto_findings,
            "phases": session_dict["phases"],
            "active_sessions": session_dict["active_sessions"],
            "attack_chain": self._build_attack_chain(),
        }

    def _build_attack_chain(self) -> list:
        """Build a linear summary of phases executed."""
        chain = []
        for phase, data in self.session.phases.items():
            chain.append({
                "phase":  phase,
                "status": data.get("status", "complete"),
            })
        return chain


def _severity_to_cvss(severity: str) -> float:
    return {
        "critical": 9.0,
        "high":     7.5,
        "medium":   5.0,
        "low":      2.5,
        "info":     0.0,
    }.get(severity, 0.0)
