"""
reporting/html_reporter.py
----------------------------
Generates a rich HTML pentest report using Jinja2.

Output: reports/session_<session_id>.html
"""

import os
import time
from core.session import Session
from core.exceptions import ReportingError

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_REMEDIATION_MAP = {
    "critical": [
        {"finding": "Critical exploit vector detected", "recommendation": "Apply vendor patches immediately. Isolate affected systems. Rotate all credentials.", "priority": "critical"},
    ],
    "high": [
        {"finding": "High-severity service exposed", "recommendation": "Restrict access via firewall rules. Update service to latest stable version.", "priority": "high"},
    ],
    "medium": [
        {"finding": "Medium-risk misconfiguration", "recommendation": "Review and harden service configuration. Apply principle of least privilege.", "priority": "medium"},
    ],
    "low": [
        {"finding": "Informational exposure", "recommendation": "Review banner / version disclosure. Consider stripping headers.", "priority": "low"},
    ],
}


class HtmlReporter:
    """
    Renders the Jinja2 HTML report template with session data.

    Parameters
    ----------
    session  : Session   Completed session.
    out_dir  : str       Output directory.
    """

    def __init__(self, session: Session, out_dir: str = "reports"):
        self.session = session
        self.out_dir = out_dir

    def generate(self) -> str:
        """Render and write the HTML report; return file path."""
        if not _JINJA2_AVAILABLE:
            print("[!] jinja2 not installed — skipping HTML report. Run: pip install jinja2")
            return ""

        os.makedirs(self.out_dir, exist_ok=True)
        filename = f"session_{self.session.session_id}.html"
        filepath = os.path.join(self.out_dir, filename)

        context = self._build_context()

        try:
            env = Environment(
                loader=FileSystemLoader(_TEMPLATE_DIR),
                autoescape=select_autoescape(["html"]),
            )
            template = env.get_template("report.html.j2")
            html = template.render(**context)
        except Exception as exc:
            raise ReportingError(f"Jinja2 render failed: {exc}") from exc

        try:
            with open(filepath, "w") as fh:
                fh.write(html)
        except IOError as exc:
            raise ReportingError(f"Failed to write HTML report: {exc}") from exc

        print(f"[HTML Report] Saved → {filepath}")
        return filepath

    def _build_context(self) -> dict:
        """Assemble all template context variables."""
        exploit_hints = self.session.metadata.get("exploit_hints", [])
        vulnerabilities = [
            {
                "port":       h.get("port"),
                "service":    h.get("service"),
                "version":    h.get("version", ""),
                "msf_module": h.get("msf_module"),
                "cve_hints":  h.get("cve_hints", []),
                "severity":   h.get("severity", "info"),
                "cvss_approx": _severity_to_cvss(h.get("severity")),
            }
            for h in exploit_hints
        ]

        open_ports = self.session.phases.get("recon", {}).get("open_ports", [])
        nse_vulns  = [
            f for f in self.session.phases.get("scanning", {}).get("script_findings", [])
            if f.get("is_vuln")
        ]
        web_findings = self.session.phases.get("nikto", {}).get("findings", [])
        persistence_audit = self.session.phases.get("persistence", {}).get(
            "persistence_audit", []
        )

        # Count vulnerabilities by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "info")
            vuln_counts[sev] = vuln_counts.get(sev, 0) + 1
        for f in nse_vulns:
            vuln_counts["high"] += 1

        # Build remediation list
        remediation = []
        seen_priorities = set()
        for v in vulnerabilities:
            sev = v.get("severity", "low")
            if sev not in seen_priorities:
                seen_priorities.add(sev)
                remediation.extend(_REMEDIATION_MAP.get(sev, []))
        # Always include general recommendations
        general_recs = [
            {"finding": "Open attack surface", "recommendation": "Implement network segmentation and reduce exposed services.", "priority": "medium"},
            {"finding": "Credential exposure", "recommendation": "Enable MFA. Rotate all credentials found during pentest.", "priority": "high"},
            {"finding": "No WAF detected", "recommendation": "Deploy a Web Application Firewall for HTTP-facing services.", "priority": "medium"},
        ]
        for rec in general_recs:
            if rec not in remediation:
                remediation.append(rec)

        session_dict = self.session.to_dict()

        return {
            "meta": {
                "tool":       "Shadow-Flow",
                "version":    "1.0.0",
                "generated":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "session_id": session_dict["session_id"],
                "target":     session_dict["target"],
                "duration":   f"{session_dict['duration_seconds']}s",
            },
            "target_profile":    session_dict["metadata"],
            "vulnerabilities":   vulnerabilities,
            "nse_vulnerabilities": nse_vulns,
            "web_findings":      web_findings,
            "persistence_audit": persistence_audit,
            "open_ports":        open_ports,
            "open_port_count":   len(open_ports),
            "web_finding_count": len(web_findings),
            "vuln_counts":       vuln_counts,
            "attack_chain":      self._build_attack_chain(),
            "remediation":       remediation,
        }

    def _build_attack_chain(self) -> list:
        return [
            {"phase": phase, "status": data.get("status", "complete")}
            for phase, data in self.session.phases.items()
        ]


def _severity_to_cvss(severity: str) -> float:
    return {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(severity, 0.0)
