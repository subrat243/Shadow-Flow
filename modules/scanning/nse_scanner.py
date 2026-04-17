"""
modules/scanning/nse_scanner.py
--------------------------------
Nmap NSE script runner for deep service enumeration.

Capabilities:
  - Runs configurable NSE script categories (vuln, auth, default, etc.)
  - Parses script output from XML for structured results
  - Flags potential vulnerabilities found by NSE scripts

Config keys (from config.yaml → scanning → nse_scripts):
  nse_scripts : list[str]   Script categories or named scripts to run
"""

import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError, ScanError


class NseScanner(BaseModule):
    """
    Nmap NSE script category runner.

    Config keys: nse_scripts (list of script names/categories)
    """

    MODULE_NAME = "NseScanner"

    def _execute(self) -> dict:
        scripts = self.config.get("nse_scripts", ["default", "vuln"])
        script_arg = ",".join(scripts)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        command = [
            "nmap",
            "-sV",
            f"--script={script_arg}",
            "-T4",
            "-oX", xml_path,
            self.target,
        ]

        self.logger.info(f"Executing NSE scan: {' '.join(command)}")

        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=600
            )
        except FileNotFoundError:
            raise ToolNotFoundError("nmap is not installed or not in PATH.")
        except subprocess.TimeoutExpired:
            raise ScanError("NSE scan timed out (>600s).")

        results = {
            "command": " ".join(command),
            "scripts_run": scripts,
            "script_findings": [],
            "raw_output": proc.stdout,
        }

        try:
            findings = self._parse_xml(xml_path)
            results["script_findings"] = findings
        except Exception as exc:
            self.logger.warning(f"NSE XML parse failed: {exc}")
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

        vuln_count = sum(1 for f in results["script_findings"] if f.get("is_vuln"))
        self.logger.info(
            f"NSE complete — {len(results['script_findings'])} finding(s), "
            f"{vuln_count} flagged as potential vulnerability."
        )

        return results

    def _parse_xml(self, xml_path: str) -> list:
        """Extract per-port script output from nmap XML."""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        findings = []

        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                port_id   = port_el.get("portid")
                protocol  = port_el.get("protocol")
                state_el  = port_el.find("state")
                state     = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue

                for script_el in port_el.findall("script"):
                    script_id     = script_el.get("id", "")
                    script_output = script_el.get("output", "").strip()

                    # Heuristic: flag likely vuln findings
                    is_vuln = any(
                        kw in script_output.lower()
                        for kw in ["vulnerable", "exploit", "cve-", "ms17", "critical"]
                    )

                    finding = {
                        "port":     int(port_id),
                        "protocol": protocol,
                        "script":   script_id,
                        "output":   script_output,
                        "is_vuln":  is_vuln,
                    }
                    findings.append(finding)

                    level = "WARNING" if is_vuln else "INFO"
                    self.logger.log(
                        __import__("logging").WARNING if is_vuln else __import__("logging").INFO,
                        f"  [{script_id}] port {port_id}/{protocol}: {script_output[:120]}"
                    )

        return findings
