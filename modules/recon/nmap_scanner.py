"""
modules/recon/nmap_scanner.py
------------------------------
Active host discovery and port scanning via Nmap.

Capabilities:
  - Host discovery  (-sn)
  - Port scan       (-sV -O with configurable timing and flags)
  - XML output parsing for structured results
  - Falls back to regex text parsing if XML unavailable

Inherits from BaseModule.
"""

import subprocess
import re
import xml.etree.ElementTree as ET
import tempfile
import os

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError, ScanError


class NmapScanner(BaseModule):
    """
    Nmap wrapper for the Reconnaissance phase.

    Config keys (from config.yaml → recon → nmap):
      timing  : str        Nmap timing template, e.g. 'T4'
      flags   : list[str]  Extra nmap flags, e.g. ['-sV', '-O']
    """

    MODULE_NAME = "NmapScanner"

    def _execute(self) -> dict:
        timing = self.config.get("timing", "T4")
        flags   = self.config.get("flags", ["-sV"])

        # ── Build XML output to a temp file for structured parsing ────────
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        command = ["nmap", f"-{timing}"] + flags + ["-oX", xml_path, self.target]

        self.logger.info(f"Executing: {' '.join(command)}")

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            raise ToolNotFoundError("nmap is not installed or not in PATH.")
        except subprocess.TimeoutExpired:
            raise ScanError("Nmap scan timed out (>300s).")

        raw_output = proc.stdout + proc.stderr
        results = {
            "command": " ".join(command),
            "raw_output": raw_output,
            "open_ports": [],
            "host_status": "unknown",
            "os_guess": None,
        }

        # ── Parse XML for structured data ─────────────────────────────────
        try:
            results.update(self._parse_xml(xml_path))
        except Exception as exc:
            self.logger.warning(f"XML parse failed ({exc}); falling back to text parse.")
            results["open_ports"] = self._parse_text(raw_output)
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

        self.logger.info(
            f"Scan complete — {len(results['open_ports'])} open port(s) found."
        )
        for p in results["open_ports"]:
            self.logger.info(
                f"  {p['port']}/{p['protocol']}  {p['state']:<8}  "
                f"{p['service']:<12}  {p['version']}"
            )

        return results

    # ── Parsers ───────────────────────────────────────────────────────────

    def _parse_xml(self, xml_path: str) -> dict:
        """Parse nmap XML output for structured port and OS data."""
        tree = ET.parse(xml_path)
        root = tree.getroot()

        data = {"open_ports": [], "host_status": "unknown", "os_guess": None}

        for host in root.findall("host"):
            # Host status
            status_el = host.find("status")
            if status_el is not None:
                data["host_status"] = status_el.get("state", "unknown")

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    if state != "open":
                        continue

                    service_el = port_el.find("service")
                    svc_name    = service_el.get("name", "")    if service_el is not None else ""
                    svc_product = service_el.get("product", "") if service_el is not None else ""
                    svc_version = service_el.get("version", "") if service_el is not None else ""
                    svc_extra   = service_el.get("extrainfo", "") if service_el is not None else ""

                    data["open_ports"].append(
                        {
                            "port":     int(port_el.get("portid")),
                            "protocol": port_el.get("protocol"),
                            "state":    state,
                            "service":  svc_name,
                            "version":  f"{svc_product} {svc_version} {svc_extra}".strip(),
                        }
                    )

            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                best = os_el.find("osmatch")
                if best is not None:
                    data["os_guess"] = {
                        "name":     best.get("name"),
                        "accuracy": best.get("accuracy"),
                    }

        return data

    def _parse_text(self, raw_output: str) -> list:
        """Fallback: regex-based port extraction from plain Nmap text."""
        port_pattern = re.compile(
            r"^(\d+)/(tcp|udp)\s+(open)\s+([\w?-]+)\s*(.*)?$", re.MULTILINE
        )
        ports = []
        for m in port_pattern.finditer(raw_output):
            ports.append(
                {
                    "port":     int(m.group(1)),
                    "protocol": m.group(2),
                    "state":    m.group(3),
                    "service":  m.group(4),
                    "version":  m.group(5).strip() if m.group(5) else "",
                }
            )
        return ports
