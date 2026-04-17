"""
modules/network_monitor/bettercap_mitm.py
-------------------------------------------
Bettercap MITM simulation wrapper.

Capabilities:
  - Launches Bettercap in API mode
  - Sends REST commands to enable ARP spoofing + sniffer modules
  - Logs all intercepted data references
  - Strictly for authorized lab environments

Config keys (from config.yaml → network_monitor):
  interface      : str   Network interface
  bettercap_enabled : bool Enable this module
"""

import subprocess
import time
import requests as req

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError


_BC_API = "http://127.0.0.1:8081/api"
_BC_USER = "user"
_BC_PASS = "pass"


class BettercapMitm(BaseModule):
    """
    Bettercap MITM wrapper — ARP spoofing + sniffer simulation.

    Config keys: interface, bettercap_enabled
    """

    MODULE_NAME = "BettercapMitm"

    def _execute(self) -> dict:
        if not self.config.get("bettercap_enabled", False):
            self.logger.info("Bettercap is disabled in config — skipping.")
            return {"skipped": True, "reason": "bettercap_enabled=false"}

        interface = self.config.get("interface", "eth0")
        result = {"interface": interface, "modules_enabled": [], "status": "not_started"}

        self.logger.warning(
            "[!!!] Starting Bettercap MITM — AUTHORIZED LAB USE ONLY."
        )

        # Launch bettercap in background API mode
        command = [
            "sudo", "bettercap",
            "-iface", interface,
            "-eval",
            "api.rest on; net.probe on; arp.spoof on; net.sniff on",
            "-no-colors",
        ]

        self.logger.info(f"Executing: {' '.join(command)}")

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            raise ToolNotFoundError(
                "Bettercap not installed. See: https://www.bettercap.org/installation/"
            )

        # Give bettercap a moment to start
        time.sleep(3)

        # Poll API for status
        try:
            resp = req.get(
                f"{_BC_API}/session",
                auth=(_BC_USER, _BC_PASS),
                timeout=5,
            )
            if resp.ok:
                session_data = resp.json()
                result["modules_enabled"] = [
                    m["name"] for m in session_data.get("modules", [])
                    if m.get("running")
                ]
                result["status"] = "running"
                self.logger.info(f"Bettercap active modules: {result['modules_enabled']}")
        except Exception as exc:
            self.logger.warning(f"Could not query Bettercap API: {exc}")
            result["status"] = "api_unreachable"

        # Let it run for capture_duration then stop
        duration = self.config.get("capture_duration", 30)
        self.logger.info(f"Running for {duration}s…")
        time.sleep(duration)

        proc.terminate()
        self.logger.info("Bettercap terminated.")
        result["duration"] = duration

        return result
