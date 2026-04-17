"""
modules/network_monitor/tcpdump_capture.py
--------------------------------------------
Passive packet capture wrapper using tcpdump.

Capabilities:
  - Captures traffic on a specified interface
  - Saves to a .pcap file in the reports directory
  - Parses basic packet summary for reporting
  - Requires root/sudo privileges (expected in pentest lab)

Config keys (from config.yaml → network_monitor):
  interface        : str   Network interface (e.g. eth0)
  capture_duration : int   Seconds to capture
"""

import subprocess
import os
import time

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError, ScanError


class TcpdumpCapture(BaseModule):
    """
    tcpdump packet capture wrapper.

    Config keys: interface, capture_duration
    """

    MODULE_NAME = "TcpdumpCapture"

    def _execute(self) -> dict:
        interface = self.config.get("interface", "eth0")
        duration  = self.config.get("capture_duration", 30)
        out_dir   = "reports"
        os.makedirs(out_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = os.path.join(out_dir, f"capture_{timestamp}.pcap")

        command = [
            "tcpdump",
            "-i", interface,
            "-w", pcap_path,
            f"host {self.target}",
            "-G", str(duration),
            "-W", "1",
            "-nn",
        ]

        self.logger.info(f"Starting packet capture on {interface} for {duration}s…")
        self.logger.info(f"Output: {pcap_path}")
        self.logger.info(f"Executing: {' '.join(command)}")

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=duration + 15,
            )
        except FileNotFoundError:
            raise ToolNotFoundError(
                "tcpdump not installed. Install with: sudo apt install tcpdump"
            )
        except subprocess.TimeoutExpired:
            raise ScanError("tcpdump capture timed out.")

        result = {
            "pcap_file":  pcap_path,
            "interface":  interface,
            "duration":   duration,
            "stderr":     proc.stderr.strip(),
        }

        # Parse packet count from tcpdump stderr
        for line in proc.stderr.splitlines():
            if "packets captured" in line:
                result["packets_captured"] = line.strip()
                self.logger.info(f"  {line.strip()}")
                break

        self.logger.info(f"Capture saved to: {pcap_path}")
        return result
