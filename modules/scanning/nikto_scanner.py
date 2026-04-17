"""
modules/scanning/nikto_scanner.py
----------------------------------
Nikto web vulnerability scanner wrapper.

Capabilities:
  - Detects web server misconfigs, outdated software, dangerous files
  - Runs against HTTP and HTTPS automatically
  - Parses CSV output for structured findings
  - Assigns severity hints based on Nikto message codes

Config keys (from config.yaml → scanning):
  nikto → extra_flags : list[str]   Additional nikto CLI flags
"""

import subprocess
import csv
import io
import tempfile
import os

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError, ScanError


# Nikto message-code → severity mapping (subset, extensible)
_CODE_SEVERITY = {
    "OSVDB-0":    "info",
    "OSVDB-3092": "medium",
    "OSVDB-3268": "medium",
    "OSVDB-3233": "low",
    "OSVDB-6697": "high",
}

_DEFAULT_SEVERITY = "medium"


class NiktoScanner(BaseModule):
    """
    Nikto web scanner wrapper.

    Config keys: extra_flags
    """

    MODULE_NAME = "NiktoScanner"

    def _execute(self) -> dict:
        extra_flags = self.config.get("extra_flags", [])

        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w"
        ) as tmp:
            csv_path = tmp.name

        command = [
            "nikto",
            "-h", self.target,
            "-Format", "csv",
            "-output", csv_path,
            "-nointeractive",
        ] + extra_flags

        self.logger.info(f"Executing: {' '.join(command)}")

        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=600
            )
        except FileNotFoundError:
            raise ToolNotFoundError(
                "nikto is not installed. Install with: sudo apt install nikto"
            )
        except subprocess.TimeoutExpired:
            raise ScanError("Nikto scan timed out (>600s).")

        results = {
            "command": " ".join(command),
            "findings": [],
            "raw_output": proc.stdout,
        }

        try:
            results["findings"] = self._parse_csv(csv_path)
        except Exception as exc:
            self.logger.warning(f"Nikto CSV parse failed: {exc}")
        finally:
            if os.path.exists(csv_path):
                os.unlink(csv_path)

        self.logger.info(f"Nikto complete — {len(results['findings'])} finding(s).")
        for f in results["findings"]:
            self.logger.info(
                f"  [{f['severity'].upper():6s}] {f['url']} — {f['description'][:100]}"
            )

        return results

    def _parse_csv(self, csv_path: str) -> list:
        """Parse Nikto CSV output into structured finding dicts."""
        findings = []
        try:
            with open(csv_path, "r", newline="", errors="ignore") as fh:
                content = fh.read()
        except FileNotFoundError:
            return findings

        # Nikto CSV has a header line starting with "Nikto" — skip it
        lines = [
            ln for ln in content.splitlines()
            if ln and not ln.startswith('"Nikto') and not ln.startswith("Nikto")
        ]

        reader = csv.DictReader(
            io.StringIO("\n".join(lines)),
            fieldnames=[
                "hostname", "ip", "port", "uri",
                "method", "description", "test_links", "namelink", "osvdb_link"
            ],
        )

        for row in reader:
            desc = row.get("description", "").strip()
            if not desc:
                continue

            # Extract OSVDB code for severity lookup
            osvdb = ""
            for part in desc.split():
                if part.startswith("OSVDB-"):
                    osvdb = part.rstrip(":")
                    break

            severity = _CODE_SEVERITY.get(osvdb, _DEFAULT_SEVERITY)

            findings.append(
                {
                    "host":        row.get("hostname", self.target),
                    "ip":          row.get("ip", ""),
                    "port":        row.get("port", ""),
                    "url":         f"{self.target}{row.get('uri', '')}",
                    "method":      row.get("method", "GET"),
                    "description": desc,
                    "osvdb":       osvdb,
                    "severity":    severity,
                }
            )

        return findings
