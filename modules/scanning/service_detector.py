"""
modules/scanning/service_detector.py
--------------------------------------
Advanced service and version fingerprinting module.

Capabilities:
  - HTTP banner grabbing (server header, powered-by, cookies)
  - SSH version extraction via raw socket
  - FTP/SMTP/POP3 banner grabbing
  - Aggregates all fingerprints into a structured dict

This module enriches the recon data with application-layer details
that raw nmap may miss or misidentify.
"""

import socket
import requests
import urllib3
from modules.base_module import BaseModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 5  # seconds per probe


class ServiceDetector(BaseModule):
    """
    Application-layer service fingerprinting module.
    Reads open_ports from config (injected by orchestrator).
    """

    MODULE_NAME = "ServiceDetector"

    def _execute(self) -> dict:
        # open_ports are injected by the orchestrator via config
        open_ports = self.config.get("open_ports", [])
        fingerprints = []

        for port_info in open_ports:
            port    = port_info.get("port")
            service = port_info.get("service", "").lower()
            fp = {"port": port, "service": service, "fingerprint": {}}

            if service in ("http", "https") or port in (80, 443, 8080, 8443, 8000):
                fp["fingerprint"] = self._http_fingerprint(port)

            elif service in ("ssh", "openssh") or port == 22:
                fp["fingerprint"] = self._banner_grab(port, label="ssh")

            elif service in ("ftp", "vsftpd", "proftpd") or port == 21:
                fp["fingerprint"] = self._banner_grab(port, label="ftp")

            elif service in ("smtp",) or port in (25, 465, 587):
                fp["fingerprint"] = self._banner_grab(port, label="smtp")

            if fp["fingerprint"]:
                fingerprints.append(fp)
                self.logger.info(
                    f"  Port {port}/{service}: {fp['fingerprint']}"
                )

        return {"service_fingerprints": fingerprints}

    # ── Probes ────────────────────────────────────────────────────────────

    def _http_fingerprint(self, port: int) -> dict:
        """Grab HTTP headers and basic web server info."""
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.target}:{port}/"
        fp = {}
        try:
            resp = requests.get(
                url, timeout=_TIMEOUT, verify=False,
                allow_redirects=True,
                headers={"User-Agent": "shadow-flow/1.0"},
            )
            fp["status_code"]  = resp.status_code
            fp["server"]       = resp.headers.get("Server", "")
            fp["x_powered_by"] = resp.headers.get("X-Powered-By", "")
            fp["content_type"] = resp.headers.get("Content-Type", "")
            fp["cookies"]      = list(resp.cookies.keys())
            fp["redirect_url"] = str(resp.url) if resp.history else None
            fp["title"]        = self._extract_title(resp.text)
        except requests.RequestException as exc:
            fp["error"] = str(exc)
        return fp

    def _banner_grab(self, port: int, label: str) -> dict:
        """Raw TCP banner grab for SSH / FTP / SMTP services."""
        fp = {}
        try:
            with socket.create_connection((self.target, port), timeout=_TIMEOUT) as s:
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                fp["banner"] = banner
                fp["label"]  = label
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            fp["error"] = str(exc)
        return fp

    @staticmethod
    def _extract_title(html: str) -> str:
        """Quick regex-free title tag extractor."""
        start = html.find("<title>")
        end   = html.find("</title>")
        if start != -1 and end != -1:
            return html[start + 7: end].strip()[:128]
        return ""
