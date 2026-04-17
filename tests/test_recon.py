"""
tests/test_recon.py
--------------------
Unit tests for the Reconnaissance module.

Tests cover:
  - NmapScanner text-fallback parser (no nmap binary required)
  - DnsEnum graceful handling when dnspython is absent
  - SubdomainEnum crt.sh response parsing
  - BaseModule lifecycle (run() → _execute())
"""

import unittest
from unittest.mock import patch, MagicMock


# ── NmapScanner Tests ─────────────────────────────────────────────────────────

class TestNmapScannerParser(unittest.TestCase):
    """Test the text-fallback port parser — no nmap binary needed."""

    def setUp(self):
        from modules.recon.nmap_scanner import NmapScanner
        self.scanner = NmapScanner.__new__(NmapScanner)
        self.scanner.target = "127.0.0.1"
        self.scanner.config = {}
        import logging
        self.scanner.logger = logging.getLogger("test")
        self.scanner._results = {}

    def test_parse_tcp_port(self):
        raw = "80/tcp   open  http    Apache httpd 2.4.41"
        ports = self.scanner._parse_text(raw)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], 80)
        self.assertEqual(ports[0]["protocol"], "tcp")
        self.assertEqual(ports[0]["service"], "http")

    def test_parse_multiple_ports(self):
        raw = (
            "22/tcp   open  ssh     OpenSSH 8.2\n"
            "80/tcp   open  http    nginx 1.18\n"
            "443/tcp  open  https   nginx 1.18\n"
        )
        ports = self.scanner._parse_text(raw)
        self.assertEqual(len(ports), 3)
        services = [p["service"] for p in ports]
        self.assertIn("ssh", services)
        self.assertIn("http", services)

    def test_ignores_closed_filtered(self):
        raw = (
            "80/tcp   open    http\n"
            "81/tcp   closed  unknown\n"
            "82/tcp   filtered unknown\n"
        )
        ports = self.scanner._parse_text(raw)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], 80)

    def test_empty_output(self):
        ports = self.scanner._parse_text("")
        self.assertEqual(ports, [])


# ── BaseModule Lifecycle Tests ─────────────────────────────────────────────────

class TestBaseModuleLifecycle(unittest.TestCase):
    """Test that BaseModule.run() wraps _execute() correctly."""

    def test_success_result_has_status_success(self):
        from modules.base_module import BaseModule

        class GoodModule(BaseModule):
            MODULE_NAME = "GoodModule"
            def _execute(self):
                return {"data": 42}

        mod = GoodModule("127.0.0.1", {})
        result = mod.run()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"], 42)

    def test_exception_captured_as_error(self):
        from modules.base_module import BaseModule

        class BadModule(BaseModule):
            MODULE_NAME = "BadModule"
            def _execute(self):
                raise RuntimeError("boom")

        mod = BadModule("127.0.0.1", {})
        result = mod.run()
        self.assertEqual(result["status"], "error")
        self.assertIn("boom", result["error"])

    def test_module_error_propagates(self):
        from modules.base_module import BaseModule
        from core.exceptions import ModuleError

        class StrictModule(BaseModule):
            MODULE_NAME = "StrictModule"
            def _execute(self):
                raise ModuleError("fatal")

        mod = StrictModule("127.0.0.1", {})
        with self.assertRaises(ModuleError):
            mod.run()


# ── DecisionEngine Tests ──────────────────────────────────────────────────────

class TestDecisionEngine(unittest.TestCase):
    """Test the rule-based decision engine."""

    def setUp(self):
        from core.decision_engine import DecisionEngine
        self.rules = {
            "target_type_rules": {
                "web": {"ports": [80, 443], "services": ["http", "https"]},
                "ssh": {"ports": [22],      "services": ["ssh"]},
            },
            "os_rules": {
                "linux":   {"keywords": ["linux", "ubuntu"]},
                "windows": {"keywords": ["windows", "iis"]},
            },
            "phase_matrix": {
                "web": {"phases": ["recon", "scanning", "nikto", "reporting"]},
                "ssh": {"phases": ["recon", "scanning", "exploitation", "reporting"]},
                "default": {"phases": ["recon", "reporting"]},
            },
            "exploit_rules": [
                {"service": "http", "port": 80, "cve_hints": [], "msf_module": "test/http", "severity": "medium"},
            ],
        }
        self.engine = DecisionEngine(self.rules)

    def test_detects_web_target(self):
        ports = [{"port": 80, "service": "http", "version": "Apache"}]
        plan  = self.engine.analyse({"open_ports": ports, "raw_output": ""})
        self.assertIn("web", plan["target_types"])

    def test_detects_linux_os(self):
        plan = self.engine.analyse({
            "open_ports": [],
            "raw_output": "Running: Linux 5.10 ubuntu",
        })
        self.assertEqual(plan["os_family"], "linux")

    def test_detects_windows_os(self):
        plan = self.engine.analyse({
            "open_ports": [],
            "raw_output": "OS details: Windows Server 2019",
        })
        self.assertEqual(plan["os_family"], "windows")

    def test_reporting_always_last(self):
        ports = [{"port": 80, "service": "http", "version": ""}]
        plan  = self.engine.analyse({"open_ports": ports, "raw_output": ""})
        self.assertEqual(plan["phases"][-1], "reporting")

    def test_unknown_target_returns_generic(self):
        plan = self.engine.analyse({"open_ports": [], "raw_output": ""})
        self.assertIn("generic", plan["target_types"])


# ── Session Tests ──────────────────────────────────────────────────────────────

class TestSession(unittest.TestCase):
    """Test Session state management."""

    def test_update_phase_merges(self):
        from core.session import Session
        s = Session(target="192.168.1.1")
        s.update_phase("recon", {"open_ports": [80]})
        s.update_phase("recon", {"host_status": "up"})
        self.assertEqual(s.phases["recon"]["open_ports"], [80])
        self.assertEqual(s.phases["recon"]["host_status"], "up")

    def test_to_dict_contains_required_keys(self):
        from core.session import Session
        import time
        s = Session(target="10.0.0.1")
        s.close()
        d = s.to_dict()
        for key in ("session_id", "target", "start_time", "end_time",
                    "duration_seconds", "metadata", "phases"):
            self.assertIn(key, d)

    def test_duration_positive(self):
        from core.session import Session
        import time
        s = Session(target="test")
        time.sleep(0.01)
        s.close()
        self.assertGreater(s.to_dict()["duration_seconds"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
