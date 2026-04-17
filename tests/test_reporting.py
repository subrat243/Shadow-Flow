"""
tests/test_reporting.py
------------------------
Unit tests for the reporting layer.

Tests cover:
  - JsonReporter produces valid JSON with required keys
  - HtmlReporter renders without errors (template smoke test)
  - Severity → CVSS score mapping
  - Attack chain building
"""

import unittest
import json
import os
import tempfile


def _make_session():
    """Helper: return a populated Session object."""
    from core.session import Session
    s = Session(target="10.0.0.1")
    s.update_phase("recon", {
        "open_ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",  "version": "OpenSSH 8.2"},
        ],
        "host_status": "up",
        "os_guess": {"name": "Linux", "accuracy": "95"},
    })
    s.update_phase("scanning", {
        "script_findings": [
            {"port": 80, "protocol": "tcp", "script": "http-headers",
             "output": "Server: Apache", "is_vuln": False},
            {"port": 80, "protocol": "tcp", "script": "http-vuln-cve2017-5638",
             "output": "VULNERABLE: Apache Struts RCE", "is_vuln": True},
        ]
    })
    s.set_metadata("target_types", ["web"])
    s.set_metadata("os_family",    "linux")
    s.set_metadata("exploit_hints", [
        {"port": 80, "service": "http", "version": "Apache 2.4",
         "msf_module": "exploit/test", "cve_hints": ["CVE-0000-0001"], "severity": "high"},
    ])
    s.close()
    return s


class TestJsonReporter(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.session = _make_session()

    def test_generates_file(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        self.assertTrue(os.path.exists(path))

    def test_valid_json(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        with open(path) as fh:
            data = json.load(fh)
        self.assertIsInstance(data, dict)

    def test_required_top_level_keys(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        with open(path) as fh:
            data = json.load(fh)
        for key in ("meta", "vulnerabilities", "attack_chain", "target_profile"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_meta_has_target(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        with open(path) as fh:
            data = json.load(fh)
        self.assertEqual(data["meta"]["target"], "10.0.0.1")

    def test_attack_chain_not_empty(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        with open(path) as fh:
            data = json.load(fh)
        self.assertGreater(len(data["attack_chain"]), 0)

    def test_vulnerability_cvss_score(self):
        from reporting.json_reporter import JsonReporter
        path = JsonReporter(self.session, self.tmp).generate()
        with open(path) as fh:
            data = json.load(fh)
        vulns = data["vulnerabilities"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cvss_approx"], 7.5)  # high


class TestSeverityMapping(unittest.TestCase):

    def test_all_severities(self):
        from reporting.json_reporter import _severity_to_cvss
        self.assertEqual(_severity_to_cvss("critical"), 9.0)
        self.assertEqual(_severity_to_cvss("high"),     7.5)
        self.assertEqual(_severity_to_cvss("medium"),   5.0)
        self.assertEqual(_severity_to_cvss("low"),      2.5)
        self.assertEqual(_severity_to_cvss("info"),     0.0)
        self.assertEqual(_severity_to_cvss("unknown"),  0.0)


class TestHtmlReporter(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.session = _make_session()

    def test_generates_html_file(self):
        try:
            from reporting.html_reporter import HtmlReporter
            path = HtmlReporter(self.session, self.tmp).generate()
            if path:  # jinja2 may not be installed in CI
                self.assertTrue(path.endswith(".html"))
                self.assertTrue(os.path.exists(path))
        except ImportError:
            self.skipTest("jinja2 not installed")

    def test_html_contains_target(self):
        try:
            from reporting.html_reporter import HtmlReporter
            path = HtmlReporter(self.session, self.tmp).generate()
            if path:
                with open(path) as fh:
                    content = fh.read()
                self.assertIn("10.0.0.1", content)
        except ImportError:
            self.skipTest("jinja2 not installed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
