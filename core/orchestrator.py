"""
core/orchestrator.py
---------------------
Master phase sequencer.

The Orchestrator:
  1. Accepts a target, config, and attack plan from the DecisionEngine
  2. Instantiates and runs each module in order
  3. Feeds each phase's output into the Session object
  4. Triggers reporting at the end

Design pattern: Template Method — the run() method defines the skeleton;
individual module calls are overridable steps.
"""

from __future__ import annotations
import importlib
from typing import Dict, Any

from core.logger import setup_logger
from core.session import Session
from core.decision_engine import DecisionEngine
from core.exceptions import ModuleError

logger = setup_logger("Orchestrator")


# Maps phase names → (module_path, class_name)
_PHASE_MODULE_MAP: Dict[str, tuple] = {
    "recon":         ("modules.recon.nmap_scanner",          "NmapScanner"),
    "dns":           ("modules.recon.dns_enum",              "DnsEnum"),
    "subdomain":     ("modules.recon.subdomain_enum",        "SubdomainEnum"),
    "scanning":      ("modules.scanning.nse_scanner",        "NseScanner"),
    "nikto":         ("modules.scanning.nikto_scanner",      "NiktoScanner"),
    "exploitation":  ("modules.exploitation.msf_rpc",        "MsfRpc"),
    "persistence":   ("modules.persistence.persistence_sim", "PersistenceSim"),
    "network_monitor": ("modules.network_monitor.tcpdump_capture", "TcpdumpCapture"),
}


class Orchestrator:
    """
    Drives the full penetration testing lifecycle.

    Parameters
    ----------
    target      : str   – IP address or domain to test.
    config      : dict  – Loaded config.yaml content.
    rules       : dict  – Loaded rules.yaml content.
    """

    def __init__(self, target: str, config: dict, rules: dict):
        self.target = target
        self.config = config
        self.rules = rules
        self.session = Session(target=target)
        self.decision_engine = DecisionEngine(rules)

    # ── Main entry point ─────────────────────────────────────────────────

    def run(self) -> Session:
        """
        Execute the full attack lifecycle.

        Returns the completed Session object, ready for reporting.
        """
        logger.info("=" * 60)
        logger.info(f"  Shadow-Flow  |  Target: {self.target}")
        logger.info(f"  Session ID  : {self.session.session_id}")
        logger.info("=" * 60)

        # ── Phase 1: Reconnaissance (always first) ───────────────────────
        recon_result = self._run_phase("recon", self.config.get("recon", {}))
        self.session.update_phase("recon", recon_result)

        # ── Decision Engine: build the rest of the attack plan ───────────
        plan = self.decision_engine.analyse(recon_result)
        self.session.set_metadata("target_types", plan["target_types"])
        self.session.set_metadata("os_family", plan["os_family"])
        self.session.set_metadata("exploit_hints", plan["exploit_hints"])

        logger.info(f"[*] Attack plan: {plan['phases']}")

        # ── Remaining phases ─────────────────────────────────────────────
        for phase in plan["phases"]:
            if phase in ("recon", "reporting"):
                continue  # recon already done; reporting handled below
            phase_cfg = self.config.get(phase, {})
            result = self._run_phase(phase, phase_cfg)
            if result:
                self.session.update_phase(phase, result)

        # ── Reporting ────────────────────────────────────────────────────
        self._generate_reports()

        self.session.close()
        logger.info("=" * 60)
        logger.info(f"  Session complete  |  Duration: "
                    f"{self.session.end_time - self.session.start_time:.1f}s")
        logger.info("=" * 60)

        return self.session

    # ── Helpers ──────────────────────────────────────────────────────────

    def _run_phase(self, phase: str, phase_cfg: dict) -> dict:
        """Dynamically load and execute the module for a given phase."""
        if phase not in _PHASE_MODULE_MAP:
            logger.warning(f"[!] No module mapped for phase: '{phase}' — skipping.")
            return {}

        module_path, class_name = _PHASE_MODULE_MAP[phase]
        logger.info(f"\n[>>>] Phase: {phase.upper()}")

        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            instance = cls(self.target, phase_cfg)
            result = instance.run()
            return result if isinstance(result, dict) else {}

        except ImportError as exc:
            logger.warning(f"[!] Module '{module_path}' not yet implemented: {exc}")
            return {}
        except ModuleError as exc:
            logger.error(f"[!] Phase '{phase}' failed: {exc}")
            return {"error": str(exc)}
        except Exception as exc:
            logger.error(f"[!] Unexpected error in phase '{phase}': {exc}")
            return {"error": str(exc)}

    def _generate_reports(self) -> None:
        """Generate JSON and HTML reports from the session data."""
        from reporting.json_reporter import JsonReporter
        from reporting.html_reporter import HtmlReporter
        import os

        out_dir = self.config.get("general", {}).get("output_dir", "reports")
        os.makedirs(out_dir, exist_ok=True)

        report_cfg = self.config.get("reporting", {})

        if report_cfg.get("json", True):
            JsonReporter(self.session, out_dir).generate()

        if report_cfg.get("html", True):
            HtmlReporter(self.session, out_dir).generate()
