"""
core/decision_engine.py
------------------------
Rule-based attack path builder.

Given the recon results (open ports + service banners) and the loaded
rules.yaml, this engine:

  1. Identifies the target type  (web / ssh / smb / database / generic)
  2. Identifies the OS family    (linux / windows / unknown)
  3. Builds an ordered list of phases to execute
  4. Recommends exploit modules for each detected service

Design pattern: Strategy – each _detect_* method is a discrete strategy
that could be swapped independently.
"""

from __future__ import annotations
from typing import List, Dict, Any
from core.logger import setup_logger

logger = setup_logger("DecisionEngine")


class DecisionEngine:
    """
    Rule-based engine that reads accumulated recon results and returns
    a prioritised attack plan.

    Parameters
    ----------
    rules : dict
        The 'rules' section from config (loaded from rules.yaml).
    """

    def __init__(self, rules: dict):
        self.rules = rules
        self._target_type_rules: dict = rules.get("target_type_rules", {})
        self._os_rules: dict = rules.get("os_rules", {})
        self._phase_matrix: dict = rules.get("phase_matrix", {})
        self._exploit_rules: list = rules.get("exploit_rules", [])

    # ── Public API ───────────────────────────────────────────────────────

    def analyse(self, recon_results: dict) -> Dict[str, Any]:
        """
        Analyse recon results and return an attack plan.

        Parameters
        ----------
        recon_results : dict
            Output of the recon phase, expected keys:
            - open_ports : list of {port, protocol, service, version}
            - raw_output : str (nmap stdout)

        Returns
        -------
        dict with keys:
            target_types  : list[str]   – detected types (may be multi)
            os_family     : str         – 'linux' | 'windows' | 'unknown'
            phases        : list[str]   – ordered phases to run
            exploit_hints : list[dict]  – recommended exploit modules
        """
        open_ports: List[dict] = recon_results.get("open_ports", [])
        raw_output: str = recon_results.get("raw_output", "")

        target_types = self._detect_target_types(open_ports)
        os_family = self._detect_os(raw_output)
        phases = self._build_phase_list(target_types)
        exploit_hints = self._recommend_exploits(open_ports)

        plan = {
            "target_types": target_types,
            "os_family": os_family,
            "phases": phases,
            "exploit_hints": exploit_hints,
        }

        logger.info(f"Target types detected   : {target_types}")
        logger.info(f"OS family detected      : {os_family}")
        logger.info(f"Attack phases selected  : {phases}")
        logger.info(f"Exploit hints generated : {len(exploit_hints)} hints")

        return plan

    # ── Private helpers ──────────────────────────────────────────────────

    def _detect_target_types(self, open_ports: list) -> List[str]:
        """Match open ports/services against target_type_rules."""
        detected = []
        for type_name, rule in self._target_type_rules.items():
            rule_ports = set(rule.get("ports", []))
            rule_services = [s.lower() for s in rule.get("services", [])]
            for p in open_ports:
                port_match = p["port"] in rule_ports
                service_match = any(
                    svc in p.get("service", "").lower() for svc in rule_services
                ) or any(
                    svc in p.get("version", "").lower() for svc in rule_services
                )
                if port_match or service_match:
                    if type_name not in detected:
                        detected.append(type_name)
                    break
        return detected if detected else ["generic"]

    def _detect_os(self, raw_output: str) -> str:
        """Heuristically determine OS family from nmap raw output."""
        raw_lower = raw_output.lower()
        for os_name, rule in self._os_rules.items():
            for keyword in rule.get("keywords", []):
                if keyword.lower() in raw_lower:
                    return os_name
        return "unknown"

    def _build_phase_list(self, target_types: List[str]) -> List[str]:
        """
        Merge phase lists from all matched target types.
        Preserves order and deduplicates.
        """
        seen = set()
        phases = []
        for t_type in target_types:
            matrix_entry = self._phase_matrix.get(
                t_type, self._phase_matrix.get("default", {})
            )
            for phase in matrix_entry.get("phases", []):
                if phase not in seen:
                    seen.add(phase)
                    phases.append(phase)
        # Always end with reporting
        if "reporting" not in seen:
            phases.append("reporting")
        return phases

    def _recommend_exploits(self, open_ports: list) -> List[dict]:
        """Cross-reference open ports with exploit_rules from rules.yaml."""
        hints = []
        for rule in self._exploit_rules:
            for p in open_ports:
                if p["port"] == rule.get("port") or rule.get("service", "") in p.get(
                    "service", ""
                ).lower():
                    hints.append(
                        {
                            "port": p["port"],
                            "service": p.get("service"),
                            "version": p.get("version"),
                            "msf_module": rule.get("msf_module"),
                            "cve_hints": rule.get("cve_hints", []),
                            "severity": rule.get("severity", "unknown"),
                        }
                    )
                    break
        return hints
