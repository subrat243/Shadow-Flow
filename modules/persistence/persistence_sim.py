"""
modules/persistence/persistence_sim.py
-----------------------------------------
Persistence simulation module — LAB USE ONLY.

This module SIMULATES what an attacker would do to establish
persistence. It:
  - Logs what would be done (never actually modifies the system)
  - Records a full audit trail of each mechanism
  - Provides defenders with detection rules for each technique

Techniques simulated (MITRE ATT&CK mapped):
  T1053.003  Cron job persistence (Linux)
  T1547.001  Registry Run Key (Windows — logged only)
  T1098      Account manipulation (SSH key injection simulation)
  T1136      Create local account (description only)
  T1037.004  RC script modification (Linux, logged only)
"""

import time
from modules.base_module import BaseModule


_TECHNIQUES = [
    {
        "id":          "T1053.003",
        "name":        "Cron Job Persistence",
        "platform":    "linux",
        "command_sim": "echo '*/5 * * * * /tmp/.shadow_flow_agent' >> /var/spool/cron/root",
        "detection":   "Monitor /var/spool/cron & /etc/cron* for unexpected entries.",
        "mitre_url":   "https://attack.mitre.org/techniques/T1053/003/",
    },
    {
        "id":          "T1547.001",
        "name":        "Registry Run Key",
        "platform":    "windows",
        "command_sim": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v ShadowFlow /t REG_SZ /d C:\\tmp\\agent.exe",
        "detection":   "Monitor HKCU/HKLM Run keys via Sysmon EventID 13.",
        "mitre_url":   "https://attack.mitre.org/techniques/T1547/001/",
    },
    {
        "id":          "T1098",
        "name":        "SSH Authorized Key Injection",
        "platform":    "linux",
        "command_sim": "echo 'ssh-rsa AAAAB3N...ATTACKER_KEY' >> ~/.ssh/authorized_keys",
        "detection":   "Monitor ~/.ssh/authorized_keys for changes (inotify/auditd).",
        "mitre_url":   "https://attack.mitre.org/techniques/T1098/",
    },
    {
        "id":          "T1136",
        "name":        "Create Local Account",
        "platform":    "linux",
        "command_sim": "useradd -M -s /bin/bash -c 'shadow' shadow_svc",
        "detection":   "Monitor /etc/passwd changes; alert on new UID < 1000 from non-root.",
        "mitre_url":   "https://attack.mitre.org/techniques/T1136/",
    },
]


class PersistenceSim(BaseModule):
    """
    Simulates persistence techniques — never executes them.
    Produces an audit trail of what would have been attempted.
    """

    MODULE_NAME = "PersistenceSim"

    def _execute(self) -> dict:
        simulation_only = self.config.get("simulation_only", True)

        audit_log = []
        for tech in _TECHNIQUES:
            entry = {
                "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "technique_id": tech["id"],
                "name":         tech["name"],
                "platform":     tech["platform"],
                "simulated_cmd": tech["command_sim"],
                "executed":     False,   # ALWAYS False in sim mode
                "detection_rule": tech["detection"],
                "mitre_url":    tech["mitre_url"],
            }
            audit_log.append(entry)
            self.logger.info(
                f"  [SIM] {tech['id']} — {tech['name']} ({tech['platform']})"
            )
            self.logger.info(f"        CMD  : {tech['command_sim']}")
            self.logger.info(f"        DETECT: {tech['detection']}")

        self.logger.warning(
            f"Persistence simulation complete — {len(audit_log)} technique(s) logged. "
            f"simulation_only={simulation_only}"
        )

        return {
            "persistence_audit": audit_log,
            "simulation_only": simulation_only,
        }
