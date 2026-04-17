"""
core/session.py
---------------
Tracks everything that happens during a pentest session:
  - Target metadata
  - Phase results (keyed by phase name)
  - Active exploit/post-exploit sessions
  - Timestamps

Designed as a single source-of-truth dict that gets persisted to a
JSON report at the end of every run.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Session:
    """
    Holds the full state of a penetration testing run.

    Attributes
    ----------
    session_id  : str   – UUID for this run.
    target      : str   – IP or domain being tested.
    start_time  : float – Unix timestamp of session start.
    end_time    : float – Unix timestamp of session end (set on close).
    phases      : dict  – Keyed by phase name → results dict.
    sessions    : list  – Active Metasploit / reverse-shell sessions.
    metadata    : dict  – Any extra key/value pairs (OS, target type, …).
    """

    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    phases: Dict[str, Any] = field(default_factory=dict)
    sessions: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── Convenience helpers ──────────────────────────────────────────────

    def update_phase(self, phase: str, result: dict) -> None:
        """Merge *result* dict into the named phase bucket."""
        if phase not in self.phases:
            self.phases[phase] = {}
        self.phases[phase].update(result)

    def set_metadata(self, key: str, value: Any) -> None:
        """Store arbitrary metadata (OS, target_type, etc.)."""
        self.metadata[key] = value

    def add_session(self, session_info: dict) -> None:
        """Register an active exploit session."""
        session_info.setdefault("opened_at", time.time())
        self.sessions.append(session_info)

    def close(self) -> None:
        """Mark session as complete."""
        self.end_time = time.time()

    def to_dict(self) -> dict:
        """Serialise the session into a plain dict for JSON reporting."""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.end_time - self.start_time, 2),
            "metadata": self.metadata,
            "phases": self.phases,
            "active_sessions": self.sessions,
        }
