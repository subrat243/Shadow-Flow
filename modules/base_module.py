"""
modules/base_module.py
-----------------------
Abstract base class for every Shadow-Flow module.

All modules MUST:
  - Accept (target: str, config: dict) in __init__
  - Implement run() → dict
  - Use self.logger for all output
  - Raise core.exceptions.ModuleError on fatal failure

Design pattern: Template Method — run() is the public template;
subclasses fill in _execute() with their specific logic.
"""

from abc import ABC, abstractmethod
from core.logger import setup_logger
from core.exceptions import ModuleError


class BaseModule(ABC):
    """
    Abstract base for all Shadow-Flow modules.

    Parameters
    ----------
    target : str   – IP address or domain being tested.
    config : dict  – Module-specific config slice from config.yaml.
    """

    MODULE_NAME: str = "BaseModule"

    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.logger = setup_logger(self.MODULE_NAME)
        self._results: dict = {
            "module": self.MODULE_NAME,
            "target": target,
            "status": "pending",
        }

    # ── Public template method ───────────────────────────────────────────

    def run(self) -> dict:
        """
        Execute the module and return results.

        Wraps _execute() with standard logging and error handling.
        """
        self.logger.info(f"[{self.MODULE_NAME}] Starting against {self.target}")
        try:
            result = self._execute()
            self._results["status"] = "success"
            self._results.update(result or {})
        except ModuleError:
            raise
        except Exception as exc:
            self._results["status"] = "error"
            self._results["error"] = str(exc)
            self.logger.error(f"[{self.MODULE_NAME}] Unexpected error: {exc}")
        self.logger.info(f"[{self.MODULE_NAME}] Completed — status: {self._results['status']}")
        return self._results

    # ── Abstract method subclasses must implement ────────────────────────

    @abstractmethod
    def _execute(self) -> dict:
        """
        Core module logic.  Must return a dict of results.
        Raise ModuleError on fatal failure.
        """
