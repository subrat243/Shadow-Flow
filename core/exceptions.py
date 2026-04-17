"""
core/exceptions.py
------------------
Custom exception hierarchy for Shadow-Flow.
All framework-level errors inherit from ShadowFlowError so callers
can catch toolkit errors without swallowing Python built-ins.
"""


class ShadowFlowError(Exception):
    """Base exception for the entire Shadow-Flow framework."""


class ConfigError(ShadowFlowError):
    """Raised when configuration is missing or invalid."""


class ModuleError(ShadowFlowError):
    """Raised when a module fails to initialise or execute."""


class ToolNotFoundError(ModuleError):
    """Raised when an external tool (nmap, nikto, etc.) is not installed."""


class ScanError(ModuleError):
    """Raised on scan / enumeration failures."""


class ExploitError(ShadowFlowError):
    """Raised during exploitation phase errors."""


class MsfRpcError(ExploitError):
    """Raised on Metasploit RPC connection or command errors."""


class ReportingError(ShadowFlowError):
    """Raised when report generation fails."""


class PluginError(ShadowFlowError):
    """Raised when a plugin fails to load or execute."""


class SessionError(ShadowFlowError):
    """Raised on session management failures."""
