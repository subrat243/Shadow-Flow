"""
core/config.py
--------------
Loads and validates the YAML configuration file.
Exposes a single get_config() call that returns the merged config dict.
"""

import os
import yaml
from core.exceptions import ConfigError

_DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "config.yaml"
)
_DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "rules.yaml"
)


def _load_yaml(path: str) -> dict:
    """Load a YAML file and return its content as a dict."""
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")
    try:
        with open(path, "r") as fh:
            return yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML at {path}: {exc}") from exc


def get_config(config_path: str = None, rules_path: str = None) -> dict:
    """
    Load and return the merged configuration.

    Parameters
    ----------
    config_path : str, optional
        Path to config.yaml.  Defaults to config/config.yaml.
    rules_path : str, optional
        Path to rules.yaml.  Defaults to config/rules.yaml.

    Returns
    -------
    dict
        A dict with keys 'config' and 'rules'.
    """
    cfg = _load_yaml(config_path or _DEFAULT_CONFIG_PATH)
    rules = _load_yaml(rules_path or _DEFAULT_RULES_PATH)
    return {"config": cfg, "rules": rules}
