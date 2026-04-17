"""
plugins/plugin_loader.py
--------------------------
Dynamic plugin discovery and loading system.

Design pattern: Plugin / Factory
  - Scans the plugins/ directory for sub-folders containing plugin.json
  - Validates the manifest schema
  - Dynamically imports and instantiates the plugin class
  - Plugins are treated as first-class modules — they implement BaseModule

Plugin manifest (plugin.json):
  {
    "name":        "my_tool",
    "version":     "1.0.0",
    "author":      "you",
    "description": "What this plugin does",
    "entry":       "tool.py",
    "class":       "MyToolClass",
    "phase":       "recon"
  }
"""

import json
import importlib.util
import os
import sys
from typing import List, Dict, Any

from core.logger import setup_logger
from core.exceptions import PluginError

logger = setup_logger("PluginLoader")

_PLUGIN_DIR = os.path.dirname(__file__)
_REQUIRED_MANIFEST_KEYS = {"name", "entry", "class", "phase"}


class PluginLoader:
    """
    Discovers, validates, and loads Shadow-Flow plugins.

    Usage:
        loader = PluginLoader()
        plugins = loader.load_all()
        for name, plugin_class in plugins.items():
            instance = plugin_class(target, config)
            result = instance.run()
    """

    def __init__(self, plugin_dir: str = None):
        self.plugin_dir = plugin_dir or _PLUGIN_DIR
        self._loaded: Dict[str, Any] = {}

    def discover(self) -> List[dict]:
        """Scan plugin directory and return list of valid manifests."""
        manifests = []
        for entry in os.scandir(self.plugin_dir):
            if not entry.is_dir():
                continue
            manifest_path = os.path.join(entry.path, "plugin.json")
            if not os.path.exists(manifest_path):
                continue
            try:
                with open(manifest_path) as fh:
                    manifest = json.load(fh)
                manifest["_path"] = entry.path
                self._validate_manifest(manifest)
                manifests.append(manifest)
                logger.info(f"[PluginLoader] Found plugin: {manifest['name']} v{manifest.get('version','?')}")
            except (json.JSONDecodeError, PluginError) as exc:
                logger.warning(f"[PluginLoader] Skipping {entry.path}: {exc}")
        return manifests

    def load_all(self) -> Dict[str, Any]:
        """Load all discovered plugins; return {name: class} dict."""
        for manifest in self.discover():
            try:
                cls = self._load_plugin(manifest)
                self._loaded[manifest["name"]] = cls
            except PluginError as exc:
                logger.error(f"[PluginLoader] Failed to load {manifest['name']}: {exc}")
        logger.info(f"[PluginLoader] Loaded {len(self._loaded)} plugin(s).")
        return self._loaded

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _validate_manifest(manifest: dict) -> None:
        """Raise PluginError if required keys are missing."""
        missing = _REQUIRED_MANIFEST_KEYS - set(manifest.keys())
        if missing:
            raise PluginError(f"Manifest missing keys: {missing}")

    def _load_plugin(self, manifest: dict) -> Any:
        """Dynamically import and return the plugin class."""
        plugin_path = manifest["_path"]
        entry_file  = os.path.join(plugin_path, manifest["entry"])
        class_name  = manifest["class"]

        if not os.path.exists(entry_file):
            raise PluginError(f"Entry file not found: {entry_file}")

        spec = importlib.util.spec_from_file_location(manifest["name"], entry_file)
        module = importlib.util.module_from_spec(spec)
        sys.modules[manifest["name"]] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise PluginError(f"Error executing plugin module: {exc}") from exc

        if not hasattr(module, class_name):
            raise PluginError(f"Class '{class_name}' not found in {entry_file}")

        return getattr(module, class_name)
