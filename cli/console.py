"""
cli/console.py
--------------
Shadow-Flow interactive REPL console — Metasploit-style interface.

Commands available:
  set target <ip/domain>      Set the current target
  set module <name>           Enable/disable a module
  set config <key> <value>    Override a config value at runtime
  show modules                List available modules and their status
  show plugins                List loaded plugins
  show config                 Print current config
  run                         Execute the full attack workflow
  run recon                   Execute a single phase
  help                        Show this help text
  exit / quit                 Exit the console

The console feeds directly into the Orchestrator engine.
"""

import os
import sys
import readline   # enables arrow-key history in input()

from core.config import get_config
from core.orchestrator import Orchestrator
from core.logger import setup_logger
from plugins.plugin_loader import PluginLoader

logger = setup_logger("Console")

# ── ANSI colours ─────────────────────────────────────────────────────────────
_R  = "\033[0;31m"   # red
_G  = "\033[0;32m"   # green
_Y  = "\033[0;33m"   # yellow
_B  = "\033[0;34m"   # blue
_C  = "\033[0;36m"   # cyan
_W  = "\033[0;37m"   # white
_BO = "\033[1m"      # bold
_RS = "\033[0m"      # reset

_BANNER = f"""
{_C}
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗      ███████╗██╗      ██████╗ ██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║      ██╔════╝██║     ██╔═══██╗██║    ██║
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗█████╗  ██║     ██║   ██║██║ █╗ ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════╝██╔══╝  ██║     ██║   ██║██║███╗██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝      ██║     ███████╗╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
{_RS}
  {_Y}Automated Penetration Testing Toolkit  v1.0.0{_RS}
  {_W}For authorized use in lab environments only.{_RS}
  Type {_G}help{_RS} for available commands.
"""

_AVAILABLE_MODULES = [
    "recon", "dns", "subdomain",
    "scanning", "nikto",
    "exploitation",
    "persistence", "network_monitor",
]


class Console:
    """
    Interactive REPL console for Shadow-Flow.
    Maintains session state between commands.
    """

    def __init__(self):
        self.target: str          = ""
        self.enabled_modules: set = set(_AVAILABLE_MODULES)
        self.cfg                  = get_config()
        self.plugins              = PluginLoader().load_all()
        self._running             = True

    # ── Entry point ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Print banner and enter the REPL loop."""
        print(_BANNER)
        self._print_status()

        while self._running:
            try:
                raw = input(f"{_C}shadow-flow{_RS} {_R}>{_RS} ").strip()
            except (KeyboardInterrupt, EOFError):
                self._cmd_exit()
                break

            if not raw:
                continue

            self._dispatch(raw)

    # ── Command dispatcher ───────────────────────────────────────────────────

    def _dispatch(self, raw: str) -> None:
        parts = raw.split()
        cmd   = parts[0].lower()

        dispatch_table = {
            "set":    self._cmd_set,
            "show":   self._cmd_show,
            "run":    self._cmd_run,
            "help":   self._cmd_help,
            "exit":   self._cmd_exit,
            "quit":   self._cmd_exit,
            "banner": lambda _: print(_BANNER),
            "clear":  lambda _: os.system("clear"),
        }

        handler = dispatch_table.get(cmd)
        if handler:
            handler(parts[1:])
        else:
            print(f"  {_R}Unknown command: {cmd}{_RS}  (type 'help')")

    # ── Commands ─────────────────────────────────────────────────────────────

    def _cmd_set(self, args: list) -> None:
        if len(args) < 2:
            print(f"  {_Y}Usage: set <key> <value>{_RS}")
            return

        key   = args[0].lower()
        value = " ".join(args[1:])

        if key == "target":
            self.target = value
            print(f"  {_G}[+]{_RS} target => {_BO}{value}{_RS}")

        elif key == "module":
            mod = value.lower()
            if mod in self.enabled_modules:
                self.enabled_modules.discard(mod)
                print(f"  {_Y}[-]{_RS} Module {mod} DISABLED")
            else:
                self.enabled_modules.add(mod)
                print(f"  {_G}[+]{_RS} Module {mod} ENABLED")

        elif key == "config":
            # Allow runtime override: set config exploitation.enabled true
            parts = value.split(None, 1)
            if len(parts) == 2:
                cfg_key, cfg_val = parts
                self._set_nested_config(cfg_key, cfg_val)
            else:
                print(f"  {_Y}Usage: set config <dotted.key> <value>{_RS}")

        else:
            print(f"  {_R}Unknown key: {key}{_RS}")

    def _cmd_show(self, args: list) -> None:
        if not args:
            print(f"  {_Y}Usage: show <modules|plugins|config|target>{_RS}")
            return

        what = args[0].lower()

        if what == "modules":
            print(f"\n  {_C}{'Module':<20} {'Status'}{_RS}")
            print(f"  {'─'*35}")
            for mod in _AVAILABLE_MODULES:
                status = f"{_G}enabled{_RS}" if mod in self.enabled_modules else f"{_R}disabled{_RS}"
                print(f"  {mod:<20} {status}")
            print()

        elif what == "plugins":
            if self.plugins:
                print(f"\n  {_C}Loaded Plugins:{_RS}")
                for name in self.plugins:
                    print(f"    {_G}+{_RS} {name}")
            else:
                print(f"  {_Y}No plugins loaded.{_RS}")
            print()

        elif what == "config":
            import json
            print(f"\n{_C}{json.dumps(self.cfg['config'], indent=4)}{_RS}\n")

        elif what == "target":
            t = self.target or f"{_R}(not set){_RS}"
            print(f"  Target: {_BO}{t}{_RS}")

        else:
            print(f"  {_R}Unknown: {what}{_RS}")

    def _cmd_run(self, args: list) -> None:
        if not self.target:
            print(f"  {_R}[!] No target set. Use: set target <ip/domain>{_RS}")
            return

        phase_filter = args[0].lower() if args else None

        print(f"\n  {_G}[*]{_RS} Starting Shadow-Flow against {_BO}{self.target}{_RS}\n")

        # Inject enabled module list into config so orchestrator respects it
        self.cfg["config"]["_enabled_modules"] = list(self.enabled_modules)
        if phase_filter:
            self.cfg["config"]["_phase_filter"] = phase_filter

        try:
            orchestrator = Orchestrator(
                target=self.target,
                config=self.cfg["config"],
                rules=self.cfg["rules"],
            )
            session = orchestrator.run()
            print(f"\n  {_G}[✓]{_RS} Session {session.session_id} complete.")
        except KeyboardInterrupt:
            print(f"\n  {_Y}[!] Run interrupted by user.{_RS}")
        except Exception as exc:
            print(f"\n  {_R}[!] Error during run: {exc}{_RS}")
            logger.exception("Run error")

    def _cmd_help(self, _) -> None:
        help_text = f"""
{_C}Shadow-Flow Command Reference{_RS}
{'─'*50}
{_G}set target <ip/domain>{_RS}         Set the target
{_G}set module <name>{_RS}              Toggle a module on/off
{_G}set config <dotted.key> <value>{_RS} Override a config value
{_G}show modules{_RS}                   List all modules + status
{_G}show plugins{_RS}                   List loaded plugins
{_G}show config{_RS}                    Print current config
{_G}show target{_RS}                    Print current target
{_G}run{_RS}                            Execute full attack workflow
{_G}run <phase>{_RS}                    Execute a single phase
{_G}banner{_RS}                         Reprint banner
{_G}clear{_RS}                          Clear terminal
{_G}exit / quit{_RS}                    Exit Shadow-Flow
"""
        print(help_text)

    def _cmd_exit(self, *_) -> None:
        print(f"\n  {_Y}Exiting Shadow-Flow. Stay ethical.{_RS}\n")
        self._running = False

    # ── Utilities ────────────────────────────────────────────────────────────

    def _print_status(self) -> None:
        target_str = self.target or f"{_R}not set{_RS}"
        print(f"  Target  : {_BO}{target_str}{_RS}")
        print(f"  Modules : {_G}{len(self.enabled_modules)}{_RS}/{len(_AVAILABLE_MODULES)} enabled")
        print(f"  Plugins : {_G}{len(self.plugins)}{_RS} loaded\n")

    def _set_nested_config(self, dotted_key: str, value: str) -> None:
        """Set a nested config value using dot-notation (e.g. exploitation.enabled)."""
        keys  = dotted_key.split(".")
        cfg   = self.cfg["config"]
        for k in keys[:-1]:
            cfg = cfg.setdefault(k, {})
        # Auto-cast booleans and ints
        if value.lower() in ("true", "yes"):
            value = True
        elif value.lower() in ("false", "no"):
            value = False
        else:
            try:
                value = int(value)
            except ValueError:
                pass
        cfg[keys[-1]] = value
        print(f"  {_G}[+]{_RS} config.{dotted_key} => {_BO}{value}{_RS}")
