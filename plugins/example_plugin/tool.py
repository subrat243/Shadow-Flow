"""
plugins/example_plugin/tool.py
--------------------------------
Example Shadow-Flow plugin — demonstrates how to build a custom tool
that integrates with the framework's plugin system.

To create your own plugin:
  1. Copy this folder → plugins/my_tool/
  2. Edit plugin.json (name, class, phase)
  3. Implement your logic in _execute()
  4. Drop in the plugins/ directory — the loader picks it up automatically.
"""

from modules.base_module import BaseModule


class ExamplePlugin(BaseModule):
    """
    Example plugin: performs a basic ping sweep via subprocess.
    Phase: recon
    """

    MODULE_NAME = "ExamplePlugin"

    def _execute(self) -> dict:
        import subprocess

        self.logger.info(f"[ExamplePlugin] Running ping check on {self.target}")

        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "1", self.target],
                capture_output=True,
                text=True,
                timeout=10,
            )
            alive = result.returncode == 0
        except subprocess.TimeoutExpired:
            alive = False
        except FileNotFoundError:
            alive = False

        self.logger.info(f"[ExamplePlugin] {self.target} is {'UP' if alive else 'DOWN'}")

        return {
            "ping_result": {
                "target": self.target,
                "alive":  alive,
            }
        }
