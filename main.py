"""
main.py
--------
Shadow-Flow — Primary entry point.

Supports two modes:
  1. Non-interactive (CLI flags)  — for automation / CI pipelines
  2. Interactive REPL             — Metasploit-style console (default)

Usage:
  python main.py                              # launch interactive console
  python main.py --target 10.0.0.1            # run full scan (non-interactive)
  python main.py --target 10.0.0.1 --modules recon,scanning
  python main.py --target 10.0.0.1 --config config/custom.yaml
"""

import argparse
import sys
import os

# Ensure the project root is always on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger  import setup_logger
from core.config  import get_config
from core.exceptions import ShadowFlowError

logger = setup_logger("Main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="shadow-flow",
        description="Shadow-Flow — Automated Penetration Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # interactive console
  python main.py --target 10.0.0.1            # full automated run
  python main.py --target 10.0.0.1 --modules recon,scanning,reporting
  python main.py --target scanme.nmap.org --no-html
        """,
    )
    parser.add_argument(
        "--target", "-t",
        metavar="IP/DOMAIN",
        help="Target IP address or domain (skips interactive console)",
    )
    parser.add_argument(
        "--modules", "-m",
        metavar="MODULE_LIST",
        default=None,
        help="Comma-separated modules to run (default: all enabled)",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="PATH",
        default=None,
        help="Path to custom config.yaml (default: config/config.yaml)",
    )
    parser.add_argument(
        "--rules",
        metavar="PATH",
        default=None,
        help="Path to custom rules.yaml (default: config/rules.yaml)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="reports",
        help="Output directory for reports (default: reports/)",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Disable HTML report generation",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Disable JSON report generation",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return parser.parse_args()


def run_automated(args: argparse.Namespace) -> None:
    """Non-interactive mode: load config, build orchestrator, run."""
    from core.orchestrator import Orchestrator

    cfg = get_config(config_path=args.config, rules_path=args.rules)

    # Apply CLI overrides
    cfg["config"]["general"]["output_dir"] = args.output
    cfg["config"]["reporting"]["html"]     = not args.no_html
    cfg["config"]["reporting"]["json"]     = not args.no_json

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    if args.modules:
        requested = [m.strip() for m in args.modules.split(",")]
        cfg["config"]["_enabled_modules"] = requested

    logger.info("=" * 60)
    logger.info(f"  Shadow-Flow v1.0.0  |  Target: {args.target}")
    logger.info("=" * 60)

    try:
        orchestrator = Orchestrator(
            target=args.target,
            config=cfg["config"],
            rules=cfg["rules"],
        )
        session = orchestrator.run()
        logger.info(f"Run complete. Session ID: {session.session_id}")
        sys.exit(0)

    except ShadowFlowError as exc:
        logger.error(f"Framework error: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(130)


def run_interactive() -> None:
    """Interactive REPL console mode."""
    from cli.console import Console
    console = Console()
    console.start()


def main() -> None:
    args = parse_args()

    if args.target:
        # Non-interactive: target supplied on CLI
        run_automated(args)
    else:
        # Interactive REPL
        run_interactive()


if __name__ == "__main__":
    main()
