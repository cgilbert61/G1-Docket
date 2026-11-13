#!/usr/bin/env python3
"""
G1 Docket — Command Line Interface & Management Entrypoint.
Provides runtime mode inspection, readiness validation, and administrative utilities.
Usage:
    python -m docket.cli --check-mode
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to path if needed
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from scripts.check_mode import run_checks, determine_mode
except ImportError:
    # Standalone fallback if scripts package not directly in path
    import importlib.util
    check_mode_path = _PROJECT_ROOT / "scripts" / "check_mode.py"
    if check_mode_path.exists():
        spec = importlib.util.spec_from_file_location("check_mode", str(check_mode_path))
        check_mode = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check_mode)
        run_checks = check_mode.run_checks
        determine_mode = check_mode.determine_mode
    else:
        def determine_mode():
            return "demo", True
        def run_checks():
            print("G1 Docket check_mode script not located.")
            return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m docket.cli",
        description="G1 Docket Enterprise Command Line Interface",
    )
    parser.add_argument(
        "--check-mode",
        action="store_true",
        help="Inspect active runtime mode (demo vs production) and validate deployment readiness.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print quick one-line environment status.",
    )

    args = parser.parse_args(argv)

    if args.check_mode:
        return run_checks()

    if args.status:
        mode_name, is_demo = determine_mode()
        print(f"G1 Docket Mode: {mode_name.upper()} (demo_mode={is_demo})")
        return 0

    # Default action: run mode checker
    return run_checks()


if __name__ == "__main__":
    sys.exit(main())
