"""Run all G1-Docket Atheris fuzz harnesses for a bounded number of executions."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent / "atheris_harnesses"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all G1-Docket Atheris fuzz harnesses")
    parser.add_argument("--runs", type=int, default=2000, help="libFuzzer runs per harness")
    args = parser.parse_args()

    harnesses = sorted(HARNESS_DIR.glob("fuzz_*.py"))
    for harness in harnesses:
        print(f"=== Running {harness.name} ({args.runs} runs) ===", flush=True)
        proc = subprocess.run(
            [sys.executable, str(harness), f"-atheris_runs={args.runs}"],
            check=False,
        )
        if proc.returncode != 0:
            print(f"FAIL: {harness.name} exited with {proc.returncode}", file=sys.stderr)
            return proc.returncode
    print(f"OK: all {len(harnesses)} G1-Docket Atheris harnesses completed {args.runs} runs each.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
