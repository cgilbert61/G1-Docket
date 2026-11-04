#!/usr/bin/env python3
"""G1 Docket — Unified Enterprise CI/CD & Cluster Verification Scorecard Runner.

Executes end-to-end multi-phase validation across the entire G1 Docket estate:
  Phase 1: Cluster Health & WORM Merkle Chain Audit (CLI Doctor)
  Phase 2: Core SDK, ABAC, and Prevalidator Test Suite (pytest tests/)
  Phase 3: Consumer Conformance Test Suite (pytest conformance/)
  Phase 4: Multi-Agent Cross-Clearance Admission Control Scenario
  Phase 5: High-Concurrency Latency & Throughput Benchmark (2,000 probes)
  Phase 6: Forensic Watermarking & Provenance Attribution Validation
  Phase 7: SOC 2 & ISO 27001 Cryptographic Compliance Audit Report
  Phase 8: Snowflake Zero-Trust Admission Demo
  Phase 9: CrewAI Multi-Agent Team Zero-Trust Demo
  Phase 10: LangGraph Workflow State Admission Demo
  Phase 11: AutoGen Multi-Agent Message Hook Demo
  Phase 12: SOC 2 Evidence Export & Standalone Air-Gapped Verifier

Exports:
  - `reports/VERIFICATION_SCORECARD.json`
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure UTF-8 output encoding if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

_REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class PhaseResult:
    phase_id: int
    name: str
    command: str
    status: str
    duration_s: float
    output_snippet: str
    details: dict[str, Any]


def run_phase(phase_id: int, name: str, command: list[str]) -> PhaseResult:
    cmd_str = " ".join(command)
    print(f"\n[{phase_id}/7] Executing: {name}...")
    print(f"      Command: {cmd_str}")

    t0 = time.perf_counter()
    try:
        res = subprocess.run(
            command,
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        duration_s = time.perf_counter() - t0
        output = (res.stdout + "\n" + res.stderr).strip()
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        snippet = "\n".join(lines[-4:]) if lines else "Done."

        is_success = res.returncode == 0
        status_str = "PASS" if is_success else "FAIL"
        tag = "[+] PASS" if is_success else "[-] FAIL"
        print(f"      {tag} in {duration_s:.2f}s (Exit code: {res.returncode})")

        return PhaseResult(
            phase_id=phase_id,
            name=name,
            command=cmd_str,
            status=status_str,
            duration_s=round(duration_s, 2),
            output_snippet=snippet,
            details={"exit_code": res.returncode},
        )
    except Exception as exc:
        duration_s = time.perf_counter() - t0
        print(f"      [-] ERROR: {exc}")
        return PhaseResult(
            phase_id=phase_id,
            name=name,
            command=cmd_str,
            status="ERROR",
            duration_s=round(duration_s, 2),
            output_snippet=str(exc),
            details={"error": str(exc)},
        )


def main() -> int:
    print("=" * 85)
    print("      G1 DOCKET: UNIFIED ENTERPRISE CI/CD & CLUSTER VERIFICATION SCORECARD     ")
    print("=" * 85)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()} | Root: {_REPO_ROOT}")

    phases: list[PhaseResult] = []

    # Phase 1: Doctor Diagnostics & WORM Chain
    phases.append(run_phase(1, "Cluster Health & WORM Merkle Chain Audit", [sys.executable, "-m", "registry.cli", "doctor"]))

    # Phase 2: Core Test Suite
    phases.append(run_phase(2, "Core SDK, ABAC, and Prevalidator Test Suite", [sys.executable, "-m", "pytest", "tests/", "-q"]))

    # Phase 3: Conformance Suite
    phases.append(run_phase(3, "Consumer Conformance Test Suite", [sys.executable, "-m", "pytest", "conformance/", "-q"]))

    # Phase 4: Multi-Agent Orchestration Benchmark
    phases.append(run_phase(4, "Multi-Agent Cross-Clearance Admission Control", [sys.executable, "examples/multi_agent_orchestration_demo.py"]))

    # Phase 5: High-Concurrency Latency Benchmark
    phases.append(run_phase(5, "High-Concurrency Latency & Throughput Benchmark", [sys.executable, "benchmarks/benchmark_gateway_concurrency.py"]))

    # Phase 6: Forensic Watermarking
    phases.append(run_phase(6, "Forensic Watermarking & Provenance Verification", [sys.executable, "-m", "pytest", "tests/test_watermark.py", "-q"]))

    # Phase 7: SOC 2 Compliance Report
    phases.append(run_phase(7, "SOC 2 & ISO 27001 Cryptographic Audit Reporter", [sys.executable, "scripts/generate_compliance_report.py"]))

    # Phase 8: Snowflake Zero-Trust Admission Demo
    phases.append(run_phase(8, "Snowflake Zero-Trust Admission Demo", [sys.executable, "examples/snowflake_rag_agent_demo.py"]))

    # Phase 9: CrewAI Multi-Agent Team Demo
    phases.append(run_phase(9, "CrewAI Multi-Agent Team Zero-Trust Demo", [sys.executable, "examples/crewai_agent_demo.py"]))

    # Phase 10: LangGraph Workflow Admission Demo
    phases.append(run_phase(10, "LangGraph Workflow State Admission Demo", [sys.executable, "examples/langgraph_agent_demo.py"]))

    # Phase 11: AutoGen Multi-Agent Message Hook Demo
    phases.append(run_phase(11, "AutoGen Multi-Agent Message Hook Demo", [sys.executable, "examples/autogen_agent_demo.py"]))

    # Phase 12: SOC 2 Evidence Packager & Standalone Air-Gapped Verification
    phases.append(run_phase(12, "SOC 2 Evidence Export & Standalone Verifier", [sys.executable, "-c", "import subprocess, sys, glob, os; subprocess.check_call([sys.executable, 'scripts/export_soc2_evidence.py']); zips = glob.glob('audit_evidence_bundles/*.zip'); assert zips; subprocess.check_call([sys.executable, 'scripts/docket_verify_standalone.py', zips[-1]]); [os.remove(z) for z in zips]"]))

    # Summary Scorecard
    total_phases = len(phases)
    passed_phases = sum(1 for p in phases if p.status == "PASS")
    total_duration = sum(p.duration_s for p in phases)

    print("\n" + "=" * 85)
    print(f"{'PHASE':<4} | {'VERIFICATION PHASE NAME':<46} | {'STATUS':<6} | {'DURATION'}")
    print("-" * 85)
    for p in phases:
        status_col = "PASS" if p.status == "PASS" else "FAIL"
        print(f"[{p.phase_id:<2}] | {p.name:<46} | {status_col:<6} | {p.duration_s:>6.2f}s")
    print("=" * 85)
    print(f"SCORECARD RESULT: {passed_phases}/{total_phases} PHASES PASSED in {total_duration:.1f}s")

    # Export machine-readable scorecard
    reports_dir = _REPO_ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    scorecard_path = reports_dir / "VERIFICATION_SCORECARD.json"

    scorecard_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_phases": total_phases,
        "passed_phases": passed_phases,
        "failed_phases": total_phases - passed_phases,
        "total_duration_seconds": round(total_duration, 2),
        "all_passed": passed_phases == total_phases,
        "phases": [asdict(p) for p in phases],
    }

    with open(scorecard_path, "w", encoding="utf-8") as f:
        json.dump(scorecard_data, f, indent=2)
    print(f"[+] Consolidated Scorecard exported to: {scorecard_path}\n")

    return 0 if passed_phases == total_phases else 1


if __name__ == "__main__":
    sys.exit(main())
