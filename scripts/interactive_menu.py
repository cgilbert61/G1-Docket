#!/usr/bin/env python3
"""G1 Docket — Interactive Operator & Auditor Verification Launcher.

Provides a unified menu to run any of the 15 enterprise scenarios,
benchmarks, live walkthroughs, compliance evidence exports, or cluster diagnostics.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Menu Item Definitions
MENU_ITEMS = [
    {
        "id": 1,
        "name": "Consolidated 20-Phase Enterprise CI/CD Scorecard",
        "description": "Full end-to-end regression and verification suite across all 20 phases",
        "command": [sys.executable, "scripts/run_all_verifications.py"],
    },
    {
        "id": 2,
        "name": "Live Cluster End-to-End Walkthrough (7 Steps)",
        "description": "Exercises health, prevalidation, egress gating, and WORM ledger",
        "command": [sys.executable, "scripts/demo_walkthrough.py"],
    },
    {
        "id": 3,
        "name": "Snowflake Data Warehouse Zero-Trust RAG Demo",
        "description": "Column-level clearance, dynamic masking, and anti-smuggling",
        "command": [sys.executable, "examples/snowflake_rag_agent_demo.py"],
    },
    {
        "id": 4,
        "name": "Vector Database & Semantic Chunk RAG Demo",
        "description": "DocketVectorRetriever with Pinecone, Milvus, Qdrant, and Chroma",
        "command": [sys.executable, "examples/vector_rag_agent_demo.py"],
    },
    {
        "id": 5,
        "name": "LlamaIndex RAG Node Postprocessor Demo",
        "description": "NodeWithScore cryptographic attestation and hash drift defense",
        "command": [sys.executable, "examples/llamaindex_rag_agent_demo.py"],
    },
    {
        "id": 6,
        "name": "Multi-Agent Swarm Attestation Delegation (<pod:delegate>)",
        "description": "Fortune 500 Section 7 provenance laundering prevention",
        "command": [sys.executable, "examples/multi_agent_swarm_delegation_demo.py"],
    },
    {
        "id": 7,
        "name": "Multi-Agent Cross-Clearance Admission Benchmark",
        "description": "Simulates 50 cross-agent task delegations across tiers",
        "command": [sys.executable, "examples/multi_agent_orchestration_demo.py"],
    },
    {
        "id": 8,
        "name": "CrewAI Multi-Agent Team Zero-Trust Demo",
        "description": "Inter-agent tool execution and task delegation attestation",
        "command": [sys.executable, "examples/crewai_agent_demo.py"],
    },
    {
        "id": 9,
        "name": "LangGraph Workflow State Admission Demo",
        "description": "Attested graph node transitions and clearance enforcement",
        "command": [sys.executable, "examples/langgraph_agent_demo.py"],
    },
    {
        "id": 10,
        "name": "AutoGen Inter-Agent Message Hook Demo",
        "description": "ConversableAgent message hook attestation and egress auditing",
        "command": [sys.executable, "examples/autogen_agent_demo.py"],
    },
    {
        "id": 11,
        "name": "High-Concurrency Latency & Throughput Benchmark",
        "description": "Evaluates p50, p95, and p99 latency under concurrent load",
        "command": [sys.executable, "benchmarks/benchmark_gateway_concurrency.py"],
    },
    {
        "id": 12,
        "name": "Cluster Health & Cryptographic WORM Merkle Chain Audit",
        "description": "Runs 'pod doctor' across all active microservices",
        "command": [sys.executable, "-m", "registry.cli", "doctor"],
    },
    {
        "id": 13,
        "name": "Export SOC 2 Type II Evidence Bundle & Verify Standalone",
        "description": "Packages signed audit ZIP and executes independent verifier",
        "command": [
            sys.executable,
            "-c",
            "import subprocess, sys, glob, os; "
            "subprocess.check_call([sys.executable, 'scripts/export_soc2_evidence.py']); "
            "zips = glob.glob('audit_evidence_bundles/*.zip'); assert zips; "
            "subprocess.check_call([sys.executable, 'scripts/docket_verify_standalone.py', zips[-1]]); "
            "[os.remove(z) for z in zips]",
        ],
    },
    {
        "id": 14,
        "name": "Verify Live Docker Compose Cluster Stack",
        "description": "Validates all 7 containerized services and live inference",
        "command": [sys.executable, "-m", "examples.verify_docker_stack"],
    },
    {
        "id": 15,
        "name": "Enterprise SIEM & SOC OCSF/CEF Exporter Verification",
        "description": "Validates OCSF v1.1.0, ArcSight CEF, and Datadog JSON event formatting",
        "command": [sys.executable, "-m", "pytest", "tests/test_governance_siem.py", "-v"],
    },
    {
        "id": 16,
        "name": "Hyperscale Cryptographic Structures & Filters Suite",
        "description": "Validates CountingBloomFilter (<10us) and 256-bit SparseMerkleTree",
        "command": [sys.executable, "-m", "pytest", "tests/test_hyperscale.py", "-v"],
    },
    {
        "id": 17,
        "name": "Hyperscale Cascading Filter & SMT Proofs Demo",
        "description": "5-scenario multi-billion object admission walkthrough with proofs",
        "command": [sys.executable, "examples/hyperscale_cascading_filter_demo.py"],
    },
    {
        "id": 18,
        "name": "Live Red-Team Attack & Four-Eyes Quarantine Replay Demo",
        "description": "Injects hash drift attack, verifies 403 block, triggers dual-signoff replay",
        "command": [sys.executable, "examples/red_team_quarantine_demo.py"],
    },
    {
        "id": 19,
        "name": "Microsoft Semantic Kernel Zero-Trust Agent Demo",
        "description": "Intercepts plugins, enforces ABAC clearance and watermarking",
        "command": [sys.executable, "examples/semantic_kernel_agent_demo.py"],
    },
    {
        "id": 20,
        "name": "Multi-Region Federation & Split-Brain Resiliency Demo",
        "description": "Active-active 3-region sync, WAN partition autonomy, healing & WORM drain",
        "command": [sys.executable, "examples/multi_region_federation_demo.py"],
    },
]


def display_menu() -> None:
    print("=" * 85)
    print("           G1 DOCKET: INTERACTIVE OPERATOR & AUDITOR CONTROL MENU            ")
    print("=" * 85)
    print(f"{'#':<4} | {'VERIFICATION / DEMO ACTION':<44} | {'DESCRIPTION'}")
    print("-" * 85)
    for item in MENU_ITEMS:
        print(f"[{item['id']:<2}] | {item['name']:<44} | {item['description']}")
    print("=" * 85)
    print(" [0] | Exit\n")


def run_item(choice: int) -> int:
    matched = next((item for item in MENU_ITEMS if item["id"] == choice), None)
    if not matched:
        print(f"[-] Invalid selection: {choice}. Please enter a number between 1 and {len(MENU_ITEMS)}.")
        return 1

    print("\n" + "=" * 85)
    print(f"[*] Executing Action [{matched['id']}]: {matched['name']}")
    print("=" * 85 + "\n")

    try:
        ret = subprocess.call(matched["command"], cwd=str(_REPO_ROOT))
        return ret
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by operator.")
        return 130


def main() -> int:
    parser = argparse.ArgumentParser(description="G1 Docket Interactive Operator Menu")
    parser.add_argument("--choice", type=int, default=None, help="Execute specific action number directly")
    parser.add_argument("--list", action="store_true", help="Print available menu actions and exit")
    args = parser.parse_args()

    if args.list:
        display_menu()
        return 0

    if args.choice is not None:
        return run_item(args.choice)

    while True:
        display_menu()
        try:
            raw = input("Select an action number [1-17] (0 to exit): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return 0

        if not raw or raw == "0":
            print("Exiting G1 Docket Operator Menu.")
            return 0

        try:
            choice = int(raw)
        except ValueError:
            print(f"[-] Please enter a valid integer between 1 and {len(MENU_ITEMS)}.\n")
            continue

        run_item(choice)
        print("\nPress Enter to return to main menu...")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            return 0


if __name__ == "__main__":
    sys.exit(main())
