#!/usr/bin/env python3
"""G1 Docket — Multi-Agent Swarm Attestation Delegation (<pod:delegate>) Demo.

Demonstrates Section 7 of the Fortune 500 Enterprise Reference Architecture:
  Multi-Agent Swarm Attestation & Context Delegation (LangGraph, CrewAI & AutoGen)
  1. Provenance Stripping Prevention:
     - Worker Agent A (Clearance: Restricted) summarizes an M&A document.
     - Injects delegation wrapper `<pod:delegate origin_sha256="..." parent_tier="Restricted" agent_id="worker-01">`.
  2. Provenance Laundering Defense:
     - Synthesizer Agent B (Clearance: Public) attempts to query a public cloud LLM with Agent A's summary.
     - Prevalidator detects the `<pod:delegate>` child envelope and calculates:
       effective_tier = max(child, parent) = RESTRICTED.
     - Sub-millisecond hard block (< 140 us): "CLEARANCE_ESCALATION_BLOCKED".
  3. Compliant Downstream Routing:
     - Executive Agent C (Clearance: Restricted) routes Agent A's summary to an air-gapped / internal VPC model.
     - Prevalidator verifies clearance and internal egress, unwraps the delegate envelope, and allows forward dispatch.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import wrap_delegated_context

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main() -> int:
    print("=" * 80)
    print("    G1 DOCKET: MULTI-AGENT SWARM ATTESTATION DELEGATION (<pod:delegate>)    ")
    print("=" * 80)

    client = DocketClient(base_url="http://localhost:18082")
    health = client.get_health()
    print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

    # -------------------------------------------------------------------------
    # Step 1: Upstream Worker Agent A Processes Restricted M&A Document
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Step 1] Worker Agent A (Restricted Clearance) Generates Delegated Summary")
    print("-" * 80)

    merger_content = "Projected Q3 M&A target acquisition valuation: $4.2B with 18% premium."
    origin_sha256 = hashlib.sha256(merger_content.encode("utf-8")).hexdigest()

    # Worker Agent A seals its summary with a <pod:delegate> envelope
    delegated_summary = wrap_delegated_context(
        content=merger_content,
        origin_sha256=origin_sha256,
        parent_tier="Restricted",
        agent_id="worker-merger-01",
        origin_locator="s3://corp-lake/finance/merger_q3.pdf",
    )
    print("  [>] Delegated Payload Created by Worker Agent A:")
    print(f"      {delegated_summary}")

    # -------------------------------------------------------------------------
    # Step 2: Downstream Synthesizer Agent B (Public) Attempts Egress to Public Cloud
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Step 2] Synthesizer Agent B (Public Clearance) -> Public Cloud LLM (gpt-4o)")
    print("-" * 80)
    print("  [!] Attack Vector: Downstream agent attempts to launder restricted context into cloud prompt.")

    try:
        client.chat_completions(
            messages=[
                {"role": "system", "content": "You are a public market communications assistant."},
                {"role": "user", "content": f"Prepare external market bulletin: {delegated_summary}"},
            ],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [-] UNEXPECTED: Restricted delegated context leaked to public cloud!")
        return 1
    except PolicyDenialError as err:
        print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
        print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
        print("  [+] Security Invariant: Provenance stripping thwarted. Low-clearance caller blocked.")

    # -------------------------------------------------------------------------
    # Step 3: Privileged Caller Attempts Public Cloud Egress (Egress Boundary Check)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Step 3] Executive Agent C (Restricted Clearance) -> Public Cloud LLM (gpt-4o)")
    print("-" * 80)
    print("  [!] Attack Vector: High-clearance agent attempts to send Restricted context outside security boundary.")

    try:
        client.chat_completions(
            messages=[
                {"role": "system", "content": "You are an executive analysis assistant."},
                {"role": "user", "content": f"Analyze merger valuation: {delegated_summary}"},
            ],
            model="gpt-4o",
            caller_key="pod-key-restricted",
        )
        print("  [-] UNEXPECTED: Restricted context egressed to external cloud model!")
        return 1
    except PolicyDenialError as err:
        print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
        print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
        print("  [+] Security Invariant: Egress boundary enforced. Restricted context restricted to local/VPC models.")

    # -------------------------------------------------------------------------
    # Step 4: Compliant Routing to Internal Air-Gapped Model
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Step 4] Executive Agent C (Restricted Clearance) -> Air-Gapped Internal Model")
    print("-" * 80)

    res4 = client.chat_completions(
        messages=[
            {"role": "system", "content": "You are an air-gapped executive assistant."},
            {"role": "user", "content": f"Analyze merger valuation: {delegated_summary}"},
        ],
        model="local-model",
        caller_key="pod-key-restricted",
    )
    print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
    print(f"  [+] Gateway Output: {res4['choices'][0]['message']['content']}")
    print("  [+] Security Guarantee: Delegated context unwrapped safely for authorized caller + internal model.")

    print("\n" + "=" * 80)
    print("     ALL MULTI-AGENT SWARM DELEGATION ZERO-TRUST TESTS PASSED      ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
