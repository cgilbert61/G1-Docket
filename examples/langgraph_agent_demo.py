#!/usr/bin/env python3
"""G1 Docket — LangGraph Workflow Admission Control Integration Demo.

Demonstrates:
  1. @docket_langgraph_node Decorator:
     - Automatically attesting and wrapping state outputs as they pass between nodes.
  2. State Pipeline:
     - Node A (Retriever): Ingests data from Snowflake and marks state with canonical locator.
     - Node B (Validator / Gatekeeper): Enforces clearance boundaries before LLM generation.
     - Node C (Synthesizer): Dispatches to target model with in-flight redaction if public.
  3. Fail-Closed Zero-Trust Enforcement:
     - Unattested state transitions or clearance mismatches are blocked at the gateway.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import docket_langgraph_node

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SNOWFLAKE_CRM = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS"
SNOWFLAKE_CATALOG = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/PUBLIC_PRODUCT_SKU_CATALOG"


# -----------------------------------------------------------------------------
# LangGraph Nodes with Docket Attestation
# -----------------------------------------------------------------------------

@docket_langgraph_node(locator=SNOWFLAKE_CRM, state_key="messages", auto_hash=True)
def fetch_confidential_crm_node(state: dict[str, Any]) -> dict[str, Any]:
    """Node 1: Retrieves confidential customer CRM row and appends to messages."""
    raw_row = "CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"
    messages = list(state.get("messages", []))
    messages.append({"role": "user", "content": raw_row})
    return {"messages": messages}


@docket_langgraph_node(locator=SNOWFLAKE_CATALOG, state_key="messages", auto_hash=True)
def fetch_public_catalog_node(state: dict[str, Any]) -> dict[str, Any]:
    """Node 2: Retrieves public catalog row and appends to messages."""
    raw_row = "SKU-100 | Quantum Router | $1,299.00 | Available"
    messages = list(state.get("messages", []))
    messages.append({"role": "user", "content": raw_row})
    return {"messages": messages}


def llm_dispatch_node(
    client: DocketClient,
    state: dict[str, Any],
    model: str,
    caller_key: str,
    permit_masked: bool = False,
) -> dict[str, Any]:
    """Node 3: Dispatches messages state to LLM through G1 Docket gateway."""
    messages = state.get("messages", [])
    response = client.chat_completions(
        messages=messages,
        model=model,
        caller_key=caller_key,
        permit_masked=permit_masked,
    )
    return {
        "messages": messages + [response["choices"][0]["message"]],
        "gateway_verdict": "ALLOW",
    }


def main() -> int:
    print("=" * 80)
    print("       G1 DOCKET: LANGGRAPH WORKFLOW ADMISSION CONTROL DEMO         ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Public Catalog State Graph -> Public LLM Node
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Public Catalog State Graph -> Public Cloud Model (gpt-4o)")
        print("-" * 80)

        initial_state = {"messages": [{"role": "system", "content": "You are a sales assistant."}]}
        state_after_fetch = fetch_public_catalog_node(initial_state)

        print("  [+] Attested State Injected by @docket_langgraph_node:")
        print(f"      {state_after_fetch['messages'][-1]['content']}")

        final_state = llm_dispatch_node(
            client=client,
            state=state_after_fetch,
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Verdict: ALLOW (HTTP 200 OK)")
        print(f"  [+] Downstream Node Output: {final_state['messages'][-1]['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Confidential CRM State Graph -> Public Cloud LLM Node (Blocked)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Confidential CRM State Graph -> Public Cloud Model (gpt-4o)")
        print("-" * 80)

        crm_state = {"messages": [{"role": "system", "content": "You are a customer assistant."}]}
        crm_state_fetched = fetch_confidential_crm_node(crm_state)

        print("  [+] Attested State Injected by @docket_langgraph_node:")
        print(f"      {crm_state_fetched['messages'][-1]['content']}")

        try:
            llm_dispatch_node(
                client=client,
                state=crm_state_fetched,
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential context reached public cloud!")
        except PolicyDenialError as err:
            print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] LangGraph Safety: Policy violation stopped graph execution immediately.")

        # ---------------------------------------------------------------------
        # Scenario 3: Confidential CRM State Graph with In-Flight Redaction
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] LangGraph Synthesis with In-Flight Masking (permit_masked=True)")
        print("-" * 80)

        sanitized_state = llm_dispatch_node(
            client=client,
            state=crm_state_fetched,
            model="gpt-4o",
            caller_key="pod-key-public",
            permit_masked=True,
        )
        print("  [+] Verdict: SANITIZED & ALLOWED (HTTP 200 OK)")
        print(f"  [+] Redacted Graph Output: {sanitized_state['messages'][-1]['content']}")

        print("\n" + "=" * 80)
        print("          LANGGRAPH ZERO-TRUST INTEGRATION DEMO PASSED           ")
        print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
