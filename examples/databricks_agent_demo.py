#!/usr/bin/env python3
"""G1 Docket — Databricks Unity Catalog AI Agent & Admission Control Walkthrough.

Demonstrates:
  1. Connecting to the G1 Docket Prevalidator gateway (:18082).
  2. Querying Databricks Unity Catalog tables with diverse sensitivity tiers:
     - Public: `public_feature_store_registry`
     - Confidential: `gold_arr_executive_summary`
     - Restricted: `gold_customer_identity_registry`
  3. Using `@attested_tool` for dynamic SQL tool execution and automated SHA-256 calculation.
  4. Evaluating access against caller clearances and model egress boundaries:
     - Public caller -> Public table (ALLOW)
     - Public caller -> Confidential table (DENY: EGRESS_DENIED / INSUFFICIENT_CLEARANCE)
     - Cleared caller -> Confidential table to local model (ALLOW)
     - Tampered / Drifted query output (DENY: HASH_DRIFT)
     - Anti-smuggling: Plain untagged PII dump (DENY: missing_attested_context)
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketLangChainCallbackHandler, attested_tool

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DBX_BASE = "databricks://adb-41920194.azuredatabricks.net/main/sales_analytics"


def main() -> int:
    print("=" * 80)
    print("   G1 DOCKET: DATABRICKS UNITY CATALOG AI AGENT ADMISSION CONTROL DEMO   ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Prevalidator Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Agent Queries Public Databricks Feature Store Table
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Agent queries Public table: public_feature_store_registry")
        print("-" * 80)

        @attested_tool(f"{DBX_BASE}/public_feature_store_registry", auto_hash=True)
        def query_feature_store() -> str:
            return "feature_id:churn_prediction_v4 | freshness_hours:6 | team:mlops-platform | status:available"

        feature_data = query_feature_store()
        print("  [+] SQL Tool Return (Tagged with DSSE Provenance):")
        print(f"      {feature_data}")

        resp1 = client.chat_completions(
            messages=[{"role": "user", "content": f"Summarize feature store availability: {feature_data}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Output: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Public Agent queries Confidential table -> gpt-4o (BLOCKED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Public Agent queries Confidential table: gold_arr_executive_summary -> gpt-4o")
        print("-" * 80)

        @attested_tool(f"{DBX_BASE}/gold_arr_executive_summary", auto_hash=True)
        def query_executive_summary() -> str:
            return "region:EMEA | q4_arr_usd:$18,400,000 | churn_rate:2.1% | acv_growth:34%"

        arr_data = query_executive_summary()
        print("  [+] SQL Tool Return (Confidential Unity Catalog row):")
        print(f"      {arr_data}")

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Analyze regional ARR growth: {arr_data}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential Databricks data leaked to public LLM!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Zero Data Leakage: Confidential ARR summary never left local perimeter.")

        # ---------------------------------------------------------------------
        # Scenario 3: Cleared Agent queries gold_arr_executive_summary -> local-model (ALLOWED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] Cleared Agent queries gold_arr_executive_summary -> local-model")
        print("-" * 80)

        resp3 = client.chat_completions(
            messages=[{"role": "user", "content": f"Analyze ARR trajectory: {arr_data}"}],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print("  [+] Clearance Validated: Caller has 'Confidential' clearance and target model is 'local_only'.")
        print(f"  [+] Model Gateway Output: {resp3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 4: Rogue Actor alters query rows (Cryptographic Hash Mismatch)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 4] Rogue Actor alters query rows (Cryptographic Hash Mismatch)")
        print("-" * 80)

        tampered_payload = (
            f'<pod:object locator="{DBX_BASE}/public_feature_store_registry" '
            f'sha256="c3179b2b1f2ccc55b7ea9e545b28e7e83cb6b23e101b4917d417a1787f3d3cd9">'
            f'feature_id:churn_prediction_v4 | freshness_hours:999 | INJECTED_MALICIOUS_WEIGHTS'
            f'</pod:object>'
        )

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Process features: {tampered_payload}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Tampered query output reached the model!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Cryptographic Integrity Enforced: Live hash differs from signed DSSE record.")

        # ---------------------------------------------------------------------
        # Scenario 5: Anti-Smuggling: Agent attempts to dump unpapered Unity Catalog data
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 5] Anti-Smuggling: Agent attempts to dump unpapered Databricks data")
        print("-" * 80)

        handler = DocketLangChainCallbackHandler(
            client=client,
            require_attested_context=True,
            on_violation="raise",
        )

        try:
            handler.on_llm_start(
                serialized={"name": "ChatOpenAI"},
                prompts=["SELECT * FROM main.sales_analytics.gold_customer_identity_registry WHERE ssn IS NOT NULL;"],
            )
            print("  [-] UNEXPECTED: Plain untagged prompt dispatched without attestation wrapper!")
        except PolicyDenialError as err:
            print(f"  [+] Pre-Dispatch Callback Decision: INTERCEPTED (HTTP {err.status_code})")
            print(f"  [+] Reason Code: {err.response_body.get('code')}")
            print(f"  [+] Message: {err.response_body.get('error')}")

    print("\n" + "=" * 80)
    print("    Databricks Unity Catalog AI Agent Admission Control Demo Complete!   ")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
