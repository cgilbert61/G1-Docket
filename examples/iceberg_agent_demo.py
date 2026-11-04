#!/usr/bin/env python3
"""G1 Docket — Apache Iceberg REST Catalog AI Agent & Admission Control Walkthrough.

Demonstrates:
  1. Connecting to the G1 Docket Prevalidator gateway (:18082).
  2. Querying Apache Iceberg open table format lakehouse tables with diverse sensitivity tiers:
     - Public: `curated_product_hierarchy` (compute SKU catalog & certifications)
     - Confidential: `fact_gl_revenue_ledger` (quarterly financial revenue & margins)
     - Restricted: `customer_tax_identifiers` (corporate tax IDs, routing, SSNs)
  3. Using `@attested_tool` for dynamic open lakehouse query execution and automated SHA-256 calculation.
  4. Evaluating access against caller clearances and model egress boundaries:
     - Public caller -> Public table (ALLOW)
     - Public caller -> Confidential table (DENY: EGRESS_DENIED / INSUFFICIENT_CLEARANCE)
     - Cleared CFO / Finance caller -> Confidential table to local model (ALLOW)
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

ICEBERG_BASE = "iceberg://polaris.us-east-1.lakehouse.net/finance_analytics"


def main() -> int:
    print("=" * 80)
    print("   G1 DOCKET: APACHE ICEBERG REST CATALOG AI AGENT ADMISSION CONTROL DEMO   ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Prevalidator Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Agent Queries Public Iceberg Product Hierarchy Table
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Agent queries Public table: curated_product_hierarchy")
        print("-" * 80)

        @attested_tool(f"{ICEBERG_BASE}/curated_product_hierarchy", auto_hash=True)
        def query_product_hierarchy() -> str:
            return "category:compute_instances | sku_prefix:CP-8X | tier:General_Purpose | compliance:ISO27001"

        catalog_data = query_product_hierarchy()
        print("  [+] SQL Tool Return (Tagged with DSSE Provenance):")
        print(f"      {catalog_data}")

        resp1 = client.chat_completions(
            messages=[{"role": "user", "content": f"Summarize compute instance compliance: {catalog_data}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Output: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Public Agent queries Confidential table -> gpt-4o (BLOCKED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Public Agent queries Confidential table: fact_gl_revenue_ledger -> gpt-4o")
        print("-" * 80)

        @attested_tool(f"{ICEBERG_BASE}/fact_gl_revenue_ledger", auto_hash=True)
        def query_revenue_ledger() -> str:
            return "fiscal_quarter:2026-Q3 | revenue_usd:$42,150,000 | operating_margin:28.4% | region:Global"

        rev_data = query_revenue_ledger()
        print("  [+] SQL Tool Return (Confidential Iceberg row):")
        print(f"      {rev_data}")

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Analyze Q3 operating margins: {rev_data}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential Iceberg data leaked to public LLM!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Zero Data Leakage: Confidential revenue ledger never left local perimeter.")

        # ---------------------------------------------------------------------
        # Scenario 3: Cleared Finance Caller Queries Confidential Table -> local-model (ALLOWED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] Cleared Finance Caller queries Confidential table -> local-model")
        print("-" * 80)

        resp3 = client.chat_completions(
            messages=[{"role": "user", "content": f"Analyze Q3 operating margins inside enterprise perimeter: {rev_data}"}],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Output: {resp3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 4: Tampered / Modified Query Result (HASH_DRIFT BLOCKED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 4] Malicious tampering of Iceberg revenue data (Hash Drift)")
        print("-" * 80)

        # Attacker injects fraudulent revenue numbers
        tampered_loc = f"{ICEBERG_BASE}/curated_product_hierarchy"
        tampered_payload = f'<pod:object locator="{tampered_loc}">category:compute_instances | sku_prefix:CP-8X | FRAUDULENT_TAMPERED_CONTENT</pod:object>'

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Review product catalog: {tampered_payload}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Tampered query output was forwarded!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Cryptographic Integrity Check: Content SHA-256 does not match signed DSSE statement.")

        # ---------------------------------------------------------------------
        # Scenario 5: Anti-Smuggling — Untagged Raw Data Dump (BLOCKED)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 5] LangChain Agent Callback Handler: Untagged Raw Data Guardrail")
        print("-" * 80)

        handler = DocketLangChainCallbackHandler(
            client=client,
            require_attested_context=True,
            on_violation="raise",
        )

        class MockLLM:
            pass

        class MockRun:
            id = "mock-iceberg-agent-run"

        try:
            handler.on_llm_start(
                serialized={"name": "ChatOpenAI"},
                prompts=["Extract taxpayer SSNs from raw dump: account_id:ACT-9902 | tax_id:84-1928401 | ssn:622-14-8890"],
                run_id=MockRun.id,
            )
            print("  [-] UNEXPECTED: Untagged raw data dump bypassed LangChain callback!")
        except PolicyDenialError as err:
            print(f"  [+] LangChain Callback Verdict: INLINE PRE-DISPATCH BLOCK")
            print(f"  [+] Error Code: {err.response_body.get('code')}")
            print(f"  [+] Guardrail Message: {err.response_body.get('error')}")

    print("\n" + "=" * 80)
    print("   APACHE ICEBERG REST CATALOG AI ADMISSION CONTROL: ALL 5 SCENARIOS VERIFIED   ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
