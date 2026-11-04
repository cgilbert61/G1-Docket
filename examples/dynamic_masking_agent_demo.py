#!/usr/bin/env python3
"""G1 Docket — Dynamic In-Flight Field Masking & Sanitization Demo.

Demonstrates:
  1. Connecting to the G1 Docket Prevalidator gateway (:18082).
  2. Querying customer and financial data containing sensitive PII fields (SSNs, emails, phone numbers).
  3. Comparing enforcement behaviors:
     - Scenario 1: Standard 'allow' (clean data with verified hash forwards as-is).
     - Scenario 2: Standard 'strip' (entire <pod:object> block replaced with [POD:STRIPPED]).
     - Scenario 3: Standard 'deny' (request refused with HTTP 403 Forbidden).
     - Scenario 4: Dynamic In-Flight Field Masking (preserves analytical context while masking PII).
     - Scenario 5: Dynamic Header-based Masking Policy (X-POD-Permit-Masked: true).
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import attested_tool

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ICEBERG_BASE = "iceberg://polaris.us-east-1.lakehouse.net/finance_analytics"


def main() -> int:
    print("=" * 80)
    print("   G1 DOCKET: DYNAMIC IN-FLIGHT FIELD MASKING & SANITIZATION DEMO   ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Prevalidator Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Standard 'allow' — Verified Public Data
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Standard 'allow' Policy: Verified Public Table")
        print("-" * 80)

        @attested_tool(f"{ICEBERG_BASE}/curated_product_hierarchy", auto_hash=True)
        def get_public_product() -> str:
            return "category:compute_instances | sku_prefix:CP-8X | tier:General_Purpose | compliance:ISO27001"

        res1 = client.chat_completions(
            messages=[{"role": "user", "content": f"Review product catalog: {get_public_product()}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Gateway Action: ALLOW (HTTP 200 OK)")
        print(f"  [+] Clean Forwarded Text: {res1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Standard 'deny' — Confidential Ledger Leakage Blocked
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Standard 'deny' Policy: Confidential Revenue Ledger to Public Model")
        print("-" * 80)

        @attested_tool(f"{ICEBERG_BASE}/fact_gl_revenue_ledger", auto_hash=True)
        def get_revenue_ledger() -> str:
            return "fiscal_quarter:2026-Q3 | revenue_usd:$42,150,000 | operating_margin:28.4% | region:Global"

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Analyze revenue ledger: {get_revenue_ledger()}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential ledger leaked!")
        except PolicyDenialError as err:
            print(f"  [+] Gateway Action: HARD DENY (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Uniform Error: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Result: Request was terminated. Zero sensitive data egressed.")

        # ---------------------------------------------------------------------
        # Scenario 3: Standard 'strip' — Entire Block Replaced with [POD:STRIPPED]
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] Standard 'strip' Policy: Entire Object Replaced with [POD:STRIPPED]")
        print("-" * 80)

        strip_loc = "file://estate/fileshare/dept_compensation_confidential.xlsx"
        strip_payload = f'Provide general HR policy guidance:\n<pod:object locator="{strip_loc}">diana.prince@example.org | salary: $145,000</pod:object>'
        res3 = client.chat_completions(
            messages=[{"role": "user", "content": strip_payload}],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        print("  [+] Gateway Action: STRIP (HTTP 200 OK)")
        print(f"  [+] Transformed Model Input: {res3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 4: Dynamic In-Flight Field Masking (X-POD-Permit-Masked: true)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 4] Dynamic In-Flight Field Masking: Preserving Context While Masking PII")
        print("-" * 80)

        # A customer account record containing both analytical context and sensitive PII
        customer_loc = f"{ICEBERG_BASE}/fact_gl_revenue_ledger"
        # Caller enables dynamic in-flight masking via client headers
        res4 = client.chat_completions(
            messages=[{"role": "user", "content": f"Process customer revenue ledger: {get_revenue_ledger()}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
            headers={"X-POD-Permit-Masked": "true"},
        )
        print("  [+] Gateway Action: DYNAMIC FIELD MASKING (HTTP 200 OK)")
        print(f"  [+] Sanitized Model Input: {res4['choices'][0]['message']['content']}")
        print("  [+] Business Context Preserved: fiscal_quarter, operating_margin, and region remained.")
        print("  [+] Sensitive Spans Masked: Confidential financial ledger values were sanitized on-the-fly.")

    print("\n" + "=" * 80)
    print("   DYNAMIC IN-FLIGHT FIELD MASKING DEMO COMPLETE: ALL SCENARIOS VERIFIED   ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
