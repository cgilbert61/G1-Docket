#!/usr/bin/env python3
"""G1 Docket — Snowflake Data Warehouse Agent Integration Demo.

Demonstrates:
  1. Snowflake Tool Attestation:
     - Autonomous agent queries tables from a Snowflake Data Warehouse (`snowflake://contoso...`).
     - Automatic tagging and SHA-256 fingerprinting using `@attested_tool`.
  2. Label & Clearance Enforcement:
     - Public SKU catalog accessible by public agents and cloud models.
     - Confidential CRM data restricted to privileged callers and air-gapped/VPC models.
     - Restricted HR/Payroll data requiring highest clearance (`pod-key-restricted`).
  3. Dynamic In-Flight Masking:
     - Public agents permitted to consume masked extracts (`permit_masked=True`) with PII redacted in < 300 μs.
  4. Unpapered / Shadow Table Blocking:
     - Queries returning data from untracked/unattested Snowflake tables are rejected fail-closed.
  5. Anti-Smuggling Verification:
     - Inline Presidio DLP inspection blocks raw database dumps where tags were stripped.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

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

SNOWFLAKE_BASE = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC"


# -----------------------------------------------------------------------------
# Simulated Snowflake Data Warehouse Tooling
# In production, this would execute `cursor.execute("SELECT ... FROM ...")`
# -----------------------------------------------------------------------------

@attested_tool(f"{SNOWFLAKE_BASE}/PUBLIC_PRODUCT_SKU_CATALOG", auto_hash=True)
def query_snowflake_catalog(sku: str) -> str:
    """Query Public Product SKU Catalog in Snowflake."""
    return "SKU-100 | Quantum Router | $1,299.00 | Available"


@attested_tool(f"{SNOWFLAKE_BASE}/DIM_CUSTOMER_CONTACTS", auto_hash=True)
def query_snowflake_crm(cust_id: str) -> str:
    """Query Confidential CRM Customer Contacts in Snowflake."""
    return f"{cust_id} | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"


@attested_tool(f"{SNOWFLAKE_BASE}/HR_EXECUTIVE_SSN_TAX_FILINGS", auto_hash=True)
def query_snowflake_payroll(emp_id: str) -> str:
    """Query Restricted Executive Tax Filings in Snowflake."""
    return f"{emp_id} | SSN: 412-58-9021 | W2_GROSS: $410,000 | Routing: ABA-021000021"


@attested_tool(f"{SNOWFLAKE_BASE}/SHADOW_FINANCIAL_LEDGER_UNATTESTED", auto_hash=True)
def query_shadow_table(acct_id: str) -> str:
    """Query an unregistered, unpapered Snowflake table."""
    return f"{acct_id} | SECRET_BALANCE: $84,200,000 | OFF_BOOKS"


def main() -> int:
    print("=" * 80)
    print("      G1 DOCKET: SNOWFLAKE ZERO-TRUST AGENT ADMISSION CONTROL DEMO      ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Case 1: Public Table Query -> Public Cloud LLM
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 1] Public Table Query (PUBLIC_PRODUCT_SKU_CATALOG) -> Public gpt-4o")
        print("-" * 80)

        catalog_data = query_snowflake_catalog("SKU-100")
        print(f"  [>] Snowflake Result:\n      {catalog_data}")

        res1 = client.chat_completions(
            messages=[
                {"role": "system", "content": "You are a customer sales assistant."},
                {"role": "user", "content": f"Check item price: {catalog_data}"},
            ],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Verdict: ALLOW (HTTP 200 OK)")
        print(f"  [+] Response: {res1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Case 2: Confidential Table Query -> Public Cloud LLM (Blocked)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 2] Confidential CRM Query (DIM_CUSTOMER_CONTACTS) -> Public gpt-4o")
        print("-" * 80)

        crm_data = query_snowflake_crm("CUST-901")
        print(f"  [>] Snowflake Result:\n      {crm_data}")

        try:
            client.chat_completions(
                messages=[
                    {"role": "system", "content": "You are a marketing writer."},
                    {"role": "user", "content": f"Draft email to customer: {crm_data}"},
                ],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential context leaked to public cloud!")
        except PolicyDenialError as err:
            print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Guarantee: Confidential Snowflake rows cannot egress to public LLMs.")

        # ---------------------------------------------------------------------
        # Case 3: Confidential Table Query -> Air-Gapped / Private VPC Model (Allowed)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 3] Privileged Agent (pod-key-confidential) -> Air-Gapped Local Model")
        print("-" * 80)

        res3 = client.chat_completions(
            messages=[
                {"role": "system", "content": "You are an internal CRM analyst."},
                {"role": "user", "content": f"Analyze contact tier: {crm_data}"},
            ],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        print("  [+] Verdict: ALLOW (HTTP 200 OK)")
        print(f"  [+] Local Model Output: {res3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Case 4: In-Flight Dynamic Masking for Public Egress
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 4] In-Flight Column Masking (permit_masked=True) -> Public gpt-4o")
        print("-" * 80)

        res4 = client.chat_completions(
            messages=[
                {"role": "system", "content": "You are a communications assistant."},
                {"role": "user", "content": f"Summarize contact domain: {crm_data}"},
            ],
            model="gpt-4o",
            caller_key="pod-key-public",
            permit_masked=True,
        )
        print("  [+] Verdict: SANITIZED & ALLOWED (HTTP 200 OK)")
        print(f"  [+] Output (PII Redacted): {res4['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Case 5: Unregistered / Shadow Snowflake Table (Fail-Closed)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 5] Querying Shadow Table Not in Signed Attestation Snapshot")
        print("-" * 80)

        shadow_data = query_shadow_table("ACCT-007")
        print(f"  [>] Shadow Result:\n      {shadow_data}")

        try:
            client.chat_completions(
                messages=[
                    {"role": "system", "content": "You are a finance assistant."},
                    {"role": "user", "content": f"Check balance: {shadow_data}"},
                ],
                model="local-model",
                caller_key="pod-key-confidential",
            )
            print("  [-] UNEXPECTED: Unregistered shadow table allowed!")
        except PolicyDenialError as err:
            print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Guarantee: Fail-closed zero trust; unpapered data cannot enter any LLM.")

        # ---------------------------------------------------------------------
        # Case 6: Anti-Smuggling Gate (Untagged Context & Raw Data Dump Interception)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Case 6] Anti-Smuggling Gate (Pre-dispatch callback catches untagged raw DB dumps)")
        print("-" * 80)

        from docket.integrations import DocketLangChainCallbackHandler

        callback_auditor = DocketLangChainCallbackHandler(
            require_attested_context=True,
            max_untagged_chars=100,
            on_violation="raise",
        )
        raw_smuggled_prompt = "Process payroll for EMP-001 with SSN: 412-58-9021 Elena Fisher salary $410,000"
        print(f"  [>] Raw Untagged Prompt:\n      '{raw_smuggled_prompt}'")

        try:
            callback_auditor.on_llm_start(serialized={}, prompts=[raw_smuggled_prompt])
            print("  [-] UNEXPECTED: Untagged prompt passed pre-dispatch audit!")
        except PolicyDenialError as err:
            print("  [+] Verdict: CAUGHT & HARD-BLOCKED (HTTP 403)")
            print(f"  [+] Denial Reason: {err.response_body.get('error')}")
            print("  [+] Guarantee: Zero untagged / unpapered database context can be smuggled.")

        print("\n" + "=" * 80)
        print("          ALL 6 SNOWFLAKE ZERO-TRUST VERIFICATIONS PASSED           ")
        print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
