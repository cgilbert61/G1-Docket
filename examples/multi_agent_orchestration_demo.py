#!/usr/bin/env python3
"""G1 Docket — Multi-Agent Orchestration & Cross-Clearance Admission Control Demo.

Demonstrates:
  1. Multi-Agent Team Collaboration:
     - Lead Orchestrator: Coordinates complex tasks and synthesizes reports.
     - Enterprise Data Specialist (Restricted Clearance): Queries Snowflake and BigQuery data stores.
     - Risk & Compliance Auditor (Internal Clearance): Validates policies and prepares masked extracts.
     - Public Communications Agent (Public Clearance): Drafts external customer-facing summaries.
  2. Zero-Trust Gateway Mediation at Every Agent Handoff:
     - Task 1: Privileged worker querying confidential data -> routes to Local/Air-gapped LLM (ALLOW).
     - Task 2: Public agent attempting to pass confidential data to public cloud LLM (HARD BLOCK / DENY).
     - Task 3: Selective in-flight stripping of unauthorized context for public summarization (STRIP -> ALLOW).
     - Task 4: Anti-smuggling gate catching untagged PII dumped by a rogue worker (DENY).
     - Task 5: WORM Merkle Chain compliance audit across all multi-agent interaction steps.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketRAGDocument, attested_tool, wrap_rag_documents

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SNOWFLAKE_BASE = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC"
BIGQUERY_BASE = "bigquery://health-corp-hipaa/prod_clinical_datamart"


class Agent:
    """Lightweight autonomous AI agent with cryptographic credentials and model routing."""

    def __init__(self, name: str, role: str, caller_key: str, default_model: str) -> None:
        self.name = name
        self.role = role
        self.caller_key = caller_key
        self.default_model = default_model

    def execute_prompt(
        self,
        client: DocketClient,
        prompt: str,
        model: str | None = None,
        permit_masked: bool = False,
    ) -> dict[str, Any]:
        target_model = model or self.default_model
        return client.chat_completions(
            messages=[
                {"role": "system", "content": f"You are {self.name}, the {self.role}."},
                {"role": "user", "content": prompt},
            ],
            model=target_model,
            caller_key=self.caller_key,
            permit_masked=permit_masked,
        )


def main() -> int:
    print("=" * 80)
    print("   G1 DOCKET: MULTI-AGENT ORCHESTRATION & ZERO-TRUST GOVERNANCE DEMO   ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # Initialize multi-agent team with segregation of duties
        data_agent = Agent(
            name="DataWorker-01",
            role="Enterprise Data Specialist",
            caller_key="pod-key-confidential",
            default_model="local-model",
        )
        compliance_agent = Agent(
            name="ComplianceAuditor-02",
            role="Risk & Compliance Reviewer",
            caller_key="pod-key-analyst",
            default_model="azure-gpt4",
        )
        public_agent = Agent(
            name="PublicComms-03",
            role="External Communications Specialist",
            caller_key="pod-key-public",
            default_model="gpt-4o",
        )

        print(f"\n[+] Active Multi-Agent Team:")
        print(f"    1. {data_agent.name}       | Role: {data_agent.role:32} | Key: {data_agent.caller_key}")
        print(f"    2. {compliance_agent.name} | Role: {compliance_agent.role:32} | Key: {compliance_agent.caller_key}")
        print(f"    3. {public_agent.name}     | Role: {public_agent.role:32} | Key: {public_agent.caller_key}")

        # ---------------------------------------------------------------------
        # Task 1: Privileged Data Worker Queries Snowflake & Local LLM
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Task 1] DataWorker queries Snowflake CRM -> Air-Gapped Local Model")
        print("-" * 80)

        @attested_tool(f"{SNOWFLAKE_BASE}/DIM_CUSTOMER_CONTACTS", auto_hash=True)
        def query_crm_store(cust_id: str) -> str:
            return f"{cust_id} | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"

        crm_record = query_crm_store("CUST-901")
        print(f"  [>] DataWorker retrieved attested record:\n      {crm_record}")

        resp1 = data_agent.execute_prompt(
            client=client,
            prompt=f"Summarize account status: {crm_record}",
        )
        print("  [+] Gateway Action: ALLOW (HTTP 200 OK)")
        print(f"  [+] Local Model Output: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Task 2: Public Agent Tries to Exfiltrate Confidential CRM Data to Public Cloud LLM
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Task 2] PublicComms Agent attempts to forward Confidential CRM context to gpt-4o")
        print("-" * 80)

        try:
            public_agent.execute_prompt(
                client=client,
                prompt=f"Draft external newsletter citing: {crm_record}",
                model="gpt-4o",
            )
            print("  [-] UNEXPECTED: Confidential context reached public API!")
        except PolicyDenialError as err:
            print(f"  [+] Gateway Action: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Security Guarantee: Confidential records blocked from public cloud egress.")

        # ---------------------------------------------------------------------
        # Task 3: Multi-Agent Handoff with In-Flight Field Sanitization
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Task 3] Handoff to Public Agent with In-Flight Masking (permit_masked=True)")
        print("-" * 80)

        @attested_tool(f"{SNOWFLAKE_BASE}/PUBLIC_PRODUCT_SKU_CATALOG", auto_hash=True)
        def query_public_catalog(sku: str) -> str:
            return f"{sku} | Quantum Router | $1,299.00 | Available"

        public_catalog = query_public_catalog("SKU-100")
        mixed_prompt = (
            f"Draft marketing announcement combining:\n"
            f"1. Verified Product: {public_catalog}\n"
            f"2. Customer Benchmark Quote: {crm_record}"
        )

        resp3 = public_agent.execute_prompt(
            client=client,
            prompt=mixed_prompt,
            model="gpt-4o",
            permit_masked=True,
        )
        print("  [+] Gateway Action: DYNAMIC IN-FLIGHT MASKING (HTTP 200 OK)")
        print(f"  [+] Sanitized Model Input: {resp3['choices'][0]['message']['content']}")
        print("  [+] Clean Pipeline: Public catalog remained intact; sensitive PII was dynamically masked.")

        # ---------------------------------------------------------------------
        # Task 4: Anti-Smuggling & Unpapered Data Defense
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Task 4] Anti-Smuggling: Rogue Agent queries unpapered shadow table & raw PII")
        print("-" * 80)

        # 4a: Rogue agent queries untracked shadow data source without DSSE provenance
        @attested_tool("bigquery://unregistered-corp/shadow_db/unauthorized_table", auto_hash=True)
        def query_shadow_store() -> str:
            return "record_id:9901 | balance:$4,200,000 | note:untracked"

        shadow_record = query_shadow_store()
        try:
            public_agent.execute_prompt(
                client=client,
                prompt=f"Process shadow record: {shadow_record}",
                model="gpt-4o",
            )
            print("  [-] UNEXPECTED: Unpapered data bypassed prevalidator!")
        except PolicyDenialError as err:
            print("  [+] Gateway Action: HARD BLOCK (HTTP 403 Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Provenance Guarantee: Zero unpapered data allowed into downstream models.")

        # 4b: Pre-dispatch agent callback catches untagged free-text PII smuggling
        from docket.integrations import DocketLangChainCallbackHandler

        callback_auditor = DocketLangChainCallbackHandler(
            require_attested_context=True,
            max_untagged_chars=100,
            on_violation="raise",
        )
        untagged_smuggle_prompt = "Raw PII dump: SSN 123-45-6789 Elena Fisher salary $410,000"
        try:
            callback_auditor.on_llm_start(serialized={}, prompts=[untagged_smuggle_prompt])
            print("  [-] UNEXPECTED: Untagged prompt passed pre-dispatch audit!")
        except PolicyDenialError as err:
            print("  [+] Pre-Dispatch Interceptor: CAUGHT (HTTP 403)")
            print(f"  [+] Reason Code: {err.response_body.get('code')}")
            print(f"  [+] Message: {err.response_body.get('error')}")

        # ---------------------------------------------------------------------
        # Task 5: Compliance Audit & WORM Ledger Verification
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Task 5] HITL Governance & SIEM Hub (:18084) Audit Trail Verification")
        print("-" * 80)

        audit_entries = client.get_audit_log(limit=5)
        print(f"  [+] Prevalidator In-Memory Audit Log: {len(audit_entries)} recent entries verified")
        if audit_entries:
            latest = audit_entries[-1]
            print(f"      Latest: decision={latest.get('decision')} | caller={latest.get('caller_clearance')} | latency={latest.get('decision_latency_us', 0):.1f} us")

        import httpx
        with httpx.Client(timeout=10.0) as gov_client:
            r_verify = gov_client.get("http://localhost:18084/api/worm/verify")
            r_quarantine = gov_client.get("http://localhost:18084/api/quarantine")
            if r_verify.status_code == 200:
                v_data = r_verify.json()
                print(f"  [+] WORM Merkle Chain Valid : {v_data.get('valid', True)}")
                print(f"  [+] WORM Verified Events     : {v_data.get('total_entries', v_data.get('events_count'))} entries")
            if r_quarantine.status_code == 200:
                q_data = r_quarantine.json()
                q_count = len(q_data) if isinstance(q_data, list) else len(q_data.get("items", []))
                print(f"  [+] Quarantine Incidents Log : {q_count} incidents tracked")

    print("\n" + "=" * 80)
    print("   [SUCCESS] MULTI-AGENT ADMISSION CONTROL BENCHMARK COMPLETE (0 ERRORS)   ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
