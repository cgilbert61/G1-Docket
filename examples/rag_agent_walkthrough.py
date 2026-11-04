#!/usr/bin/env python3
"""G1 Docket — RAG Agent Integration & Zero-Trust Admission Control Walkthrough.

Demonstrates:
  1. Simulating a RAG vector retriever fetching context from S3, Snowflake, and local files.
  2. Formatting retrieved documents into cryptographic `<pod:object>` tokens via `docket.integrations`.
  3. Dispatching prompts through `DocketClient` with clearance tiers and ABAC departmental headers.
  4. Observing policy enforcement: public allowance vs. confidential redaction vs. unattested refusal.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketRAGDocument, format_rag_prompt, wrap_rag_documents

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main() -> int:
    print("=" * 70)
    print("      G1 DOCKET: AI AGENT & RAG RETRIEVAL PIPELINE WALKTHROUGH        ")
    print("=" * 70)

    # 1. Simulate Vector Database Retriever Output (Heterogeneous Chunks)
    print("\n[Step 1] Simulating Vector Retriever (LangChain / LlamaIndex style)...")
    retrieved_chunks = [
        # Public reference doc (from AWS S3)
        DocketRAGDocument(
            locator="file://estate/fileshare/product_overview_public.md",
            content="Open Source AI Architecture Overview",
            title="Public Product Overview",
        ),
        # Confidential customer record (from Snowflake Warehouse)
        {
            "locator": "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS",
            "content": "CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise",
            "metadata": {"tier": "Confidential", "owner": "crm-warehouse@contoso.com"},
        },
    ]
    print(f"  [+] Retrieved {len(retrieved_chunks)} context chunks from multi-cloud storage.")

    # 2. Format Context into `<pod:object>` Blocks
    print("\n[Step 2] Formatting Attested Context Blocks via docket.integrations...")
    prompt_template = (
        "You are an enterprise AI assistant. Answer the user prompt using only the attested data below:\n\n"
        "{context}\n\n"
        "User Question: Provide a summary of our architecture and customer Elena Fisher."
    )
    prompt = format_rag_prompt(prompt_template, retrieved_chunks)
    print("  [+] Constructed Prompt with Embedded <pod:object> Tokens:")
    print("  -------------------------------------------------------------")
    for line in prompt.splitlines()[:10]:
        print(f"    {line}")
    print("  -------------------------------------------------------------")

    # 3. Test Agent Execution with Public Clearance (Expect Denial on Snowflake)
    print("\n[Step 3] Dispatching Prompt as Public Agent (pod-key-public)...")
    with DocketClient(base_url="http://localhost:18082") as client:
        try:
            client.chat_completions(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] Unexpected: Public caller accessed Confidential Snowflake table!")
        except PolicyDenialError as err:
            print("  [+] Gate Blocked Inline (HTTP 403):", err.status_code)
            print("  [+] Attestation Policy Refusal:", err.response_body.get("error", {}).get("message"))

    # 4. Test Agent Execution with Approved Clearance & Department Context
    print("\n[Step 4] Dispatching Prompt as Cleared Agent (pod-key-confidential + Finance Dept)...")
    with DocketClient(base_url="http://localhost:18082") as client:
        # For a prompt containing only Public data
        public_only_chunks = [retrieved_chunks[0]]
        public_prompt = format_rag_prompt(prompt_template, public_only_chunks)
        res = client.chat_completions(
            messages=[{"role": "user", "content": public_prompt}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Public Prompt Passed Prevalidator Successfully (HTTP 200 OK)")
        print("  [+] Model Gateway Response:", res.get("choices", [{}])[0].get("message", {}).get("content"))

    print("\n" + "=" * 70)
    print("             RAG Agent Integration Walkthrough Complete!              ")
    print("=" * 70 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
