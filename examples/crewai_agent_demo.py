#!/usr/bin/env python3
"""G1 Docket — CrewAI Multi-Agent Team Zero-Trust Integration Demo.

Demonstrates:
  1. DocketCrewAITool Wrapper:
     - Equipping CrewAI agents with data extraction tools that automatically wrap
       database records, RAG snippets, and API responses in `<pod:object>` tokens.
  2. Cross-Agent Data Handoffs:
     - Privileged Researcher agent queries internal financial ledgers.
     - Communications Writer agent synthesizes customer-facing updates.
  3. Zero-Trust Gateway Enforcement:
     - Blocks unauthorized egress of confidential records to public cloud models.
     - Enables dynamic in-flight masking when public clearance is needed.
     - Automatically embeds forensic cryptographic watermarks into generated artifacts.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketCrewAITool

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SNOWFLAKE_LEDGER = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS"


class MockCrewAIAgent:
    """Mock CrewAI Agent illustrating agent execution with caller keys."""

    def __init__(self, role: str, goal: str, caller_key: str, default_model: str) -> None:
        self.role = role
        self.goal = goal
        self.caller_key = caller_key
        self.default_model = default_model

    def execute_task(
        self,
        client: DocketClient,
        task_prompt: str,
        model: str | None = None,
        permit_masked: bool = False,
    ) -> dict[str, Any]:
        target_model = model or self.default_model
        return client.chat_completions(
            messages=[
                {"role": "system", "content": f"Role: {self.role}. Goal: {self.goal}."},
                {"role": "user", "content": task_prompt},
            ],
            model=target_model,
            caller_key=self.caller_key,
            permit_masked=permit_masked,
        )


def main() -> int:
    print("=" * 80)
    print("        G1 DOCKET: CREWAI MULTI-AGENT ADMISSION CONTROL DEMO         ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Step 1: Define CrewAI Tool with Docket Data Attestation Wrapper
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 1] Wrap Database Tool with DocketCrewAITool")
        print("-" * 80)

        def raw_crm_tool(cust_id: str) -> str:
            """Raw tool logic returning CRM record from Snowflake."""
            return f"{cust_id} | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"

        attested_crm_tool = DocketCrewAITool(
            raw_crm_tool,
            locator=SNOWFLAKE_LEDGER,
            auto_hash=True,
        )

        tool_output = attested_crm_tool("CUST-901")
        print(f"  [+] Attested Tool Output:\n      {tool_output}")

        # ---------------------------------------------------------------------
        # Step 2: Privileged Senior Financial Researcher (Local / VPC Model)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 2] Privileged Researcher Agent (pod-key-confidential -> local-model)")
        print("-" * 80)

        researcher = MockCrewAIAgent(
            role="Senior Financial Researcher",
            goal="Analyze enterprise customer portfolios",
            caller_key="pod-key-confidential",
            default_model="local-model",
        )

        resp1 = researcher.execute_task(
            client=client,
            task_prompt=f"Analyze credit profile for account: {tool_output}",
        )
        print("  [+] Gateway Action: ALLOW (HTTP 200 OK)")
        print(f"  [+] Output: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Step 3: Public Comms Agent Tries to Egress Unmasked CRM Data (Blocked)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 3] Public Writer Agent Tries to Forward Confidential Data to gpt-4o")
        print("-" * 80)

        writer = MockCrewAIAgent(
            role="Public Content Writer",
            goal="Draft quarterly newsletter updates",
            caller_key="pod-key-public",
            default_model="gpt-4o",
        )

        try:
            writer.execute_task(
                client=client,
                task_prompt=f"Draft public announcement using: {tool_output}",
                model="gpt-4o",
            )
            print("  [-] UNEXPECTED: Confidential context leaked to public cloud!")
        except PolicyDenialError as err:
            print(f"  [+] Gateway Action: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] CrewAI Guardrail: Public agents cannot leak confidential data across crews.")

        # ---------------------------------------------------------------------
        # Step 4: Multi-Agent Handoff with In-Flight Dynamic Masking
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 4] Handoff with In-Flight Masking (permit_masked=True)")
        print("-" * 80)

        resp4 = writer.execute_task(
            client=client,
            task_prompt=f"Draft public announcement using: {tool_output}",
            model="gpt-4o",
            permit_masked=True,
        )
        print("  [+] Gateway Action: SANITIZED & ALLOWED (HTTP 200 OK)")
        masked_content = resp4["choices"][0]["message"]["content"]
        print(f"  [+] Sanitized Output: {masked_content}")

        # ---------------------------------------------------------------------
        # Step 5: Embed Cryptographic Provenance Watermark
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 5] Cryptographic Forensic Watermarking on CrewAI Artifact")
        print("-" * 80)

        watermarked_text = client.embed_watermark(
            text=masked_content,
            snapshot_sequence=health.get("snapshot_sequence", 1),
            caller_key=writer.caller_key,
        )
        print(f"  [+] Watermarked Text (Length: {len(watermarked_text)} chars with zero visual drift)")

        inspection = client.extract_watermark(watermarked_text)
        print(f"  [+] Forensic Verification: valid={inspection.get('signature_valid')}")
        print(f"      Snapshot Seq: {inspection.get('snapshot_sequence')} | Caller: {inspection.get('caller_key')}")

        print("\n" + "=" * 80)
        print("          CREWAI ZERO-TRUST INTEGRATION DEMO PASSED           ")
        print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
