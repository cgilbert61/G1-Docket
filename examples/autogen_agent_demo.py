#!/usr/bin/env python3
"""G1 Docket — Microsoft AutoGen Multi-Agent Zero-Trust Integration Demo.

Demonstrates:
  1. DocketAutoGenHook Message Processing:
     - Automatically intercepts and envelops sensitive database lookups
       passed between ConversableAgents in canonical `<pod:object>` tokens.
  2. AutoGen Conversational Workflow:
     - UserProxy / Orchestrator assigns tasks.
     - Database Specialist Agent retrieves customer CRM records from Snowflake.
     - Public Communications Agent drafts external executive summaries.
  3. Prevalidator Gateway Defense:
     - Allows privileged analysis on air-gapped local / VPC models.
     - Hard-blocks unauthorized egress of confidential context to public cloud LLMs.
     - Performs dynamic in-flight masking when public clearance is permitted.
     - Embeds invisible forensic provenance watermarks into final deliverables.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketAutoGenHook

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SNOWFLAKE_CRM = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS"


class MockAutoGenAgent:
    """Mock AutoGen ConversableAgent demonstrating message hooks and model dispatch."""

    def __init__(self, name: str, system_message: str, caller_key: str, default_model: str) -> None:
        self.name = name
        self.system_message = system_message
        self.caller_key = caller_key
        self.default_model = default_model
        self.hook: DocketAutoGenHook | None = None

    def register_hook(self, hook: DocketAutoGenHook) -> None:
        self.hook = hook

    def send(self, message: str | dict[str, Any], recipient: MockAutoGenAgent) -> str | dict[str, Any]:
        """Send a message to another agent, processing through registered Docket hook."""
        if self.hook:
            message = self.hook.process_message(self, message, recipient)
        return recipient.receive(message, self)

    def receive(self, message: str | dict[str, Any], sender: MockAutoGenAgent) -> str | dict[str, Any]:
        return message

    def generate_reply(
        self,
        client: DocketClient,
        prompt: str,
        model: str | None = None,
        permit_masked: bool = False,
    ) -> dict[str, Any]:
        """Dispatch prompt through G1 Docket Prevalidator gateway."""
        target_model = model or self.default_model
        return client.chat_completions(
            messages=[
                {"role": "system", "content": self.system_message},
                {"role": "user", "content": prompt},
            ],
            model=target_model,
            caller_key=self.caller_key,
            permit_masked=permit_masked,
        )


def main() -> int:
    print("=" * 80)
    print("       G1 DOCKET: AUTOGEN MULTI-AGENT ADMISSION CONTROL DEMO        ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Gateway Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Step 1: Initialize AutoGen Agents & Hook
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 1] Register DocketAutoGenHook with Pattern-to-Locator Mappings")
        print("-" * 80)

        data_agent = MockAutoGenAgent(
            name="DataSpecialist",
            system_message="You are an enterprise data specialist querying internal data warehouses.",
            caller_key="pod-key-confidential",
            default_model="local-model",
        )

        public_writer = MockAutoGenAgent(
            name="PublicWriter",
            system_message="You are a public communications copywriter drafting customer updates.",
            caller_key="pod-key-public",
            default_model="gpt-4o",
        )

        # Register hook mapping raw CRM tokens to canonical Snowflake locator
        hook = DocketAutoGenHook(
            locator_map={"CUST-901": SNOWFLAKE_CRM},
            auto_hash=True,
        )
        data_agent.register_hook(hook)
        print("  [+] Registered AutoGen hook for pattern 'CUST-901' ->", SNOWFLAKE_CRM)

        # ---------------------------------------------------------------------
        # Step 2: Agent-to-Agent Message Handoff with Automatic Token Wrapping
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 2] AutoGen Agent Message Handoff")
        print("-" * 80)

        raw_query_result = "CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"
        handoff_message = data_agent.send(raw_query_result, public_writer)

        print(f"  [+] Message Received by {public_writer.name}:")
        print(f"      {handoff_message}")

        # ---------------------------------------------------------------------
        # Step 3: Privileged Analysis on Air-Gapped Local Model
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 3] Privileged Execution on Local Model (pod-key-confidential -> local-model)")
        print("-" * 80)

        resp1 = data_agent.generate_reply(
            client=client,
            prompt=f"Summarize account status: {handoff_message}",
        )
        print("  [+] Verdict: ALLOW (HTTP 200 OK)")
        print(f"  [+] Local Model Output: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Step 4: Public Agent Attempts Public Model Egress (Blocked)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 4] PublicWriter Attempts Egress to Public Cloud Model (gpt-4o)")
        print("-" * 80)

        try:
            public_writer.generate_reply(
                client=client,
                prompt=f"Draft newsletter quoting: {handoff_message}",
                model="gpt-4o",
            )
            print("  [-] UNEXPECTED: Confidential context reached public cloud!")
        except PolicyDenialError as err:
            print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] AutoGen Guardrail: Confidential records blocked from external egress.")

        # ---------------------------------------------------------------------
        # Step 5: Multi-Agent Handoff with In-Flight Field Sanitization
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 5] Handoff to PublicWriter with In-Flight Dynamic Masking")
        print("-" * 80)

        resp5 = public_writer.generate_reply(
            client=client,
            prompt=f"Draft public announcement using: {handoff_message}",
            model="gpt-4o",
            permit_masked=True,
        )
        print("  [+] Verdict: SANITIZED & ALLOWED (HTTP 200 OK)")
        sanitized_text = resp5["choices"][0]["message"]["content"]
        print(f"  [+] Redacted Model Output: {sanitized_text}")

        # ---------------------------------------------------------------------
        # Step 6: Embed Cryptographic Provenance Watermark
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Step 6] Cryptographic Provenance Watermark on AutoGen Output")
        print("-" * 80)

        watermarked = client.embed_watermark(
            text=sanitized_text,
            snapshot_sequence=health.get("snapshot_sequence", 1),
            caller_key=public_writer.caller_key,
        )
        print(f"  [+] Invisible Watermark Embedded ({len(watermarked)} chars)")

        extracted = client.extract_watermark(watermarked)
        print(f"  [+] Forensic Verification: valid={extracted.get('signature_valid')}")
        print(f"      Snapshot Seq: {extracted.get('snapshot_sequence')} | Caller: {extracted.get('caller_key')}")

        print("\n" + "=" * 80)
        print("          AUTOGEN ZERO-TRUST INTEGRATION DEMO PASSED           ")
        print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
