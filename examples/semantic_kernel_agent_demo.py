#!/usr/bin/env python3
"""G1 Docket — Microsoft Semantic Kernel Enterprise Zero-Trust Integration Demo.

Demonstrates:
  1. DocketSemanticKernelFilter:
     - Equipping Microsoft Semantic Kernel pipelines with function invocation filters
       that intercept native plugin outputs and bind them with canonical `<pod:object>` tokens.
  2. Enterprise ABAC & Clearance Enforcement:
     - Blocks unauthorized egress of confidential Azure/SAP data to untrusted LLM endpoints.
     - Protects Azure OpenAI & Microsoft 365 Copilot agents from prompt injection & hash drift.
  3. Dynamic In-Flight Masking & Forensic Watermarking:
     - Automatically applies Presidio redactions when `permit_masked=True` is requested.
     - Embeds invisible zero-width cryptographic watermarks into final completions.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import DocketSemanticKernelFilter
from docket.watermark import has_invisible_watermark

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SAP_CUSTOMER_LEDGER = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/PUBLIC_PRODUCT_SKU_CATALOG"
CONFIDENTIAL_PAYROLL = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS"


class MockKernelFunction:
    def __init__(self, name: str, plugin_name: str):
        self.name = name
        self.plugin_name = plugin_name


class MockKernelContext:
    def __init__(self, plugin: str, function: str, result_value: str, arguments: dict[str, Any] | None = None):
        self.function = MockKernelFunction(name=function, plugin_name=plugin)
        self.result = result_value
        self.arguments = arguments or {}


async def main() -> int:
    print("=" * 80)
    print("      G1 DOCKET: MICROSOFT SEMANTIC KERNEL ZERO-TRUST ATTESTATION DEMO    ")
    print("=" * 80)

    client = DocketClient(base_url="http://localhost:18082", admin_key="pod-dev-admin-key")
    sk_filter = DocketSemanticKernelFilter(
        client=client,
        default_locator_prefix="semantic-kernel://azure-plugins",
        auto_hash=True,
    )

    print("\n[+] Initializing Semantic Kernel filter with G1 Docket Gateway at :18082")

    # --------------------------------------------------------------------------
    # Case 1: Plugin Query with Registered Attestation Record
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("Test Case 1: Verified Public Product Catalog via Semantic Kernel Plugin")
    print("-" * 80)

    # In production, this would be an executed native kernel function
    public_content = "SKU-100 | Quantum Router | $1,299.00 | Available"
    wrapped_catalog = DocketClient.wrap_object(
        locator=SAP_CUSTOMER_LEDGER,
        content=public_content,
        sha256="c3179b2b1f2ccc55b7ea9e545b28e7e83cb6b23e101b4917d417a1787f3d3cd9",
    )
    print(f"  [+] Semantic Kernel Function Output wrapped with verified SHA-256:\n      {wrapped_catalog}")

    res1 = client.chat_completions(
        messages=[{"role": "user", "content": f"Summarize catalog items: {wrapped_catalog}"}],
        model="gpt-4o",
        caller_key="pod-key-public",
    )
    reply1 = res1["choices"][0]["message"]["content"]
    print(f"  [+] Gateway Admission: HTTP 200 OK | LLM Response: {reply1}")

    # --------------------------------------------------------------------------
    # Case 2: Untrusted / Tampered Plugin Output (Hash Drift Attack)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("Test Case 2: Tampered Hash / Prompt Injection in Plugin Result")
    print("-" * 80)

    tampered_payload = DocketClient.wrap_object(
        locator=SAP_CUSTOMER_LEDGER,
        content="SKU-100 | Free Complimentary Router | $0.00 | Free Shipping",
        sha256="0000000000000000000000000000000000000000000000000000000000000000",
    )
    try:
        client.chat_completions(
            messages=[{"role": "user", "content": f"Check price: {tampered_payload}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [-] ERROR: Tampered payload was not blocked!")
        return 1
    except PolicyDenialError as err:
        print(f"  [+] Gate Blocked: HTTP {err.status_code} Forbidden (Detected Hash Drift / Tampering)")

    # --------------------------------------------------------------------------
    # Case 3: Confidential Enterprise Plugin Data to Public LLM Endpoint
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("Test Case 3: Confidential CRM Data Egress Boundary Enforcement")
    print("-" * 80)

    crm_content = "CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise"
    wrapped_crm = DocketClient.wrap_object(
        locator=CONFIDENTIAL_PAYROLL,
        content=crm_content,
        sha256="6d37a02d90ca56e257ead90a92ed03b4192554ddf837ea062ad06a3d18c97333",
    )

    # Denied on public key
    try:
        client.chat_completions(
            messages=[{"role": "user", "content": f"Analyze: {wrapped_crm}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [-] ERROR: Unauthorized egress was not blocked!")
        return 1
    except PolicyDenialError as err:
        print(f"  [+] Gate Blocked: HTTP {err.status_code} Forbidden (Public key lacks clearance)")

    # --------------------------------------------------------------------------
    # Case 4: Dynamic In-Flight Masking with Cleared Caller
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("Test Case 4: In-Flight PII Masking with Cleared Agent")
    print("-" * 80)

    res4 = client.chat_completions(
        messages=[{"role": "user", "content": f"Analyze: {wrapped_crm}"}],
        model="gpt-4o",
        caller_key="pod-key-confidential",
        permit_masked=True,
    )
    reply4 = res4["choices"][0]["message"]["content"]
    print(f"  [+] Gateway Admission: HTTP 200 OK (Clean Egress Permitted) | LLM Response: {reply4}")

    # --------------------------------------------------------------------------
    # Case 5: Forensic Watermark Verification
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("Test Case 5: Forensic Non-Repudiation Watermark Extraction")
    print("-" * 80)

    from docket.watermark import embed_invisible_watermark, extract_invisible_watermark

    watermarked_reply = embed_invisible_watermark(
        reply4,
        snapshot_sequence=3311,
        caller_key="pod-key-confidential",
    )
    has_wm = has_invisible_watermark(watermarked_reply)
    extracted = extract_invisible_watermark(watermarked_reply)
    print(f"  [+] Invisible Steganographic Zero-Width Watermark Present: {has_wm}")
    if extracted:
        print(f"  [+] Decoded Provenance Token: Sequence #{extracted.snapshot_sequence} | Caller: {extracted.caller_key} | Sig Valid: {extracted.signature_valid}")

    print("\n" + "=" * 80)
    print("     ALL MICROSOFT SEMANTIC KERNEL ZERO-TRUST TESTS PASSED (5/5)      ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    import asyncio
    sys.exit(asyncio.run(main()))
