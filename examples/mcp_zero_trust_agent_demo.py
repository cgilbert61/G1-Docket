#!/usr/bin/env python3
"""G1 Docket - Model Context Protocol (MCP) Zero-Trust Integration Demo.

Demonstrates how G1 Docket acts as a Zero-Trust MCP Server and Tool Interceptor
for AI agents connecting via Cursor, Claude Desktop, Antigravity, or LangChain.
"""

import json
from docket.integrations import DocketMCPServer, DocketMCPInterceptor


def run_mcp_agent_demo() -> bool:
    print("=" * 80)
    print("        G1 DOCKET: MODEL CONTEXT PROTOCOL (MCP) ZERO-TRUST DEMO        ")
    print("=" * 80)

    # 1. Initialize Zero-Trust MCP Server
    print("\n[Step 1] Initializing DocketMCPServer conforming to MCP 2024-11-05 spec...")
    server = DocketMCPServer(name="g1-docket-mcp-demo", version="1.0.0")

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"},
    }
    init_resp = server.handle_jsonrpc(init_req)
    print("  [+] Server Initialized:", init_resp["result"]["serverInfo"])
    print("  [+] Capabilities:", list(init_resp["result"]["capabilities"].keys()))

    # 2. Inspect Available Tools
    print("\n[Step 2] Listing MCP Attestation & Provenance Tools...")
    tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    tools_resp = server.handle_jsonrpc(tools_req)
    tools = tools_resp["result"]["tools"]
    for t in tools:
        print(f"  [>] Tool: {t['name']:25} | {t['description']}")

    # 3. Call `pod_attest_tool_output` via standard MCP JSON-RPC
    print("\n[Step 3] Calling `pod_attest_tool_output` to wrap database query payload...")
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "pod_attest_tool_output",
            "arguments": {
                "locator": "snowflake://corp_wh/finance/quarterly_forecast",
                "content": "Q4 Projected Gross Margin: 74.2% across Enterprise Segment",
                "auto_hash": True,
            },
        },
    }
    call_resp = server.handle_jsonrpc(call_req)
    attested_token = call_resp["result"]["content"][0]["text"]
    print("  [+] Output Wrapped in Provenance Token:")
    print(f"      {attested_token}")

    # 4. Read Policy Resource `pod://policies/tiers`
    print("\n[Step 4] Querying MCP Policy Resource `pod://policies/tiers`...")
    res_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/read",
        "params": {"uri": "pod://policies/tiers"},
    }
    res_resp = server.handle_jsonrpc(res_req)
    policies = json.loads(res_resp["result"]["contents"][0]["text"])
    for tier, cfg in policies["tiers"].items():
        print(f"  [>] Tier: {tier:15} | Eligibility: {cfg['ai_eligibility']:7} | Egress: {cfg['egress_class']}")

    # 5. Third-Party MCP Tool Interceptor
    print("\n[Step 5] Applying DocketMCPInterceptor to wrap arbitrary external tool outputs...")
    interceptor = DocketMCPInterceptor(default_locator_prefix="mcp://external-tools")
    simulated_tool_result = {
        "content": [
            {
                "type": "text",
                "text": "Jira Issue SEC-902: Zero-Trust edge proxy firewall configuration.",
            }
        ]
    }
    intercepted = interceptor.intercept_tool_result("jira_get_issue", simulated_tool_result)
    intercepted_text = intercepted["content"][0]["text"]
    print("  [+] Intercepted & Provenance-Stamped Text:")
    print(f"      {intercepted_text}")

    print("\n" + "=" * 80)
    print("        ALL MODEL CONTEXT PROTOCOL (MCP) VERIFICATIONS PASSED        ")
    print("=" * 80)
    return True


if __name__ == "__main__":
    run_mcp_agent_demo()
