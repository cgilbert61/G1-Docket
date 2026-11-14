"""Tests for G1 Docket Model Context Protocol (MCP) Server and Interceptor."""

import json
from docket.integrations import DocketMCPServer, DocketMCPInterceptor


def test_docket_mcp_server_initialize():
    server = DocketMCPServer(name="g1-docket-mcp-test", version="1.0.0")
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"},
    }
    resp = server.handle_jsonrpc(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert "result" in resp
    assert resp["result"]["serverInfo"]["name"] == "g1-docket-mcp-test"
    assert "tools" in resp["result"]["capabilities"]


def test_docket_mcp_server_tools_list_and_call():
    server = DocketMCPServer()
    
    # List tools
    req_list = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    resp_list = server.handle_jsonrpc(req_list)
    tools = resp_list["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "pod_verify_locator" in tool_names
    assert "pod_attest_tool_output" in tool_names

    # Call pod_attest_tool_output
    req_call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "pod_attest_tool_output",
            "arguments": {
                "locator": "mcp://jira/SEC-101",
                "content": "Jira ticket regarding firewall rules",
                "auto_hash": True,
            },
        },
    }
    resp_call = server.handle_jsonrpc(req_call)
    assert resp_call["id"] == 3
    content = resp_call["result"]["content"][0]["text"]
    assert '<pod:object locator="mcp://jira/SEC-101"' in content
    assert 'sha256=' in content
    assert 'Jira ticket regarding firewall rules' in content


def test_docket_mcp_server_resources():
    server = DocketMCPServer()
    
    req_list = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/list",
        "params": {},
    }
    resp_list = server.handle_jsonrpc(req_list)
    assert len(resp_list["result"]["resources"]) >= 1

    req_read = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "resources/read",
        "params": {"uri": "pod://policies/tiers"},
    }
    resp_read = server.handle_jsonrpc(req_read)
    text = resp_read["result"]["contents"][0]["text"]
    data = json.loads(text)
    assert "tiers" in data
    assert "Restricted" in data["tiers"]
    assert data["tiers"]["Restricted"]["ai_eligibility"] == "deny"


def test_docket_mcp_interceptor():
    interceptor = DocketMCPInterceptor(default_locator_prefix="mcp://corp-tools")
    
    raw_tool_result = {
        "content": [
            {"type": "text", "text": "Customer account balance: $450,000"}
        ]
    }
    intercepted = interceptor.intercept_tool_result("crm_query", raw_tool_result)
    text = intercepted["content"][0]["text"]
    assert '<pod:object locator="mcp://corp-tools/crm_query"' in text
    assert 'sha256=' in text
    assert 'Customer account balance: $450,000' in text
