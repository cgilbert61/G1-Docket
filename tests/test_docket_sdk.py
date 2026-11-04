"""Unit tests for the G1 Docket Python SDK."""

from __future__ import annotations

from pathlib import Path
import httpx
import pytest

from docket import AsyncDocketClient, DocketClient, DocketError, PolicyDenialError
from docket.client import compute_file_sha256, wrap_object_tag


def test_sdk_helpers(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Hello G1 Docket", encoding="utf-8")

    digest = compute_file_sha256(test_file)
    assert len(digest) == 64
    assert DocketClient.hash_file(test_file) == digest

    tag = DocketClient.wrap_object("file://test.txt", "Some text")
    assert tag == '<pod:object locator="file://test.txt">Some text</pod:object>'

    tag_with_hash = DocketClient.wrap_object("file://test.txt", "Some text", sha256=digest)
    assert tag_with_hash == f'<pod:object locator="file://test.txt" sha256="{digest}">Some text</pod:object>'


def test_docket_client_context_manager():
    with DocketClient() as client:
        assert client.base_url == "http://localhost:18082"
        assert client.admin_key == "pod-dev-admin-key"


def test_docket_client_mock_policy_denial():
    # Mock a 403 policy denial response
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=403,
            json={"error": {"message": "Request denied by data attestation policy.", "code": "policy_denied"}},
        )

    transport = httpx.MockTransport(handler)
    client = DocketClient()
    client._client = httpx.Client(transport=transport)

    with pytest.raises(PolicyDenialError) as exc_info:
        client.chat_completions(messages=[{"role": "user", "content": "secret"}])

    assert exc_info.value.status_code == 403
    assert "policy_denied" in str(exc_info.value.response_body)


def test_docket_client_mock_success():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok", "mode": "enforce"})
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(200, json={"choices": [{"message": {"content": "acknowledged"}}]})
        if request.url.path == "/v1/records/lookup":
            return httpx.Response(200, json={"locator": "file://doc.txt", "tier": "Public"})
        if request.url.path == "/v1/snapshot/latest":
            return httpx.Response(200, json={"payloadType": "https://schemas.proofofdata.dev/snapshot/v0.1"})
        return httpx.Response(404, json={"detail": "Not found"})

    transport = httpx.MockTransport(handler)
    client = DocketClient()
    client._client = httpx.Client(transport=transport)

    health = client.get_health()
    assert health["status"] == "ok"

    completion = client.chat_completions(messages=[{"role": "user", "content": "hello"}])
    assert completion["choices"][0]["message"]["content"] == "acknowledged"

    record = client.lookup_record("file://doc.txt")
    assert record["tier"] == "Public"

    snap = client.get_latest_snapshot()
    assert "payloadType" in snap

    # Test sync wait_for_sync
    def sync_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "snapshot_sequence": 5})

    client._client = httpx.Client(transport=httpx.MockTransport(sync_handler))
    assert client.wait_for_sync(min_sequence=5, timeout_sec=2, interval_sec=0.1) is True


def test_async_docket_client_mock():
    async def _run():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/healthz":
                return httpx.Response(200, json={"status": "ok", "mode": "enforce", "snapshot_sequence": 5})
            return httpx.Response(200, json={"status": "received"})

        transport = httpx.MockTransport(handler)
        async with AsyncDocketClient() as client:
            client._client = httpx.AsyncClient(transport=transport)
            health = await client.get_health()
            assert health["status"] == "ok"
            assert await client.wait_for_sync(min_sequence=5, timeout_sec=2, interval_sec=0.1) is True

    import asyncio
    asyncio.run(_run())


def test_docket_client_governance_methods():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/worm/verify":
            return httpx.Response(200, json={"valid": True, "total_entries": 10})
        if request.url.path == "/api/worm/export":
            fmt = request.url.params.get("format", "json")
            if fmt == "csv":
                return httpx.Response(200, text="entry_id,timestamp_utc_iso8601\n1,2026-11-04")
            return httpx.Response(200, json={"events": [], "total_events": 0})
        if request.url.path == "/api/quarantine/export":
            fmt = request.url.params.get("format", "json")
            if fmt == "csv":
                return httpx.Response(200, text="quarantine_id,status\nQ-1,QUARANTINED")
            return httpx.Response(200, json={"items": [], "total_items": 0})
        return httpx.Response(404, json={"detail": "Not found"})

    transport = httpx.MockTransport(handler)
    client = DocketClient()
    client._client = httpx.Client(transport=transport)

    verify = client.verify_worm_chain()
    assert verify["valid"] is True

    worm_json = client.export_worm_ledger(format="json")
    assert "events" in worm_json

    worm_csv = client.export_worm_ledger(format="csv")
    assert "entry_id,timestamp_utc_iso8601" in worm_csv

    q_json = client.export_quarantine(format="json")
    assert "items" in q_json

    q_csv = client.export_quarantine(format="csv")
    assert "quarantine_id,status" in q_csv


def test_docket_sdk_abac_headers():
    client = DocketClient()
    headers = client._caller_headers(
        caller_key="pod-key-confidential",
        caller_dept="Finance",
        target_region="eu-central-1",
        caller_id="agent-007",
        jwt_token="mock-jwt",
    )
    assert headers["X-POD-Caller-Key"] == "pod-key-confidential"
    assert headers["X-POD-Caller-Dept"] == "Finance"
    assert headers["X-POD-Target-Region"] == "eu-central-1"
    assert headers["X-POD-Caller-Id"] == "agent-007"
    assert headers["X-POD-Caller-Token"] == "mock-jwt"


def test_docket_rag_integrations():
    from docket.integrations import (
        DocketRAGDocument,
        extract_prompt_locators,
        format_rag_prompt,
        wrap_rag_documents,
    )

    doc1 = DocketRAGDocument(
        locator="s3://lake/doc1.md",
        content="Fact 1",
    )
    assert doc1.to_pod_tag() == '<pod:object locator="s3://lake/doc1.md">Fact 1</pod:object>'

    docs = [
        doc1,
        {"locator": "snowflake://corp/tbl", "content": "Row A | Row B"},
        {"page_content": "Page content text", "source": "file://corp/policy.pdf"},
        ("gs://vertex/data.csv", "id,val\n1,100"),
    ]
    wrapped = wrap_rag_documents(docs)
    assert '<pod:object locator="s3://lake/doc1.md">Fact 1</pod:object>' in wrapped
    assert '<pod:object locator="snowflake://corp/tbl">Row A | Row B</pod:object>' in wrapped
    assert '<pod:object locator="file://corp/policy.pdf">Page content text</pod:object>' in wrapped
    assert '<pod:object locator="gs://vertex/data.csv">id,val\n1,100</pod:object>' in wrapped

    tpl = "Context:\n{context}\n\nQuestion: What is X?"
    prompt = format_rag_prompt(tpl, docs)
    assert "Context:\n<pod:object" in prompt

    locators = extract_prompt_locators(prompt)
    assert locators == [
        "s3://lake/doc1.md",
        "snowflake://corp/tbl",
        "file://corp/policy.pdf",
        "gs://vertex/data.csv",
    ]


def test_docket_framework_integrations_and_tool_decorator():
    from docket.integrations import attested_tool, wrap_agent_tool_output, wrap_rag_documents

    # 1. wrap_agent_tool_output
    out1 = wrap_agent_tool_output("snowflake://db/tbl", "100 rows", auto_hash=True)
    assert '<pod:object locator="snowflake://db/tbl" sha256=' in out1
    assert "100 rows</pod:object>" in out1

    # 2. @attested_tool with static locator
    @attested_tool("snowflake://analytics/public/metrics", auto_hash=True)
    def fetch_metrics(metric_name: str) -> str:
        return f"{metric_name}: 99.4%"

    tagged_res = fetch_metrics("uptime")
    assert '<pod:object locator="snowflake://analytics/public/metrics" sha256=' in tagged_res
    assert "uptime: 99.4%</pod:object>" in tagged_res

    # 3. @attested_tool with dynamic locator callable
    @attested_tool(lambda table: f"snowflake://prod/{table}")
    def run_sql(table: str) -> str:
        return f"SELECT * FROM {table}"

    sql_res = run_sql("customers")
    assert sql_res == '<pod:object locator="snowflake://prod/customers">SELECT * FROM customers</pod:object>'

    # 4. Duck-typed LangChain Document
    class MockLangChainDoc:
        def __init__(self, content: str, source: str):
            self.page_content = content
            self.metadata = {"source": source}

    # 5. Duck-typed LlamaIndex NodeWithScore
    class MockNode:
        def __init__(self, text: str, file_path: str):
            self.text = text
            self.metadata = {"file_path": file_path}

    class MockNodeWithScore:
        def __init__(self, text: str, file_path: str):
            self.node = MockNode(text, file_path)

    docs = [
        MockLangChainDoc("LangChain retrieved chunk", "s3://legal/contract.pdf"),
        MockNodeWithScore("LlamaIndex retrieved chunk", "snowflake://warehouse/q3_kpi"),
    ]
    wrapped = wrap_rag_documents(docs)
    assert '<pod:object locator="s3://legal/contract.pdf">LangChain retrieved chunk</pod:object>' in wrapped
    assert '<pod:object locator="snowflake://warehouse/q3_kpi">LlamaIndex retrieved chunk</pod:object>' in wrapped

    # 6. DocketDocumentTransformer
    from docket.integrations import DocketDocumentTransformer, DocketLlamaIndexPostprocessor

    transformer = DocketDocumentTransformer(auto_hash=True)
    transformed = transformer.transform_documents([MockLangChainDoc("Doc content", "s3://corp/doc.md")])
    assert len(transformed) == 1
    assert '<pod:object locator="s3://corp/doc.md" sha256=' in transformed[0].page_content
    assert "Doc content</pod:object>" in transformed[0].page_content

    # 7. DocketLlamaIndexPostprocessor
    postprocessor = DocketLlamaIndexPostprocessor(auto_hash=True)
    post_nodes = postprocessor.postprocess_nodes([MockNodeWithScore("Node text", "snowflake://corp/view")])
    assert len(post_nodes) == 1
    assert '<pod:object locator="snowflake://corp/view" sha256=' in post_nodes[0].node.text
    assert "Node text</pod:object>" in post_nodes[0].node.text
