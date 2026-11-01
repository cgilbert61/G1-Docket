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


@pytest.mark.asyncio
async def test_async_docket_client_mock():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok", "mode": "enforce"})
        return httpx.Response(200, json={"status": "received"})

    transport = httpx.MockTransport(handler)
    async with AsyncDocketClient() as client:
        client._client = httpx.AsyncClient(transport=transport)
        health = await client.get_health()
        assert health["status"] == "ok"
