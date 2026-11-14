"""Unit and Integration Tests for Native Google Gemini Gateway Prevalidator.

Tests `/v1beta/models/{model}:generateContent` and `:streamGenerateContent`
against G1-Docket cryptographic data attestation snapshots.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from prevalidator.proxy import create_prevalidator_app
from registry.signing import Keyring, compute_bytes_sha256
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


def _setup_gemini_test_environment(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'gemini_test.db').as_posix()}"
    keys_dir = tmp_path / "keys"
    registry = RegistryService(db_url=db_url, key_dir=keys_dir)

    # 1. Attest Public content
    pub_text = "Google Gemini public reference data."
    pub_sha = compute_bytes_sha256(pub_text.encode("utf-8"))
    registry.issue_or_queue_finding(
        locator="file:///gemini/public_doc.txt",
        content_sha256=pub_sha,
        tier="Public",
        owner="data-team@enterprise.corp",
    )

    # 2. Attest Restricted content
    sec_text = "Quarterly secret earnings numbers 2026."
    sec_sha = compute_bytes_sha256(sec_text.encode("utf-8"))
    registry.issue_or_queue_finding(
        locator="file:///gemini/confidential_earnings.xlsx",
        content_sha256=sec_sha,
        tier="Restricted",
        owner="finance@enterprise.corp",
    )

    # 3. Publish Snapshot
    publisher = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    envelope = publisher.publish_snapshot()
    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(envelope)

    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        strict_inline_hash=True,
    )
    app = create_prevalidator_app(
        enforcer=enforcer,
        upstream_gateway_url="mock://gemini-upstream",
    )
    return app, registry, pub_sha, sec_sha


def test_gemini_generate_content_allowed(tmp_path: Path):
    app, registry, pub_sha, _ = _setup_gemini_test_environment(tmp_path)
    client = TestClient(app)

    try:
        # Prompt containing attested public <pod:object>
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": f'Summarize this document: <pod:object locator="file:///gemini/public_doc.txt" sha256="{pub_sha}">Google Gemini public reference data.</pod:object>'
                        }
                    ],
                }
            ],
            "generationConfig": {"temperature": 0.2},
        }

        resp = client.post(
            "/v1beta/models/gemini-1.5-pro:generateContent",
            json=payload,
            headers={"X-POD-Caller-Clearance": "Public"},
        )
        assert resp.status_code == 200
        assert resp.headers.get("X-POD-Attestation-Verdict") == "ALLOW"
        data = resp.json()
        assert "candidates" in data
        assert len(data["candidates"]) > 0
        candidate = data["candidates"][0]
        assert candidate["content"]["role"] == "model"
        assert "[Google Gemini Gateway Ack (gemini-1.5-pro)]" in candidate["content"]["parts"][0]["text"]
    finally:
        registry.close()


def test_gemini_generate_content_restricted_blocked(tmp_path: Path):
    app, registry, _, sec_sha = _setup_gemini_test_environment(tmp_path)
    client = TestClient(app)

    try:
        # Prompt containing Restricted object with insufficient Public clearance
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": f'Explain: <pod:object locator="file:///gemini/confidential_earnings.xlsx" sha256="{sec_sha}">Quarterly secret earnings numbers 2026.</pod:object>'
                        }
                    ],
                }
            ]
        }

        resp = client.post(
            "/v1beta/models/gemini-1.5-flash:generateContent",
            json=payload,
            headers={"X-POD-Caller-Clearance": "Public"},
        )
        assert resp.status_code == 403
        assert resp.headers.get("X-Blocked-By") == "G1-Docket-Prevalidator"
        assert resp.headers.get("X-POD-Attestation-Verdict") == "BLOCKED"
        err = resp.json()
        assert "error" in err
        assert err["error"]["code"] == "policy_denied"
    finally:
        registry.close()


def test_gemini_generate_content_hash_drift(tmp_path: Path):
    app, registry, pub_sha, _ = _setup_gemini_test_environment(tmp_path)
    client = TestClient(app)

    try:
        # Prompt where inner text differs from attested hash
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": f'<pod:object locator="file:///gemini/public_doc.txt" sha256="{pub_sha}">TAMPERED INNER CONTENT HERE</pod:object>'
                        }
                    ],
                }
            ]
        }

        resp = client.post(
            "/v1beta/models/gemini-1.5-pro:generateContent",
            json=payload,
            headers={"X-POD-Caller-Clearance": "Public"},
        )
        assert resp.status_code == 403
        assert resp.headers.get("X-POD-Attestation-Verdict") == "BLOCKED"
    finally:
        registry.close()


def test_gemini_stream_generate_content(tmp_path: Path):
    app, registry, pub_sha, _ = _setup_gemini_test_environment(tmp_path)
    client = TestClient(app)

    try:
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": f'Stream: <pod:object locator="file:///gemini/public_doc.txt" sha256="{pub_sha}">Google Gemini public reference data.</pod:object>'
                        }
                    ],
                }
            ]
        }

        resp = client.post(
            "/v1beta/models/gemini-1.5-pro:streamGenerateContent",
            json=payload,
            headers={"X-POD-Caller-Clearance": "Public"},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        assert resp.headers.get("X-POD-Attestation-Verdict") == "ALLOW"
        body = resp.text
        assert "data:" in body
        assert "candidates" in body
    finally:
        registry.close()
