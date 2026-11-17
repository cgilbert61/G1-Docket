"""Unit and integration tests for Caller Identity & Authentication Enforcement (Production vs Demo Mode).

Validates:
1. Production mode (DOCKET_ENVIRONMENT=production or DOCKET_REQUIRE_AUTH=true):
   - Missing token/key -> 403 UNOWNED_AGENT_BLOCKED
   - Invalid or expired token -> 403 UNOWNED_AGENT_BLOCKED
   - Unknown caller key -> 403 UNOWNED_AGENT_BLOCKED
   - Valid token (Public/Internal) -> allowed through to data evaluation
   - Valid configured key (e.g. pod-key-public) -> allowed through to data evaluation
2. Demo mode (default, DOCKET_ENVIRONMENT unset / demo):
   - Missing token, invalid token, unknown key fall through to "Public" clearance without blocking
3. Claim extraction and audit log enrichment:
   - Verified JWT sub lands in caller_id (not shadowed by default "anonymous")
   - Verified JWT agent_id lands in agent_id
   - Verified JWT owner lands in owner
   - AuditLogEntry and audit events record caller_id, agent_id, and owner
"""

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
import jwt
import pytest
from starlette.testclient import TestClient

from prevalidator.enforcer import (
    InMemorySnapshotStore,
    PrevalidatorEnforcer,
    REASON_UNOWNED_AGENT_BLOCKED,
)
from prevalidator.proxy import create_prevalidator_app
from registry.signing import Keyring


@pytest.fixture
def test_setup(tmp_path: Path):
    keyring = Keyring()
    store = InMemorySnapshotStore(keyring)
    content = "Public release note details"
    content_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    store._snapshot_predicate = {
        "sequence_number": 1,
        "expires_at": "2099-01-01T00:00:00Z",
        "entries": {
            "file:///data/public_doc.txt": {
                "content_sha256": content_sha,
                "minimum_clearance": "Public",
                "egress_class": "public_api",
                "ai_eligibility": "allow",
                "status": "active",
                "record_expires_at": "2099-01-01T00:00:00Z",
            }
        },
    }
    jwt_secret = "test-jwt-secret-with-minimum-32-chars-length"
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        jwt_secret=jwt_secret,
    )
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)
    return {
        "enforcer": enforcer,
        "client": client,
        "jwt_secret": jwt_secret,
        "content": content,
        "content_sha": content_sha,
    }


def test_production_mode_unowned_agent_blocked_without_token(test_setup, monkeypatch):
    """In production mode, a request without a token or key must be denied with UNOWNED_AGENT_BLOCKED."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    enforcer = test_setup["enforcer"]

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello LLM"}],
    }
    resp = client.post("/v1/chat/completions", json=payload)
    assert resp.status_code == 403
    assert resp.headers.get("X-POD-Reason-Codes") == REASON_UNOWNED_AGENT_BLOCKED
    assert resp.headers.get("X-POD-Attestation-Verdict") == "BLOCKED"
    assert resp.json()["error"]["code"] == "policy_denied"

    # Verify audit log entry
    last_audit = enforcer.audit_log[-1]
    assert last_audit.decision == "deny"
    assert REASON_UNOWNED_AGENT_BLOCKED in last_audit.reason_codes
    assert last_audit.caller_clearance == "Unresolved"


def test_production_mode_unowned_agent_blocked_with_invalid_token(test_setup, monkeypatch):
    """In production mode, a request with an invalid/tampered token must be denied with UNOWNED_AGENT_BLOCKED."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    enforcer = test_setup["enforcer"]

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello LLM"}],
    }
    headers = {"X-POD-Caller-Token": "invalid.jwt.token.here"}
    resp = client.post("/v1/chat/completions", json=payload, headers=headers)
    assert resp.status_code == 403
    assert resp.headers.get("X-POD-Reason-Codes") == REASON_UNOWNED_AGENT_BLOCKED

    last_audit = enforcer.audit_log[-1]
    assert REASON_UNOWNED_AGENT_BLOCKED in last_audit.reason_codes


def test_production_mode_unowned_agent_blocked_with_expired_token(test_setup, monkeypatch):
    """In production mode, an expired JWT token must be denied with UNOWNED_AGENT_BLOCKED."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    jwt_secret = test_setup["jwt_secret"]
    enforcer = test_setup["enforcer"]

    expired_claims = {
        "sub": "agent-exp",
        "clearance": "Public",
        "exp": int(time.time()) - 3600,
    }
    expired_token = jwt.encode(expired_claims, jwt_secret, algorithm="HS256")

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello LLM"}],
    }
    headers = {"X-POD-Caller-Token": expired_token}
    resp = client.post("/v1/chat/completions", json=payload, headers=headers)
    assert resp.status_code == 403
    assert resp.headers.get("X-POD-Reason-Codes") == REASON_UNOWNED_AGENT_BLOCKED


def test_production_mode_unowned_agent_blocked_with_unknown_key(test_setup, monkeypatch):
    """In production mode, an unconfigured/unknown caller key must be denied with UNOWNED_AGENT_BLOCKED."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    enforcer = test_setup["enforcer"]

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello LLM"}],
    }
    headers = {"X-POD-Caller-Key": "unknown-unconfigured-key-999"}
    resp = client.post("/v1/chat/completions", json=payload, headers=headers)
    assert resp.status_code == 403
    assert resp.headers.get("X-POD-Reason-Codes") == REASON_UNOWNED_AGENT_BLOCKED


def test_production_mode_valid_token_allowed_and_enriches_claims(test_setup, monkeypatch):
    """In production mode, a valid token passes through to evaluation and populates sub, agent_id, and owner in audit."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    jwt_secret = test_setup["jwt_secret"]
    enforcer = test_setup["enforcer"]
    content = test_setup["content"]
    content_sha = test_setup["content_sha"]

    valid_claims = {
        "sub": "autonomous-agent-77",
        "agent_id": "agent-id-777",
        "owner": "sponsor.operator@corp.com",
        "clearance": "Public",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(valid_claims, jwt_secret, algorithm="HS256")

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Public query:\n<pod:object locator="file:///data/public_doc.txt" sha256="{content_sha}">{content}</pod:object>',
            }
        ],
    }
    # Pass X-POD-Caller-Id to verify token's sub wins over default header
    headers = {
        "X-POD-Caller-Token": token,
        "X-POD-Caller-Id": "header-default-id",
    }
    resp = client.post("/v1/chat/completions", json=payload, headers=headers)
    assert resp.status_code == 200

    last_audit = enforcer.audit_log[-1]
    assert last_audit.decision == "allow"
    assert last_audit.caller_clearance == "Public"
    # Token's sub must land in caller_id (not shadowed by "header-default-id")
    assert last_audit.caller_id == "autonomous-agent-77"
    assert last_audit.agent_id == "agent-id-777"
    assert last_audit.owner == "sponsor.operator@corp.com"

    # Verify to_dict() includes identity fields
    d = last_audit.to_dict()
    assert d["caller_id"] == "autonomous-agent-77"
    assert d["agent_id"] == "agent-id-777"
    assert d["owner"] == "sponsor.operator@corp.com"


def test_production_mode_valid_configured_key_allowed(test_setup, monkeypatch):
    """In production mode, a configured key (e.g. pod-key-public) is allowed through."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    client = test_setup["client"]
    enforcer = test_setup["enforcer"]
    content = test_setup["content"]
    content_sha = test_setup["content_sha"]

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Public query:\n<pod:object locator="file:///data/public_doc.txt" sha256="{content_sha}">{content}</pod:object>',
            }
        ],
    }
    headers = {"X-POD-Caller-Key": "pod-key-public"}
    resp = client.post("/v1/chat/completions", json=payload, headers=headers)
    assert resp.status_code == 200
    assert enforcer.audit_log[-1].caller_clearance == "Public"


def test_demo_mode_fall_through_unchanged(test_setup, monkeypatch):
    """In demo mode (DOCKET_ENVIRONMENT unset / default), missing token or unknown key falls through to Public."""
    monkeypatch.delenv("DOCKET_ENVIRONMENT", raising=False)
    monkeypatch.delenv("DOCKET_REQUIRE_AUTH", raising=False)
    client = test_setup["client"]
    enforcer = test_setup["enforcer"]
    content = test_setup["content"]
    content_sha = test_setup["content_sha"]

    # 1. No token or key
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Public query:\n<pod:object locator="file:///data/public_doc.txt" sha256="{content_sha}">{content}</pod:object>',
            }
        ],
    }
    resp1 = client.post("/v1/chat/completions", json=payload)
    assert resp1.status_code == 200
    assert enforcer.audit_log[-1].caller_clearance == "Public"

    # 2. Invalid token
    resp2 = client.post(
        "/v1/chat/completions",
        json=payload,
        headers={"X-POD-Caller-Token": "invalid-token"},
    )
    assert resp2.status_code == 200
    assert enforcer.audit_log[-1].caller_clearance == "Public"

    # 3. Unknown key
    resp3 = client.post(
        "/v1/chat/completions",
        json=payload,
        headers={"X-POD-Caller-Key": "unknown-key"},
    )
    assert resp3.status_code == 200
    assert enforcer.audit_log[-1].caller_clearance == "Public"
