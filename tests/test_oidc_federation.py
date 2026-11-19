"""Tests for Enterprise OIDC JWT signature verification & federation across Governance and Prevalidator."""

import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import governance.auth as g_auth
from governance.auth import AuthManager
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from prevalidator.proxy import create_prevalidator_app
from registry.signing import Keyring


class MockJWK:
    def __init__(self, key: Any) -> None:
        self.key = key


class MockJWKSClient:
    def __init__(self, key: Any) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> MockJWK:
        return MockJWK(self._key)

    def get_signing_keys(self) -> list[MockJWK]:
        return [MockJWK(self._key)]

    def get_signing_key(self, kid: Any = None) -> MockJWK:
        return MockJWK(self._key)


@pytest.fixture
def oidc_env(monkeypatch: pytest.MonkeyPatch):
    """Fixture providing RSA keys, mock JWKS client, and configured issuer/audience environment."""
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    test_iss = "https://identity.enterprise.gov/v2.0"
    test_aud = "https://docket.enterprise.gov/api"

    mock_client = MockJWKSClient(pub_key)
    monkeypatch.setattr(g_auth, "get_jwks_client", lambda iss: mock_client)
    monkeypatch.setenv("DOCKET_OIDC_ISSUER", test_iss)
    monkeypatch.setenv("DOCKET_OIDC_AUDIENCE", test_aud)
    monkeypatch.setenv("POD_OIDC_ISSUER", test_iss)
    monkeypatch.setenv("POD_OIDC_AUDIENCE", test_aud)

    return {
        "priv_key": priv_key,
        "pub_key": pub_key,
        "wrong_key": wrong_key,
        "issuer": test_iss,
        "audience": test_aud,
    }


def test_1_governance_valid_rs256_session_and_roles(tmp_path: Path, oidc_env: dict[str, Any]):
    """(1) Governance valid RS256 token -> authenticated session, role mapping preserved."""
    mgr = AuthManager(keys_dir=tmp_path)
    now = int(time.time())
    payload = {
        "sub": "ciso-officer@enterprise.gov",
        "email": "ciso-officer@enterprise.gov",
        "roles": ["Security_Approver", "Compliance_Officer"],
        "exp": now + 3600,
        "nbf": now - 10,
        "iss": oidc_env["issuer"],
        "aud": oidc_env["audience"],
    }
    valid_jwt = jwt.encode(payload, oidc_env["priv_key"], algorithm="RS256")

    sess = mgr.verify_bearer_token(valid_jwt)
    assert sess is not None
    assert sess["sub"] == "ciso-officer@enterprise.gov"
    assert sess["role"] == "security_approver"
    assert sess["auth_type"] == "oidc_jwt"


def test_2_governance_wrong_key_signature_returns_none(tmp_path: Path, oidc_env: dict[str, Any]):
    """(2) Governance token signed with wrong key or forged signature -> None."""
    mgr = AuthManager(keys_dir=tmp_path)
    now = int(time.time())
    payload = {
        "sub": "attacker@external.corp",
        "roles": ["Security_Approver"],
        "exp": now + 3600,
        "iss": oidc_env["issuer"],
        "aud": oidc_env["audience"],
    }
    wrong_key_jwt = jwt.encode(payload, oidc_env["wrong_key"], algorithm="RS256")
    fake_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciJ9.invalid_signature"

    assert mgr.verify_bearer_token(wrong_key_jwt) is None
    assert mgr.verify_bearer_token(fake_jwt) is None


def test_3_governance_wrong_issuer_returns_none(tmp_path: Path, oidc_env: dict[str, Any]):
    """(3) Governance token with untrusted/wrong issuer -> None."""
    mgr = AuthManager(keys_dir=tmp_path)
    now = int(time.time())
    payload = {
        "sub": "user@rogue-issuer.org",
        "roles": ["Security_Approver"],
        "exp": now + 3600,
        "iss": "https://rogue-issuer.org/auth",
        "aud": oidc_env["audience"],
    }
    wrong_iss_jwt = jwt.encode(payload, oidc_env["priv_key"], algorithm="RS256")
    assert mgr.verify_bearer_token(wrong_iss_jwt) is None


def test_4_governance_expired_token_returns_none(tmp_path: Path, oidc_env: dict[str, Any]):
    """(4) Governance expired RS256 token -> None."""
    mgr = AuthManager(keys_dir=tmp_path)
    now = int(time.time())
    payload = {
        "sub": "user@enterprise.gov",
        "roles": ["Security_Approver"],
        "exp": now - 60,
        "iss": oidc_env["issuer"],
        "aud": oidc_env["audience"],
    }
    expired_jwt = jwt.encode(payload, oidc_env["priv_key"], algorithm="RS256")
    assert mgr.verify_bearer_token(expired_jwt) is None


def test_5_governance_native_hmac_token_still_verifies(tmp_path: Path):
    """(5) Governance native HMAC 2-part token continues to verify seamlessly."""
    mgr = AuthManager(keys_dir=tmp_path)
    user = mgr.users["operator1"]
    native_tok = mgr.create_session_token(user)

    sess = mgr.verify_bearer_token(native_tok)
    assert sess is not None
    assert sess["sub"] == "operator1"
    assert sess["role"] == "triage_operator"


def test_6_enforcer_valid_rs256_caller_token(oidc_env: dict[str, Any]):
    """(6) Enforcer valid RS256 caller token -> clearance + context claims resolved."""
    store = InMemorySnapshotStore(Keyring())
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        oidc_issuer=oidc_env["issuer"],
        oidc_audience=oidc_env["audience"],
    )
    now = int(time.time())
    payload = {
        "sub": "agent-orchestrator-alpha",
        "clearance": "Confidential",
        "agent_id": "agent-uuid-777",
        "owner": "secops-team",
        "dept": "cyber-defense",
        "tenant_id": "gov-tenant-alpha",
        "jurisdiction": "us-east-1",
        "exp": now + 3600,
        "iss": oidc_env["issuer"],
        "aud": oidc_env["audience"],
    }
    valid_jwt = jwt.encode(payload, oidc_env["priv_key"], algorithm="RS256")
    headers = {"X-POD-Caller-Token": valid_jwt}

    clearance = enforcer.resolve_caller_clearance(headers)
    assert clearance == "Confidential"

    ctx = enforcer.resolve_caller_context(
        headers,
        payload={"model": "gpt-4o"},
        caller_clearance=clearance,
        target_egress="public_api",
    )
    assert ctx["caller_id"] == "agent-orchestrator-alpha"
    assert ctx["agent_id"] == "agent-uuid-777"
    assert ctx["owner"] == "secops-team"
    assert ctx["department"] == "cyber-defense"
    assert ctx["tenant_id"] == "gov-tenant-alpha"
    assert ctx["jurisdiction"] == "us-east-1"


def test_7_enforcer_wrong_key_rs256_rejected(oidc_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch):
    """(7) Enforcer wrong-key RS256 -> None under auth-enforced conditions."""
    monkeypatch.setenv("DOCKET_REQUIRE_AUTH", "true")
    store = InMemorySnapshotStore(Keyring())
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        oidc_issuer=oidc_env["issuer"],
        oidc_audience=oidc_env["audience"],
    )
    now = int(time.time())
    payload = {
        "sub": "forged-agent",
        "clearance": "Restricted",
        "exp": now + 3600,
        "iss": oidc_env["issuer"],
        "aud": oidc_env["audience"],
    }
    wrong_jwt = jwt.encode(payload, oidc_env["wrong_key"], algorithm="RS256")
    headers = {"X-POD-Caller-Token": wrong_jwt}

    assert enforcer.resolve_caller_clearance(headers) is None


def test_8_enforcer_hs256_local_token_unchanged():
    """(8) Enforcer HS256 local token remains completely unchanged and valid."""
    store = InMemorySnapshotStore(Keyring())
    hs256_secret = "pod-local-test-secret-at-least-32-chars-long!"
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        jwt_secret=hs256_secret,
    )
    token = jwt.encode(
        {"sub": "local-agent-42", "clearance": "Restricted", "agent_id": "agent-42", "owner": "dev-user"},
        hs256_secret,
        algorithm="HS256",
    )
    headers = {"X-POD-Caller-Token": token}

    clearance = enforcer.resolve_caller_clearance(headers)
    assert clearance == "Restricted"

    ctx = enforcer.resolve_caller_context(
        headers,
        payload={"model": "local-model"},
        caller_clearance=clearance,
        target_egress="local_only",
    )
    assert ctx["caller_id"] == "local-agent-42"
    assert ctx["agent_id"] == "agent-42"
    assert ctx["owner"] == "dev-user"


def test_9_verification_latency_and_startup_guard(oidc_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch):
    """(9) Latency benchmark: 100 RS256 verifications with cached key, added p95 vs HS256 < 0.5 ms, plus F3 startup guard."""
    store = InMemorySnapshotStore(Keyring())
    hs256_secret = "pod-local-benchmark-secret-at-least-32-chars-long!"
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="enforce",
        jwt_secret=hs256_secret,
        oidc_issuer=oidc_env["issuer"],
        oidc_audience=oidc_env["audience"],
    )

    now = int(time.time())
    hs_token = jwt.encode({"sub": "bench", "clearance": "Public", "exp": now + 3600}, hs256_secret, algorithm="HS256")
    rs_token = jwt.encode(
        {"sub": "bench", "clearance": "Public", "exp": now + 3600, "iss": oidc_env["issuer"], "aud": oidc_env["audience"]},
        oidc_env["priv_key"],
        algorithm="RS256",
    )

    # Warm-up
    for _ in range(10):
        enforcer._verify_caller_token(hs_token)
        enforcer._verify_caller_token(rs_token)

    # Measure 100 HS256 verifications
    hs_latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        enforcer._verify_caller_token(hs_token)
        hs_latencies.append(time.perf_counter() - t0)

    # Measure 100 RS256 verifications
    rs_latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        enforcer._verify_caller_token(rs_token)
        rs_latencies.append(time.perf_counter() - t0)

    hs_latencies.sort()
    rs_latencies.sort()
    hs_p95_ms = hs_latencies[94] * 1000.0
    rs_p95_ms = rs_latencies[94] * 1000.0
    added_p95_ms = rs_p95_ms - hs_p95_ms

    print(f"\n[BENCHMARK] HS256 p95: {hs_p95_ms:.4f} ms | RS256 cached p95: {rs_p95_ms:.4f} ms | Added p95: {added_p95_ms:.4f} ms")
    assert added_p95_ms < 0.5, f"Added RS256 p95 latency {added_p95_ms:.4f} ms exceeded 0.5 ms threshold"

    # F3 Startup guard test: in auth-enforced production mode without POD_JWT_SECRET or OIDC issuer, refuse to start
    monkeypatch.setenv("DOCKET_REQUIRE_AUTH", "true")
    monkeypatch.delenv("POD_JWT_SECRET", raising=False)
    monkeypatch.delenv("POD_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("DOCKET_OIDC_ISSUER", raising=False)
    with pytest.raises(RuntimeError, match="POD_JWT_SECRET"):
        create_prevalidator_app(enforcer=None)
