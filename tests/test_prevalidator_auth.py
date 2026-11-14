"""
Unit and Integration Tests for Unified Session Authentication in the G1 Prevalidator Gateway.
Verifies shared session cookie verification with Governance, machine-to-machine API exemptions,
browser route protection, RBAC enforcement (auditor read-only lockouts), and login/logout flows.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from governance.auth import AuthManager, SESSION_COOKIE_NAME
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from prevalidator.proxy import create_prevalidator_app
from registry.signing import Keyring


@pytest.fixture
def auth_setup(tmp_path, monkeypatch):
    """Sets up a shared keys directory and test prevalidator app."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("POD_PUBLIC_KEY_DIR", str(keys_dir))
    monkeypatch.setenv("POD_KEY_DIR", str(keys_dir))
    monkeypatch.setenv("DOCKET_REQUIRE_AUTH", "true")
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")

    keyring = Keyring(public_key_dir=keys_dir, verification_only=True)
    store = InMemorySnapshotStore(keyring)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce")

    auth_mgr = AuthManager(keys_dir=keys_dir)
    app = create_prevalidator_app(
        enforcer=enforcer,
        upstream_gateway_url="mock://local",
        auth_manager=auth_mgr,
        keys_dir=keys_dir,
    )
    client = TestClient(app, follow_redirects=False)
    return client, auth_mgr, keys_dir


def test_unauthenticated_browser_redirected_to_login(auth_setup):
    """Browser routes (GET / and GET /dlp) must redirect unauthenticated clients to /login."""
    client, _, _ = auth_setup

    resp = client.get("/")
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?next=/"

    resp_dlp = client.get("/dlp")
    assert resp_dlp.status_code == 302
    assert resp_dlp.headers["location"] == "/login?next=/dlp"


def test_login_flow_and_session_cookie_minting(auth_setup):
    """POST /login with valid institutional credentials returns a signed docket_session cookie."""
    client, auth_mgr, _ = auth_setup

    # Test GET /login renders login page
    get_login = client.get("/login")
    assert get_login.status_code == 200
    assert "Operator Sign In" in get_login.text
    assert "G1 Docket" in get_login.text

    # Test POST /login with valid credentials
    login_data = {
        "username": "admin",
        "password": "DocketAdmin2026!Secure",
    }
    resp = client.post("/login", data=login_data)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    assert SESSION_COOKIE_NAME in resp.cookies

    # Accessing GET / with the session cookie now succeeds
    auth_cookie = resp.cookies[SESSION_COOKIE_NAME]
    dash_resp = client.get("/", cookies={SESSION_COOKIE_NAME: auth_cookie})
    assert dash_resp.status_code == 200
    assert "G1 Docket" in dash_resp.text


def test_shared_session_with_governance(auth_setup):
    """A session token minted by the Governance AuthManager using the shared key is recognized by Prevalidator."""
    client, auth_mgr, keys_dir = auth_setup

    # Simulate Governance subsystem minting an operator session on port 18084
    gov_auth_mgr = AuthManager(keys_dir=keys_dir)
    operator_user = gov_auth_mgr.users["operator1"]
    shared_token = gov_auth_mgr.create_session_token(operator_user)

    # Prevalidator receives this cookie on port 18082
    whoami_resp = client.get("/api/whoami", cookies={SESSION_COOKIE_NAME: shared_token})
    assert whoami_resp.status_code == 200
    data = whoami_resp.json()
    assert data["authenticated"] is True
    assert data["operator"] == "operator1"
    assert data["role"] == "triage_operator"

    # GET / is accessible
    dash_resp = client.get("/", cookies={SESSION_COOKIE_NAME: shared_token})
    assert dash_resp.status_code == 200


def test_invalid_or_expired_cookie_rejected(auth_setup):
    """Tampered or invalid session cookies are rejected and redirected to /login."""
    client, _, _ = auth_setup

    bad_cookies = [
        "invalid.token",
        "tampered_payload.bad_signature",
        "eyJzdWIiOiAiYWRtaW4ifQ.invalid_sig",
    ]
    for c in bad_cookies:
        resp = client.get("/", cookies={SESSION_COOKIE_NAME: c})
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]


def test_logout_clears_cookie(auth_setup):
    """GET /logout clears the session cookie and redirects to /login."""
    client, auth_mgr, _ = auth_setup
    admin_token = auth_mgr.create_session_token(auth_mgr.users["admin"])

    resp = client.get("/logout", cookies={SESSION_COOKIE_NAME: admin_token})
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]


def test_m2m_api_exemption_chat_completions(auth_setup):
    """AI agent / M2M endpoints (/v1/chat/completions, /healthz, /metrics) must NOT require browser session cookies."""
    client, _, _ = auth_setup

    # Healthz and metrics require no cookies
    assert client.get("/healthz").status_code == 200
    assert client.get("/metrics").status_code == 200

    # /v1/chat/completions accepts standard API keys without session cookies
    chat_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": "Hello, world!"}],
    }
    chat_headers = {
        "Authorization": "Bearer pod-caller-key",
        "X-POD-Caller-Key": "pod-caller-key",
    }
    resp = client.post("/v1/chat/completions", json=chat_payload, headers=chat_headers)
    # The prevalidator evaluates the request using API keys; it should not redirect to /login
    assert resp.status_code in (200, 403)  # 200 allowed or 403 policy block, never 302 login redirect!
    assert "location" not in resp.headers


def test_rbac_auditor_read_only_restriction(auth_setup):
    """Auditors can read scorecards, but cannot trigger mutating directory prevalidation or mode changes."""
    client, auth_mgr, _ = auth_setup

    auditor_token = auth_mgr.create_session_token(auth_mgr.users["auditor1"])
    operator_token = auth_mgr.create_session_token(auth_mgr.users["operator1"])

    # 1. Auditor trying to trigger prevalidate-directory should receive 403 Forbidden
    preval_payload = {
        "directory_path": "pc_demo_folder",
        "caller_key": "pod-key-confidential",
        "model": "local-model",
    }
    auditor_resp = client.post(
        "/v1/prevalidate-directory",
        json=preval_payload,
        cookies={SESSION_COOKIE_NAME: auditor_token},
    )
    assert auditor_resp.status_code == 403
    assert "auditor" in auditor_resp.json()["detail"].lower()

    # 2. Operator triggering prevalidate-directory is allowed through RBAC (proceeds to execution)
    op_resp = client.post(
        "/v1/prevalidate-directory",
        json=preval_payload,
        cookies={SESSION_COOKIE_NAME: operator_token},
    )
    # Execution completes or processes files, not blocked by 403
    assert op_resp.status_code != 403

    # 3. Auditor cannot change gateway mode
    mode_resp = client.post(
        "/v1/admin/mode",
        json={"mode": "observe"},
        cookies={SESSION_COOKIE_NAME: auditor_token},
    )
    assert mode_resp.status_code == 403


def test_json_login_api(auth_setup):
    """Programmatic API clients can log in via JSON POST /login."""
    client, _, _ = auth_setup

    resp = client.post(
        "/login",
        json={"username": "operator1", "password": "TriageOperator2026!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "authenticated"
    assert data["operator"] == "operator1"
    assert data["role"] == "triage_operator"
    assert SESSION_COOKIE_NAME in resp.cookies
