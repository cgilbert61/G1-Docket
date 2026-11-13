"""
Unit and Integration Tests for Governance Authentication and Session Security.
Verifies PBKDF2 password derivation, HMAC session signing, brute-force lockout,
and Role-Based Access Control (RBAC) in dual-control triage flows.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from governance.auth import AuthManager, hash_password, verify_password, SESSION_COOKIE_NAME
from governance.triage_server import create_governance_app


def test_password_hashing_and_verification():
    raw_pass = "TestSecret2026!"
    hashed = hash_password(raw_pass)
    assert "$" in hashed
    salt, dk = hashed.split("$", 1)
    assert len(salt) == 32  # 16-byte hex
    assert len(dk) == 64    # sha256 hex

    # Positive match
    assert verify_password(raw_pass, hashed) is True
    # Negative match
    assert verify_password("WrongPassword", hashed) is False
    assert verify_password("", hashed) is False


def test_session_token_minting_and_tamper_rejection(tmp_path):
    mgr = AuthManager(keys_dir=tmp_path)
    user = mgr.users["operator1"]

    token = mgr.create_session_token(user, ttl_seconds=3600)
    assert "." in token

    # Valid token verification
    verified = mgr.verify_session_token(token)
    assert verified is not None
    assert verified["sub"] == "operator1"
    assert verified["role"] == "triage_operator"

    # Tampered payload rejected
    b64_p, b64_s = token.split(".", 1)
    tampered_p = b64_p[:-2] + "AA"
    assert mgr.verify_session_token(f"{tampered_p}.{b64_s}") is None

    # Tampered signature rejected
    tampered_s = b64_s[:-2] + "00"
    assert mgr.verify_session_token(f"{b64_p}.{tampered_s}") is None

    # Expired token rejected
    expired_token = mgr.create_session_token(user, ttl_seconds=-10)
    assert mgr.verify_session_token(expired_token) is None


def test_brute_force_rate_limit_lockout(tmp_path):
    mgr = AuthManager(keys_dir=tmp_path)

    # 4 failed attempts should fail normally (returning None)
    for _ in range(4):
        res = mgr.authenticate("operator1", "IncorrectPassword", client_ip="10.0.0.99")
        assert res is None

    # 5th failed attempt
    res = mgr.authenticate("operator1", "IncorrectPassword", client_ip="10.0.0.99")
    assert res is None

    # 6th attempt should now trigger lockout ValueError
    with pytest.raises(ValueError) as exc_info:
        mgr.authenticate("operator1", "TriageOperator2026!", client_ip="10.0.0.99")
    assert "Too many failed login attempts" in str(exc_info.value)


def test_login_flow_and_session_cookie(tmp_path):
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "test_config.yaml"
    cfg_file.write_text(f"""
server:
  host: "127.0.0.1"
  port: 18083
  inference_gateway_url: "http://127.0.0.1:18082"
storage:
  worm_sqlite_path: "{p_str}/worm.db"
  worm_jsonl_path: "{p_str}/worm.jsonl"
  quarantine_db_path: "{p_str}/quarantine.db"
  siem_buffer_db_path: "{p_str}/siem.db"
  keys_dir: "{p_str}/keys"
siem_destinations: []
""", encoding="utf-8")

    app = create_governance_app(config_path=cfg_file)
    client = TestClient(app)

    # 1. GET /login renders form
    resp_login_page = client.get("/login")
    assert resp_login_page.status_code == 200
    assert "Operator Sign In" in resp_login_page.text

    # 2. POST /login with bad credentials
    resp_bad = client.post("/login", data={"username": "operator1", "password": "WrongPassword"})
    assert resp_bad.status_code == 401
    assert "Invalid operator ID or password." in resp_bad.text

    # 3. POST /login with valid credentials
    resp_good = client.post(
        "/login",
        data={"username": "operator1", "password": "TriageOperator2026!"},
        follow_redirects=False,
    )
    assert resp_good.status_code == 302
    assert resp_good.headers["location"] == "/"
    assert SESSION_COOKIE_NAME in resp_good.cookies

    # 4. Verify session API endpoint
    cookie_val = resp_good.cookies[SESSION_COOKIE_NAME]
    resp_session = client.get("/api/auth/session", cookies={SESSION_COOKIE_NAME: cookie_val})
    assert resp_session.status_code == 200
    sess_json = resp_session.json()
    assert sess_json["authenticated"] is True
    assert sess_json["operator"] == "operator1"
    assert sess_json["role"] == "triage_operator"

    # 5. GET /logout clears session
    resp_logout = client.get("/logout", follow_redirects=False)
    assert resp_logout.status_code == 302
    assert resp_logout.headers["location"] == "/login"


def test_rbac_privilege_enforcement(tmp_path):
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "test_config.yaml"
    cfg_file.write_text(f"""
server:
  host: "127.0.0.1"
  port: 18083
  inference_gateway_url: "http://127.0.0.1:18082"
storage:
  worm_sqlite_path: "{p_str}/worm.db"
  worm_jsonl_path: "{p_str}/worm.jsonl"
  quarantine_db_path: "{p_str}/quarantine.db"
  siem_buffer_db_path: "{p_str}/siem.db"
  keys_dir: "{p_str}/keys"
siem_destinations: []
""", encoding="utf-8")

    app = create_governance_app(config_path=cfg_file)
    auth_mgr = app.state.auth_manager
    q_store = app.state.quarantine_store

    qid = q_store.stage_quarantine(
        event_type="DOCKET_DENIAL",
        reason_code="UNATTESTED_DATA_OBJECT",
        payload_digest="aa" * 32,
        raw_payload={"messages": [{"role": "user", "content": "Sensitive payload"}]},
        locator_uri="file:///confidential_brief.docx",
        claimed_tier="Confidential",
        extracted_text="Sensitive board memo",
    )

    client = TestClient(app)

    # Mint session cookies for different roles
    op_cookie = auth_mgr.create_session_token(auth_mgr.users["operator1"])
    auditor_cookie = auth_mgr.create_session_token(auth_mgr.users["auditor1"])
    approver_cookie = auth_mgr.create_session_token(auth_mgr.users["approver1"])

    # 1. Auditor attempts to stage override -> Must receive 403 Forbidden
    client.cookies.set(SESSION_COOKIE_NAME, auditor_cookie)
    resp_auditor_stage = client.post(
        f"/api/quarantine/{qid}/stage-override",
        json={"rationale": "Auditor trying to intervene"},
    )
    assert resp_auditor_stage.status_code == 403
    assert "Auditor role has read-only privileges" in resp_auditor_stage.json()["detail"]

    # 2. Operator stages override -> Allowed
    client.cookies.set(SESSION_COOKIE_NAME, op_cookie)
    resp_op_stage = client.post(
        f"/api/quarantine/{qid}/stage-override",
        json={"rationale": "Emergency financial review needed"},
    )
    assert resp_op_stage.status_code == 200
    assert resp_op_stage.json()["status"] == "AWAITING_SECOND_KEY"

    # 3. Operator attempts to approve own override -> Must fail (Four-Eyes or Role)
    resp_op_approve = client.post(
        f"/api/quarantine/{qid}/approve-override",
        json={"notes": "Operator approving own request"},
    )
    assert resp_op_approve.status_code == 403

    # 4. Approver signs second key -> Allowed
    client.cookies.set(SESSION_COOKIE_NAME, approver_cookie)
    resp_approver = client.post(
        f"/api/quarantine/{qid}/approve-override",
        json={"notes": "Approved by security officer"},
    )
    assert resp_approver.status_code == 200
    assert resp_approver.json()["status"] == "RELEASED"
