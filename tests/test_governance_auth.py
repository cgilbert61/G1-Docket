"""
Unit and Integration Tests for Governance Authentication and Session Security.
Verifies PBKDF2 password derivation, HMAC session signing, brute-force lockout,
and Role-Based Access Control (RBAC) in dual-control triage flows.
"""

import base64
import json
import os
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from governance.auth import (
    AuthManager,
    SESSION_COOKIE_NAME,
    compute_totp_code,
    generate_totp_secret,
    hash_password,
    verify_password,
    verify_totp_code,
)
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


def test_auth_events_recorded_in_worm_ledger(tmp_path):
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
    worm_ledger = app.state.worm_ledger

    # 1. Failed login -> records OPERATOR_AUTH_FAILURE
    client.post("/login", data={"username": "operator1", "password": "WrongPassword"})
    events = worm_ledger.get_events(event_type="OPERATOR_AUTH_FAILURE")
    assert len(events) >= 1
    assert events[-1]["actor_identity"] == "operator:operator1"

    # 2. Successful login -> records OPERATOR_AUTH_SUCCESS
    resp_login = client.post("/login", data={"username": "operator1", "password": "TriageOperator2026!"})
    events_ok = worm_ledger.get_events(event_type="OPERATOR_AUTH_SUCCESS")
    assert len(events_ok) >= 1
    assert events_ok[-1]["actor_identity"] == "operator:operator1"

    # 3. Logout -> records OPERATOR_LOGOUT
    client.get("/logout")
    events_logout = worm_ledger.get_events(event_type="OPERATOR_LOGOUT")
    assert len(events_logout) >= 1
    assert events_logout[-1]["actor_identity"] == "operator:operator1"


def test_totp_generation_and_verification():
    secret = generate_totp_secret()
    assert len(secret) >= 16

    # Current time valid code
    code = compute_totp_code(secret)
    assert len(code) == 6
    assert code.isdigit()
    assert verify_totp_code(secret, code) is True

    # Bad codes rejected
    assert verify_totp_code(secret, "000000" if code != "000000" else "111111") is False
    assert verify_totp_code(secret, "abc") is False
    assert verify_totp_code(secret, "") is False

    # Clock drift (+/- 30 seconds) tolerance test
    import time
    past_code = compute_totp_code(secret, for_time=int(time.time()) - 30)
    future_code = compute_totp_code(secret, for_time=int(time.time()) + 30)
    far_past_code = compute_totp_code(secret, for_time=int(time.time()) - 120)

    assert verify_totp_code(secret, past_code, window=1) is True
    assert verify_totp_code(secret, future_code, window=1) is True
    assert verify_totp_code(secret, far_past_code, window=1) is False


def test_sliding_inactivity_timeout(tmp_path):
    mgr = AuthManager(keys_dir=tmp_path)
    user = mgr.users["operator1"]

    token = mgr.create_session_token(user, ttl_seconds=3600)
    # Token valid right now
    assert mgr.verify_session_token(token) is not None

    # Simulate token where last_active was 2000 seconds ago (> 1800s inactivity limit)
    import json
    import base64
    import hmac
    import hashlib
    b64_p, _ = token.split(".", 1)
    payload_pad = b64_p + "=" * (-len(b64_p) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_pad).decode("utf-8"))

    # Set last active to 2000 seconds ago
    payload["last_active"] = payload["iat"] - 2000
    raw_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    new_b64_p = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    new_sig = hmac.new(mgr.session_key, new_b64_p.encode("ascii"), hashlib.sha256).digest()
    new_b64_sig = base64.urlsafe_b64encode(new_sig).decode("ascii").rstrip("=")
    inactive_token = f"{new_b64_p}.{new_b64_sig}"

    # Inactivity expired -> None
    assert mgr.verify_session_token(inactive_token) is None


def test_mfa_login_challenge_and_worm_audit(tmp_path):
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
    worm_ledger = app.state.worm_ledger
    auth_mgr = app.state.auth_manager

    # mfa_operator has a configured totp_secret
    mfa_user = auth_mgr.users["mfa_operator"]
    assert mfa_user.totp_secret is not None

    # 1. Login with correct password but missing/wrong TOTP code -> 401
    resp_no_totp = client.post(
        "/login",
        json={"username": "mfa_operator", "password": "MfaOperator2026!", "totp_code": "000000"},
    )
    assert resp_no_totp.status_code == 401
    assert "Invalid or missing authenticator code" in resp_no_totp.json()["error"]
    mfa_failures = worm_ledger.get_events(event_type="OPERATOR_MFA_FAILURE")
    assert len(mfa_failures) >= 1
    assert mfa_failures[-1]["actor_identity"] == "operator:mfa_operator"

    # 2. Login with correct password AND correct TOTP code -> 200 / authenticated
    valid_totp = compute_totp_code(mfa_user.totp_secret)
    resp_success = client.post(
        "/login",
        json={"username": "mfa_operator", "password": "MfaOperator2026!", "totp_code": valid_totp},
    )
    assert resp_success.status_code == 200
    assert resp_success.json()["status"] == "authenticated"
    assert SESSION_COOKIE_NAME in resp_success.cookies

    # Check WORM ledger has OPERATOR_MFA_SUCCESS
    mfa_successes = worm_ledger.get_events(event_type="OPERATOR_MFA_SUCCESS")
    assert len(mfa_successes) >= 1
    assert mfa_successes[-1]["actor_identity"] == "operator:mfa_operator"
    assert mfa_successes[-1]["metadata"]["mfa_enforced"] is True


def test_cli_operator_login_whoami_logout(tmp_path, monkeypatch, capsys):
    from registry.cli import main as cli_main
    import json
    import urllib.request

    session_file = tmp_path / "test_session.json"
    fake_token = "fake.payload.sig"

    class FakeHTTPResponse:
        def __init__(self, body_dict, headers=None, status=200):
            self.body = json.dumps(body_dict).encode("utf-8")
            self.headers = headers or {}
            self.status = status

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def mock_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith("/login"):
            return FakeHTTPResponse(
                {"status": "authenticated", "operator": "operator1", "role": "triage_operator", "display_name": "Triage Specialist"},
                headers={"Set-Cookie": f"docket_session={fake_token}; Path=/; HttpOnly"},
            )
        if url.endswith("/api/auth/session"):
            return FakeHTTPResponse(
                {"authenticated": True, "operator": "operator1", "role": "triage_operator", "display_name": "Triage Specialist", "email": "operator1@internal.corp"}
            )
        if url.endswith("/logout"):
            return FakeHTTPResponse({"status": "logged_out"})
        raise ValueError(f"Unexpected URL: {url}")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    # 1. Test CLI login
    rc_login = cli_main([
        "login",
        "--url", "http://mock-governance:18084",
        "--username", "operator1",
        "--password", "TriageOperator2026!",
        "--session-file", str(session_file),
    ])
    assert rc_login == 0
    assert session_file.exists()
    saved = json.loads(session_file.read_text(encoding="utf-8"))
    assert saved["operator"] == "operator1"
    assert saved["role"] == "triage_operator"
    assert saved["token"] == fake_token

    # 2. Test CLI whoami
    capsys.readouterr()
    rc_whoami = cli_main(["whoami", "--session-file", str(session_file)])
    assert rc_whoami == 0
    out = capsys.readouterr().out
    assert "operator1" in out
    assert "triage_operator" in out
    assert "Active (Server-Verified)" in out

    # 3. Test CLI logout
    rc_logout = cli_main(["logout", "--session-file", str(session_file)])
    assert rc_logout == 0
    assert not session_file.exists()

    # 4. Test whoami when logged out -> returns 1
    rc_whoami_after = cli_main(["whoami", "--session-file", str(session_file)])
    assert rc_whoami_after == 1


def test_governance_cicd_and_secret_audit_endpoints(tmp_path):
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

    # 1. Test CI/CD telemetry endpoint
    resp_cicd = client.get("/api/cicd/status")
    assert resp_cicd.status_code == 200
    cicd_data = resp_cicd.json()
    assert "status" in cicd_data
    assert "latest_run" in cicd_data
    assert "jobs" in cicd_data["latest_run"]

    # 2. Test Secret audit endpoint
    resp_sec = client.get("/api/security/secret-audit")
    assert resp_sec.status_code == 200
    sec_data = resp_sec.json()
    assert sec_data["verdict"] == "CLEAN_PASS"
    assert sec_data["tracked_files"]["active_secrets_detected"] == 0
    assert "dotfile_isolation" in sec_data


def test_oidc_jwt_bearer_token_validation(tmp_path):
    import time
    mgr = AuthManager(keys_dir=tmp_path)

    # 1. Native 2-part HMAC token is valid as a bearer token
    native_tok = mgr.create_session_token(mgr.users["operator1"])
    native_sess = mgr.verify_bearer_token(native_tok)
    assert native_sess is not None
    assert native_sess["sub"] == "operator1"
    assert native_sess["role"] == "triage_operator"

    # 2. Forge an OIDC JWT with claims
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "sub": "auth0|6123456789abcdef",
        "email": "ciso-officer@enterprise.corp",
        "preferred_username": "ciso_officer",
        "name": "Jane Doe, CISO",
        "roles": ["Security_Approver", "Data_Governance"],
        "exp": now + 3600,
        "iat": now,
        "iss": "https://sts.windows.net/enterprise-tenant-id/",
        "aud": "api://g1-docket-governance",
    }
    b64_h = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("ascii").rstrip("=")
    b64_p = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    fake_jwt = f"{b64_h}.{b64_p}.fake_signature"

    # Verify OIDC token extracts user and maps role
    sess = mgr.verify_bearer_token(fake_jwt)
    assert sess is not None
    assert sess["sub"] == "ciso-officer@enterprise.corp"
    assert sess["role"] == "security_approver"
    assert sess["auth_type"] == "oidc_jwt"

    # 3. Test expired OIDC JWT is rejected
    expired_payload = dict(payload)
    expired_payload["exp"] = now - 60
    b64_exp_p = base64.urlsafe_b64encode(json.dumps(expired_payload).encode("utf-8")).decode("ascii").rstrip("=")
    expired_jwt = f"{b64_h}.{b64_exp_p}.fake_signature"
    assert mgr.verify_bearer_token(expired_jwt) is None

    # 4. Test HTTP API with Authorization: Bearer <fake_jwt>
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "test_oidc_config.yaml"
    cfg_file.write_text(f"""
server:
  host: "127.0.0.1"
  port: 18083
storage:
  worm_sqlite_path: "{p_str}/worm.db"
  worm_jsonl_path: "{p_str}/worm.jsonl"
  quarantine_db_path: "{p_str}/quarantine.db"
  siem_buffer_db_path: "{p_str}/siem.db"
  keys_dir: "{p_str}/keys"
""", encoding="utf-8")
    app = create_governance_app(config_path=cfg_file)
    client = TestClient(app)

    # Calling /api/whoami with Bearer token
    resp = client.get("/api/whoami", headers={"Authorization": f"Bearer {fake_jwt}"})
    assert resp.status_code == 200
    who = resp.json()
    assert who["logged_in"] is True
    assert who["operator"] == "ciso-officer@enterprise.corp"
    assert who["role"] == "security_approver"




