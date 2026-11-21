"""
Unit and Integration Tests for HITL Dual-Key Governance & Triage Subsystem.
Verifies four-eyes principle (self-approval rejection), Ed25519 DSSE ticket minting,
automated replay, and FastAPI administrative endpoints.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from governance.dual_key import DualKeyGovernanceManager, FourEyesViolationError
from governance.quarantine import QuarantineStore
from governance.siem_forwarder import SIEMForwarder
from governance.triage_server import create_governance_app
from governance.worm_ledger import WORMAuditLedger
from registry.signing import Keyring, verify_dsse_envelope


@pytest.fixture
def governance_stack(tmp_path):
    q_db = tmp_path / "quarantine.db"
    w_db = tmp_path / "worm.db"
    w_jsonl = tmp_path / "worm.jsonl"
    s_db = tmp_path / "siem.db"
    key_dir = tmp_path / "keys"

    keyring = Keyring(public_key_dir=key_dir, private_key_dir=key_dir)
    keyring.generate_key(algorithm="Ed25519", operator_id="test-authority", activate=True)

    q_store = QuarantineStore(db_path=q_db)
    w_ledger = WORMAuditLedger(db_path=w_db, jsonl_path=w_jsonl)
    s_forwarder = SIEMForwarder(buffer_db_path=s_db, destinations=[])
    manager = DualKeyGovernanceManager(
        quarantine_store=q_store,
        worm_ledger=w_ledger,
        siem_forwarder=s_forwarder,
        keyring=keyring,
        inference_gateway_url="http://127.0.0.1:18082",
    )

    return {
        "q_store": q_store,
        "w_ledger": w_ledger,
        "s_forwarder": s_forwarder,
        "manager": manager,
        "keyring": keyring,
        "w_jsonl": w_jsonl,
    }


def test_four_eyes_violation_and_successful_dual_approval(governance_stack):
    manager = governance_stack["manager"]
    q_store = governance_stack["q_store"]
    keyring = governance_stack["keyring"]
    w_jsonl = governance_stack["w_jsonl"]

    # 1. Stage an un-papered document into quarantine
    qid = q_store.stage_quarantine(
        event_type="DOCKET_DENIAL",
        reason_code="UNATTESTED_DATA_OBJECT",
        payload_digest="aa" * 32,
        raw_payload={"messages": [{"role": "user", "content": "Unattested confidential doc text"}]},
        locator_uri="file:///confidential_brief.docx",
        claimed_tier="Confidential",
        extracted_text="Unattested confidential doc text",
    )

    item_staged = q_store.get_item(qid)
    assert item_staged["status"] == "QUARANTINED"

    # 2. Key 1: Operator A stages override request
    res_k1 = manager.stage_override(
        quarantine_id=qid,
        requester_id="secops_analyst_alice",
        rationale="Emergency board review required under CEO exemption.",
    )
    assert res_k1["status"] == "AWAITING_SECOND_KEY"

    # 3. Four-Eyes Enforcement: Operator A attempts to self-approve Key 2 -> MUST BE REJECTED
    with pytest.raises(FourEyesViolationError) as exc_four_eyes:
        manager.approve_and_release(
            quarantine_id=qid,
            approver_id="secops_analyst_alice",  # Same operator identity!
            notes="I approve my own request.",
            perform_replay=False,
        )
    assert "Four-Eyes Violation: Self-approval prohibited!" in str(exc_four_eyes.value)

    # 4. Key 2: Distinct Operator B signs approval
    res_k2 = manager.approve_and_release(
        quarantine_id=qid,
        approver_id="compliance_director_bob",  # Distinct authorized identity!
        notes="Verified board exemption certificate #8841. Approved for 2-hour window.",
        perform_replay=False,
    )
    assert res_k2["approval_state"] == "APPROVED"
    assert res_k2["status"] == "APPROVED"
    assert res_k2["requester"] == "secops_analyst_alice"
    assert res_k2["approver"] == "compliance_director_bob"

    # 5. Verify cryptographic validity of the minted Ed25519 DSSE emergency ticket
    ticket = res_k2["emergency_ticket"]
    assert "<pod:object" in ticket["pod_xml_tag"]
    assert ticket["tier"] == "Confidential"

    dsse_env = ticket["dsse_envelope"]
    verified = verify_dsse_envelope(dsse_env, keyring=keyring)
    assert verified.verified is True
    assert verified.subject_name == "file:///confidential_brief.docx"
    assert verified.statement["predicate"]["classification"]["tier"] == "Confidential"

    # 6. Verify WORM audit trail was recorded for both Key 1 and Key 2
    w_events = governance_stack["w_ledger"].get_events(limit=10)
    assert len(w_events) == 2
    event_types = [e["event_type"] for e in w_events]
    assert "HITL_DUAL_KEY_RELEASE" in event_types
    assert "HITL_OVERRIDE_REQUEST" in event_types


def test_fastapi_triage_server_routes(tmp_path):
    p_str = str(tmp_path).replace("\\", "/")
    # Create test config
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

    # 1. GET Dashboard HTML
    resp_dashboard = client.get("/")
    assert resp_dashboard.status_code == 200
    assert "G1 Security Infrastructure" in resp_dashboard.text
    assert "Quarantine & Triage Queue" in resp_dashboard.text

    # 2. Intercept event from boundary (:18082)
    resp_intercept = client.post(
        "/api/intercept",
        json={
            "event_type": "DOCKET_DENIAL",
            "reason_code": "UNATTESTED_DATA_OBJECT",
            "payload_digest": "33" * 32,
            "raw_payload": {"messages": [{"role": "user", "content": "intercepted doc"}]},
            "locator_uri": "file:///strategy.pdf",
            "claimed_tier": "Internal",
            "extracted_text": "intercepted doc text",
        },
    )
    assert resp_intercept.status_code == 200
    qid = resp_intercept.json()["quarantine_id"]

    # 3. Stage Key 1
    resp_k1 = client.post(
        f"/api/quarantine/{qid}/stage-override",
        json={"requester_id": "operator_charlie", "rationale": "Urgent review"},
    )
    assert resp_k1.status_code == 200
    assert resp_k1.json()["status"] == "AWAITING_SECOND_KEY"

    # 4. Attempt self-approval via API -> Expect 403 Forbidden
    resp_self_approve = client.post(
        f"/api/quarantine/{qid}/approve-override",
        json={"approver_id": "operator_charlie", "notes": "Self signoff"},
    )
    assert resp_self_approve.status_code == 403
    assert "Four-Eyes Violation" in resp_self_approve.json()["detail"]

    # 5. Distinct Approver signs -> Expect 200 OK
    resp_distinct = client.post(
        f"/api/quarantine/{qid}/approve-override",
        json={"approver_id": "auditor_diana", "notes": "Verified"},
    )
    assert resp_distinct.status_code == 200
    assert resp_distinct.json()["approval_state"] == "APPROVED"
    assert resp_distinct.json()["status"] in ("APPROVED", "DELIVERED", "DISPATCH_REJECTED")

    # 6. Verify WORM Chain API
    resp_verify = client.get("/api/worm/verify")
    assert resp_verify.status_code == 200
    assert resp_verify.json()["valid"] is True
    assert resp_verify.json()["total_entries"] >= 2

    # 7. Test Export APIs (JSON and CSV)
    resp_worm_json = client.get("/api/worm/export?format=json")
    assert resp_worm_json.status_code == 200
    assert "events" in resp_worm_json.json()

    resp_worm_csv = client.get("/api/worm/export?format=csv")
    assert resp_worm_csv.status_code == 200
    assert "entry_id,timestamp_utc_iso8601" in resp_worm_csv.text

    export_auth_headers = {"X-Forwarded-Email": "auditor_diana@company.com", "X-Forwarded-Roles": "auditor"}
    resp_q_json = client.get("/api/quarantine/export?format=json", headers=export_auth_headers)
    assert resp_q_json.status_code == 200
    assert "items" in resp_q_json.json()

    resp_q_csv = client.get("/api/quarantine/export?format=csv", headers=export_auth_headers)
    assert resp_q_csv.status_code == 200
    assert "quarantine_id,timestamp_utc" in resp_q_csv.text

    # 8. Test Authenticated Proxy Identity Extraction (OAuth2-Proxy / Cloudflare Access / Azure EasyAuth)
    resp_dash_auth = client.get("/", headers={"X-Forwarded-Email": "operator_sso@company.com"})
    assert resp_dash_auth.status_code == 200
    assert "operator_sso@company.com" in resp_dash_auth.text

    # Intercept new item to test header-based stage and release
    resp_inc2 = client.post(
        "/api/intercept",
        json={
            "event_type": "DOCKET_DENIAL",
            "reason_code": "UNATTESTED_DATA_OBJECT",
            "payload_digest": "44" * 32,
            "raw_payload": {"messages": [{"role": "user", "content": "proxy doc"}]},
            "locator_uri": "file:///proxy_test.pdf",
            "claimed_tier": "Internal",
            "extracted_text": "proxy test",
        },
    )
    qid2 = resp_inc2.json()["quarantine_id"]
    # Stage without explicit requester_id; extracted from X-Forwarded-Email header
    resp_k1_hdr = client.post(
        f"/api/quarantine/{qid2}/stage-override",
        headers={"X-Forwarded-Email": "requester_corp@company.com"},
        json={"rationale": "SSO staged request"},
    )
    assert resp_k1_hdr.status_code == 200
    assert resp_k1_hdr.json()["first_key"]["operator"] == "requester_corp@company.com"

    # Approve with distinct header
    resp_k2_hdr = client.post(
        f"/api/quarantine/{qid2}/approve-override",
        headers={"X-Forwarded-Email": "approver_ciso@company.com"},
        json={"notes": "SSO approved signoff"},
    )
    assert resp_k2_hdr.status_code == 200
    assert resp_k2_hdr.json()["approval_state"] == "APPROVED"
    assert resp_k2_hdr.json()["status"] in ("APPROVED", "DELIVERED", "DISPATCH_REJECTED")
    assert resp_k2_hdr.json()["approver"] == "approver_ciso@company.com"


def test_demo_vs_production_mode_governance(tmp_path, monkeypatch):
    from governance.triage_server import is_demo_mode

    # 1. Test DOCKET_ENVIRONMENT precedence
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "demo")
    assert is_demo_mode() is True

    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    assert is_demo_mode() is False

    # 2. Test legacy DOCKET_DEMO_MODE compatibility
    monkeypatch.delenv("DOCKET_ENVIRONMENT", raising=False)
    monkeypatch.setenv("DOCKET_DEMO_MODE", "false")
    assert is_demo_mode() is False

    monkeypatch.setenv("DOCKET_DEMO_MODE", "true")
    assert is_demo_mode() is True

    # 3. Test production enforcement rejecting demo identities
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "test_config_prod.yaml"
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

    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    resp_health = client.get("/healthz")
    assert resp_health.status_code == 200
    assert resp_health.json()["environment"] == "production"
    assert resp_health.json()["demo_mode"] is False

    # Stage an item via the intercept API
    resp_inc = client.post(
        "/api/intercept",
        json={
            "event_type": "DOCKET_DENIAL",
            "reason_code": "UNATTESTED_DATA_OBJECT",
            "payload_digest": "55" * 32,
            "raw_payload": {"messages": []},
            "locator_uri": "file:///test_prod.pdf",
            "claimed_tier": "Internal",
            "extracted_text": "sample text",
        },
    )
    assert resp_inc.status_code == 200
    qid = resp_inc.json()["quarantine_id"]

    resp_demo_k1 = client.post(
        f"/api/quarantine/{qid}/stage-override",
        json={"requester_id": "demo-requester", "rationale": "testing production mode"},
    )
    assert resp_demo_k1.status_code == 403
    assert "Demo requester identities are not permitted in production mode" in resp_demo_k1.json()["detail"]


def test_cicd_status_and_secret_audit_endpoints(tmp_path):
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "test_config_cicd.yaml"
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

    # 1. CI/CD status endpoint
    r_ci = client.get("/api/governance/cicd-status")
    assert r_ci.status_code == 200
    ci_data = r_ci.json()
    assert "latest_run" in ci_data
    assert "jobs" in ci_data["latest_run"]
    assert len(ci_data["latest_run"]["jobs"]) >= 4

    # 2. Secret audit endpoint
    r_sec = client.get("/api/governance/secret-audit")
    assert r_sec.status_code == 200
    sec_data = r_sec.json()
    assert sec_data["verdict"] == "CLEAN_PASS"
    assert sec_data["tracked_files"]["active_secrets_detected"] == 0
    assert "credential_inventory" in sec_data
    assert len(sec_data["credential_inventory"]) >= 8

    # 3. Secret audit trigger endpoint
    r_run = client.post("/api/governance/secret-audit/run")
    assert r_run.status_code == 200
    run_data = r_run.json()
    assert run_data["success"] is True
    assert run_data["audit"]["verdict"] == "CLEAN_PASS"

    # 4. Verify dashboard view renders tab-cicd
    r_dash = client.get("/")
    assert r_dash.status_code == 200
    assert "tab-cicd" in r_dash.text
    assert "CI/CD &amp; Security Posture" in r_dash.text or "CI/CD & Security Posture" in r_dash.text

