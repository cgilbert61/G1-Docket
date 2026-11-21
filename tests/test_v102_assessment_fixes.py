"""Comprehensive Automated Verification Suite for G1-Docket v1.0.2 Assessment Fix Sheet (Tiers 1, 2, & 3).

Deterministically verifies all 15 remediated findings from the 2026-11-21 Independent Assessment:
  Tier 1 — Trust Core (Items 1–5)
  Tier 2 — Shipped-Artifact Correctness (Items 6–10)
  Tier 3 — Hardening & Claims Hygiene (Items 11–15)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from docket.cli import main as docket_cli_main
from docket.client import DocketClient
from docket.federation import CentralGovernanceHub, RegionalPrevalidatorNode
from docket.watermark import embed_invisible_watermark, extract_invisible_watermark
from engine.classifier import PresidioClassifier
from engine.extractor import TikaDocumentExtractor
from engine.pipeline import AttestationEngine
from engine.service import is_demo_bootstrap_enabled
from governance.auth import AuthManager, SESSION_COOKIE_NAME
from governance.dual_key import DualKeyGovernanceManager
from governance.quarantine import QuarantineStore
from governance.siem_forwarder import SIEMForwarder
from governance.triage_server import create_governance_app
from governance.worm_ledger import WORMIntegrityError, WORMAuditLedger
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer, SnapshotRollbackError
from prevalidator.proxy import (
    CANONICAL_GATEWAY_ENV_VARS,
    GatewaySettings,
    build_outbound_provider_headers,
    create_prevalidator_app,
)
from registry.api import create_registry_app
from registry.schema_validator import ATTESTATION_PREDICATE_TYPE, SNAPSHOT_PREDICATE_TYPE
from registry.signing import (
    Keyring,
    SignatureVerificationError,
    build_attestation_statement,
    build_snapshot_statement,
    compute_bytes_sha256,
    sign_statement,
    verify_dsse_envelope,
)
from registry.store import (
    ApprovalVersionMismatchError,
    DualApprovalSamePrincipalError,
    RegistryService,
)
from snapshot.publisher import SnapshotPublisher


# ==============================================================================
# TIER 1 — ITEM 1: Session & Role Auth on Quarantine & SIEM Integration + Write-Only Secrets
# ==============================================================================
def test_tier1_item1_quarantine_and_siem_rbac_and_write_only_secrets(tmp_path: Path):
    """Prove unauthenticated -> 401, unauthorized role -> 403, authorized role -> 200, and write-only SIEM secrets."""
    p_str = str(tmp_path).replace("\\", "/")
    cfg_file = tmp_path / "gov_config.yaml"
    cfg_file.write_text(
        f"""
server:
  host: "127.0.0.1"
  port: 18084
  inference_gateway_url: "http://127.0.0.1:18082"
storage:
  worm_sqlite_path: "{p_str}/worm.db"
  worm_jsonl_path: "{p_str}/worm.jsonl"
  quarantine_db_path: "{p_str}/quarantine.db"
  siem_buffer_db_path: "{p_str}/siem_buf.db"
  keys_dir: "{p_str}/keys"
siem_destinations:
  - id: "splunk_hec"
    name: "Splunk Enterprise HEC"
    type: "splunk_hec"
    enabled: false
    endpoint_url: "http://localhost:18088/services/collector/event"
""",
        encoding="utf-8",
    )

    app = create_governance_app(config_path=cfg_file)
    auth_mgr = app.state.auth_manager
    qstore = app.state.quarantine_store

    qid = qstore.stage_quarantine(
        event_type="DOCKET_DENIAL",
        reason_code="PRESIDIO_PII_DETECTED",
        payload_digest="a" * 64,
        raw_payload={"messages": [{"role": "user", "content": "Sensitive SSN 123-45-6789"}]},
        locator_uri="file://hr/sensitive.txt",
        claimed_tier="Confidential",
        triggered_rules=["US_SSN"],
        extracted_text="Sensitive SSN 123-45-6789",
    )
    client = TestClient(app)

    # 1. Unauthenticated requests to quarantine & SIEM endpoints MUST return 401
    for path in (
        "/api/quarantine",
        "/api/quarantine/export",
        f"/api/quarantine/{qid}",
        "/api/siem/status",
        "/api/siem/splunk_hec/config",
    ):
        r_unauth = client.get(path)
        assert r_unauth.status_code == 401, f"Expected 401 on unauthenticated GET {path}, got {r_unauth.status_code}"

    # 2. Unauthorized role (e.g. 'guest_viewer' / 'viewer') MUST return 403 on quarantine and SIEM routes
    unauth_role_headers = {"X-Forwarded-Email": "basic-user@corp.org", "X-Forwarded-Roles": "basic_user"}
    # Note: basic_user maps to triage_operator by default in fallback unless role is explicitly restricted;
    # test auditor role on SIEM config write (403) and viewer session token on quarantine (403).
    from governance.auth import UserAccount
    viewer_acct = UserAccount(
        username="viewer1",
        password_hash="unused",
        role="viewer",
        display_name="Read Viewer",
        email="viewer1@corp.org",
    )
    viewer_token = auth_mgr.create_session_token(viewer_acct)
    for path in ("/api/quarantine", "/api/quarantine/export", f"/api/quarantine/{qid}", "/api/siem/splunk_hec/config"):
        r_forbidden = client.get(path, headers={"Authorization": f"Bearer {viewer_token}"})
        assert r_forbidden.status_code == 403, f"Expected 403 for viewer role on {path}, got {r_forbidden.status_code}"

    # 3. Authorized secops/admin role succeeds (200) on quarantine read/export
    admin_token = auth_mgr.create_session_token(auth_mgr.users["admin"])
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/quarantine", headers=admin_headers).status_code == 200
    assert client.get("/api/quarantine/export", headers=admin_headers).status_code == 200
    assert client.get(f"/api/quarantine/{qid}", headers=admin_headers).status_code == 200

    # 4. Write-only SIEM secrets: POST a secret api_key and auth_header, then verify neither POST nor GET returns plaintext
    secret_key_val = "SPLUNK-SUPER-SECRET-TOKEN-998877"
    secret_hdr_val = "Bearer SENTINEL-SECRET-JWT-112233"
    r_post_cfg = client.post(
        "/api/siem/splunk_hec/config",
        headers=admin_headers,
        json={
            "enabled": True,
            "endpoint": "https://splunk.enterprise.internal:8088/services/collector/event",
            "api_key": secret_key_val,
            "auth_header": secret_hdr_val,
        },
    )
    assert r_post_cfg.status_code == 200
    post_body_str = json.dumps(r_post_cfg.json())
    assert secret_key_val not in post_body_str
    assert secret_hdr_val not in post_body_str
    assert r_post_cfg.json()["destination"]["api_key_configured"] is True
    assert r_post_cfg.json()["destination"]["configured"] is True

    r_get_cfg = client.get("/api/siem/splunk_hec/config", headers=admin_headers)
    assert r_get_cfg.status_code == 200
    get_cfg = r_get_cfg.json()
    get_body_str = json.dumps(get_cfg)
    assert secret_key_val not in get_body_str
    assert secret_hdr_val not in get_body_str
    assert "api_key" not in get_cfg
    assert "auth_header" not in get_cfg
    assert get_cfg["api_key_configured"] is True
    assert get_cfg["auth_header_configured"] is True
    assert get_cfg["configured"] is True

    r_status = client.get("/api/siem/status", headers=admin_headers)
    assert r_status.status_code == 200
    assert secret_key_val not in json.dumps(r_status.json())
    assert secret_hdr_val not in json.dumps(r_status.json())


# ==============================================================================
# TIER 1 — ITEM 2: True Two-Person Dual Approval Bound to Authenticated Principals & Document Version
# ==============================================================================
def test_tier1_item2_two_person_dual_approval_and_version_binding(tmp_path: Path):
    """Prove single caller cannot supply two approver IDs, self-seconding fails (403), stale version fails (409), and two distinct principals succeed."""
    db_url = f"sqlite:///{(tmp_path / 'reg_dual.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    app = create_registry_app(registry=registry)
    client = TestClient(app)

    try:
        locator = "file://finance/q4_board_deck.pdf"
        sha_v1 = compute_bytes_sha256(b"Board deck version 1")
        registry.issue_or_queue_finding(
            locator=locator,
            content_sha256=sha_v1,
            tier="Confidential",
            owner="cfo@enterprise.org",
        )

        # 1. Single authenticated caller attempting to supply two approver_id strings in one payload -> 403
        r_single_body = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "alice@enterprise.org"},
            json={
                "locator": locator,
                "new_tier": "Internal",
                "approvals": [
                    {"approver_id": "alice@enterprise.org", "rationale": "First approval"},
                    {"approver_id": "bob@enterprise.org", "rationale": "Forged second approval in same request"},
                ],
            },
        )
        assert r_single_body.status_code == 403
        assert r_single_body.json()["detail"]["error_code"] == "SINGLE_CALLER_MULTI_APPROVAL_REJECTED"

        # 2. First authenticated principal (alice@enterprise.org) submits first approval -> PENDING_SECOND_APPROVAL
        r_step1 = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "alice@enterprise.org"},
            json={
                "locator": locator,
                "new_tier": "Internal",
                "rationale": "Declassifying after earnings release",
            },
        )
        assert r_step1.status_code in (200, 202)
        step1_data = r_step1.json()
        assert step1_data["status"] == "PENDING_SECOND_APPROVAL"
        doc_version = step1_data["document_version"]

        # 3. Same principal (alice@enterprise.org) attempts to second her own approval -> 403 DUAL_APPROVAL_SAME_PRINCIPAL
        r_self_second = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "alice@enterprise.org"},
            json={
                "locator": locator,
                "new_tier": "Internal",
                "rationale": "Trying to self-second",
                "document_version": doc_version,
            },
        )
        assert r_self_second.status_code == 403
        assert r_self_second.json()["detail"]["error_code"] == "DUAL_APPROVAL_SAME_PRINCIPAL"

        # 4. Stale document_version -> 409 APPROVAL_VERSION_MISMATCH
        r_stale_ver = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "bob@enterprise.org"},
            json={
                "locator": locator,
                "new_tier": "Internal",
                "rationale": "Approving stale version",
                "document_version": "sha256:0000000000000000000000000000000000000000000000000000000000000000:rec:stale",
            },
        )
        assert r_stale_ver.status_code == 409
        assert r_stale_ver.json()["detail"]["error_code"] == "APPROVAL_VERSION_MISMATCH"

        # 5. If document content changes between approval 1 and approval 2, approval 2 fails with 409 APPROVAL_VERSION_MISMATCH
        sha_v2 = compute_bytes_sha256(b"Board deck version 2 modified content")
        registry.issue_or_queue_finding(
            locator=locator,
            content_sha256=sha_v2,
            tier="Confidential",
            owner="cfo@enterprise.org",
        )
        r_mutated = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "bob@enterprise.org"},
            json={
                "locator": locator,
                "new_tier": "Internal",
                "rationale": "Seconding after document mutated",
            },
        )
        assert r_mutated.status_code == 409
        assert r_mutated.json()["detail"]["error_code"] == "APPROVAL_VERSION_MISMATCH"

        # 6. Fresh two-person approval on v2 by alice@enterprise.org then bob@enterprise.org succeeds
        r_v2_step1 = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "alice@enterprise.org"},
            json={"locator": locator, "new_tier": "Internal", "rationale": "Approve v2 step 1"},
        )
        assert r_v2_step1.status_code in (200, 202)
        assert r_v2_step1.json()["status"] == "PENDING_SECOND_APPROVAL"

        r_v2_step2 = client.post(
            "/v1/records/lower-tier",
            headers={"X-Forwarded-Email": "bob@enterprise.org"},
            json={"locator": locator, "new_tier": "Internal", "rationale": "Approve v2 step 2"},
        )
        assert r_v2_step2.status_code == 200
        assert r_v2_step2.json()["status"] in ("APPROVED", "tier_lowered")
        lowered_rec = r_v2_step2.json()["record"]
        assert lowered_rec["tier"] == "Internal"
        approvals = lowered_rec["dsse_envelope"]
        ver = registry.keyring.verify_dsse(approvals, expected_predicate_type=ATTESTATION_PREDICATE_TYPE)
        recorded_approvals = ver.statement["predicate"]["lifecycle"]["tier_lower_approvals"]
        assert len(recorded_approvals) == 2
        assert recorded_approvals[0]["approver_principal_id"] == "alice@enterprise.org"
        assert recorded_approvals[1]["approver_principal_id"] == "bob@enterprise.org"
        assert recorded_approvals[0]["requested_change_digest"] == recorded_approvals[1]["requested_change_digest"]
        assert recorded_approvals[0]["binding_signature"]
        assert recorded_approvals[1]["binding_signature"]
    finally:
        registry.close()


# ==============================================================================
# TIER 1 — ITEM 3: Explicit Extraction-Quality Signal & Fail-Closed Classification
# ==============================================================================
def test_tier1_item3_extraction_quality_and_fail_closed_classification(tmp_path: Path):
    """Evaluate labeled corpus: clean text, scanned image-only PDF, corrupted XLSX, NUL-binary file, and unsupported binary."""
    db_url = f"sqlite:///{(tmp_path / 'extract_eval.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    engine = AttestationEngine(registry=registry)

    try:
        # 1. Clean public text file -> COMPLETE extraction quality, active attestation
        clean_md = tmp_path / "clean_public.md"
        clean_md.write_text("# Open Source SDK Guide\nThis public guide explains the client CLI.", encoding="utf-8")
        res_clean = engine.attest_file(clean_md, owner="docs@enterprise.org", locator_override="file://corpus/clean_public.md")
        assert res_clean["extraction_quality"] == "COMPLETE"
        assert res_clean["extracted_char_count"] > 20
        assert res_clean["status"] in ("active", "issued")

        # 2. Scanned/image-only PDF (valid PDF header & structure, zero extractable text streams) -> UNREADABLE -> PENDING_REVIEW
        scanned_pdf = tmp_path / "scanned_contract.pdf"
        scanned_pdf.write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n%%EOF\n" + (b"\x00" * 128))
        res_pdf = engine.attest_file(scanned_pdf, owner="legal@enterprise.org", locator_override="file://corpus/scanned_contract.pdf")
        assert res_pdf["extraction_quality"] in ("UNREADABLE", "DAMAGED")
        assert res_pdf["status"] == "PENDING_REVIEW"
        assert res_pdf["tier"] != "Public"

        # 3. Corrupted / truncated .xlsx spreadsheet -> DAMAGED -> PENDING_REVIEW (never Public at 0.95 confidence!)
        corrupt_xlsx = tmp_path / "corrupt_payroll.xlsx"
        corrupt_xlsx.write_bytes(b"PK\x03\x04TRUNCATED_CORRUPT_ZIP_ARCHIVE_BYTES")
        res_xlsx = engine.attest_file(corrupt_xlsx, owner="hr@enterprise.org", locator_override="file://corpus/corrupt_payroll.xlsx")
        assert res_xlsx["extraction_quality"] == "DAMAGED"
        assert res_xlsx["status"] == "PENDING_REVIEW"
        assert res_xlsx["tier"] != "Public"

        # 4. Binary NUL-stuffed .txt file -> DAMAGED -> PENDING_REVIEW
        nul_txt = tmp_path / "binary_dump.txt"
        nul_txt.write_bytes(b"\x00\x00\x00\xff\xfe\x00\x00BINARY_PAYLOAD")
        res_nul = engine.attest_file(nul_txt, owner="sec@enterprise.org", locator_override="file://corpus/binary_dump.txt")
        assert res_nul["extraction_quality"] == "DAMAGED"
        assert res_nul["status"] == "PENDING_REVIEW"
        assert res_nul["tier"] != "Public"

        # 5. Unsupported binary extension (.bin) -> UNSUPPORTED -> PENDING_REVIEW
        unsupported_bin = tmp_path / "firmware.bin"
        unsupported_bin.write_bytes(os.urandom(256))
        ext_doc = TikaDocumentExtractor().extract_file(unsupported_bin)
        assert ext_doc.extraction_quality == "UNSUPPORTED"
        verdict = PresidioClassifier().classify_text(
            ext_doc.text,
            extraction_quality=ext_doc.extraction_quality,
            extracted_char_count=ext_doc.extracted_char_count,
            parse_error=ext_doc.parse_error,
        )
        assert verdict.low_confidence is True
        assert verdict.confidence == 0.0
        assert verdict.tier != "Public"
    finally:
        registry.close()


# ==============================================================================
# TIER 1 — ITEM 4: WORM Ledger Completeness Proof, Checkpoint & Startup Reconciliation
# ==============================================================================
def test_tier1_item4_worm_ledger_completeness_checkpoint_and_reconciliation(tmp_path: Path):
    """Prove missing/truncated JSONL fails verification when DB has entries, and startup reconciles missing JSONL tail."""
    db_path = tmp_path / "worm_test.db"
    jsonl_path = tmp_path / "worm_test.jsonl"
    ledger = WORMAuditLedger(db_path=str(db_path), jsonl_path=str(jsonl_path))

    for idx in range(5):
        ledger.append_event(
            event_type="DOCKET_DENIAL",
            actor_identity="boundary:prevalidator",
            payload_digest=hashlib.sha256(f"event-{idx}".encode()).hexdigest(),
            metadata={"seq": idx},
        )

    v_ok = ledger.verify_ledger_integrity()
    assert v_ok["valid"] is True
    assert v_ok["total_entries"] == 5
    assert ledger.checkpoint_path.exists()

    # 1. Delete JSONL export file while SQLite DB and checkpoint hold 5 entries -> verify_ledger_integrity MUST return valid=False
    jsonl_path.unlink()
    v_missing = ledger.verify_ledger_integrity()
    assert v_missing["valid"] is False
    assert v_missing["reason"] == "LEDGER_EXPORT_MISSING_OR_TRUNCATED"

    # 2. Simulate restart: new WORMAuditLedger instance automatically reconciles missing JSONL from committed SQLite rows
    restarted_ledger = WORMAuditLedger(db_path=str(db_path), jsonl_path=str(jsonl_path))
    assert jsonl_path.exists()
    v_reconciled = restarted_ledger.verify_ledger_integrity()
    assert v_reconciled["valid"] is True
    assert v_reconciled["total_entries"] == 5

    # 3. Truncate 2 lines from JSONL export -> verify_ledger_integrity MUST fail with LEDGER_EXPORT_MISSING_OR_TRUNCATED
    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    jsonl_path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    v_truncated = restarted_ledger.verify_ledger_integrity()
    assert v_truncated["valid"] is False
    assert v_truncated["reason"] == "LEDGER_EXPORT_MISSING_OR_TRUNCATED"

    # 4. Restart again -> missing tail entries 4..5 are re-appended and verified against checkpoint
    restarted_again = WORMAuditLedger(db_path=str(db_path), jsonl_path=str(jsonl_path))
    assert restarted_again.verify_ledger_integrity()["valid"] is True
    assert restarted_again.verify_ledger_integrity()["total_entries"] == 5

    # 5. Tamper with line 2 in JSONL -> startup reconciliation detects hash divergence and raises WORMIntegrityError
    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    tampered_obj = json.loads(lines[1])
    tampered_obj["entry_hash"] = "f" * 64
    lines[1] = json.dumps(tampered_obj)
    jsonl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(WORMIntegrityError, match="LEDGER_DIVERGENCE_DETECTED"):
        WORMAuditLedger(db_path=str(db_path), jsonl_path=str(jsonl_path))


# ==============================================================================
# TIER 1 — ITEM 5: Gate Demo Bootstrap Behind Explicit Opt-In Setting (Default OFF)
# ==============================================================================
def test_tier1_item5_demo_bootstrap_gated_off_by_default(monkeypatch: pytest.MonkeyPatch):
    """Prove demo bootstrap is disabled by default and refuses to run DROP TABLE unless explicitly opted in."""
    monkeypatch.delenv("DOCKET_ENABLE_DEMO_BOOTSTRAP", raising=False)
    monkeypatch.delenv("DOCKET_PROFILE", raising=False)
    assert is_demo_bootstrap_enabled() is False

    # Even if one of the two flags is set alone, it remains False
    monkeypatch.setenv("DOCKET_ENABLE_DEMO_BOOTSTRAP", "true")
    monkeypatch.setenv("DOCKET_PROFILE", "production")
    assert is_demo_bootstrap_enabled() is False

    from examples.docker_bootstrap import main as bootstrap_main
    with pytest.raises(RuntimeError, match="DOCKET_ENABLE_DEMO_BOOTSTRAP"):
        bootstrap_main()

    # Only when BOTH DOCKET_ENABLE_DEMO_BOOTSTRAP=true AND DOCKET_PROFILE=demo is it enabled
    monkeypatch.setenv("DOCKET_PROFILE", "demo")
    assert is_demo_bootstrap_enabled() is True


# ==============================================================================
# TIER 2 — ITEM 6: Fix Shipped docket CLI & Watermark API Mismatches
# ==============================================================================
def test_tier2_item6_docket_cli_commands_and_watermark_roundtrip(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Exercise watermark-embed, watermark-inspect, wrap, check-mode, status, and lookup via docket.cli."""
    # 1. watermark-embed and watermark-inspect on a file
    wm_out = tmp_path / "watermarked.txt"
    rc_embed = docket_cli_main(
        [
            "watermark-embed",
            "Confidential RAG synthesis output for executive review.",
            "--owner",
            "secops@enterprise.org",
            "--agent-id",
            "rag-agent-007",
            "--tier",
            "Confidential",
            "--output",
            str(wm_out),
        ]
    )
    assert rc_embed == 0
    capsys.readouterr()

    rc_inspect = docket_cli_main(["watermark-inspect", str(wm_out)])
    assert rc_inspect == 0
    out_inspect = capsys.readouterr().out
    assert "Owner: secops@enterprise.org" in out_inspect
    assert "Agent ID: rag-agent-007" in out_inspect
    assert "Tier: Confidential" in out_inspect

    # 2. wrap command
    sample_file = tmp_path / "doc.txt"
    sample_file.write_text("Quarterly revenue summary", encoding="utf-8")
    rc_wrap = docket_cli_main(["wrap", "file://finance/doc.txt", "--file", str(sample_file)])
    assert rc_wrap == 0
    out_wrap = capsys.readouterr().out
    assert '<pod:object locator="file://finance/doc.txt" sha256="' in out_wrap

    # 3. --check-mode flag and check-mode subcommand
    rc_cm1 = docket_cli_main(["--check-mode"])
    assert rc_cm1 == 0
    rc_cm2 = docket_cli_main(["check-mode"])
    assert rc_cm2 == 0
    capsys.readouterr()

    # 4. Flag ordering: both `docket --url X status` and `docket status --url X --api-key Y` parse cleanly
    from docket.cli import build_parser
    parser = build_parser()
    a1 = parser.parse_args(["--url", "http://gateway.internal:18082", "--api-key", "k1", "status", "--json"])
    assert a1.url == "http://gateway.internal:18082"
    assert a1.api_key == "k1"
    a2 = parser.parse_args(["status", "--url", "http://gateway.internal:18082", "--api-key", "k2", "--json"])
    assert a2.url == "http://gateway.internal:18082"
    assert a2.api_key == "k2"

    # 5. Out-of-tree isolated wheel execution of all 5 CLI commands (status, lookup, wrap, watermark-embed, watermark-inspect) + --check-mode
    import http.server
    import subprocess
    import sys
    import threading
    import zipfile

    repo_root = Path(__file__).resolve().parent.parent
    wheel_path = repo_root / "dist" / "g1_docket_sdk-1.0.2-py3-none-any.whl"
    if not wheel_path.exists():
        (repo_root / "dist").mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(repo_root), "-w", str(repo_root / "dist"), "--no-deps"],
            check=True,
            capture_output=True,
        )
    assert wheel_path.exists(), f"Expected built v1.0.2 wheel at {wheel_path}"

    isolated_site = tmp_path / "isolated_wheel_site"
    isolated_site.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel_path, "r") as zf:
        zf.extractall(isolated_site)

    class _MockGatewayHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/healthz"):
                body = json.dumps({"status": "ok", "mode": "enforce", "snapshot_sequence": 42}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif "/v1/records/lookup" in self.path:
                body = json.dumps(
                    {
                        "found": True,
                        "record": {
                            "locator": "file://finance/doc.txt",
                            "tier": "Internal",
                            "status": "issued",
                            "content_sha256": "b" * 64,
                        },
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _MockGatewayHandler)
    port = httpd.server_address[1]
    srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    srv_thread.start()

    try:
        iso_env = dict(os.environ)
        iso_env["PYTHONPATH"] = str(isolated_site)
        iso_env["PYTHONIOENCODING"] = "utf-8"

        def _run_iso_cli(*cli_args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-m", "docket.cli", *cli_args],
                cwd=str(tmp_path),
                env=iso_env,
                capture_output=True,
                text=True,
                timeout=15,
            )

        r_st = _run_iso_cli("status", "--url", f"http://127.0.0.1:{port}", "--api-key", "test-key")
        assert r_st.returncode == 0, r_st.stderr
        assert "Active Snapshot Sequence: 42" in r_st.stdout

        r_lk = _run_iso_cli("lookup", "file://finance/doc.txt", "--url", f"http://127.0.0.1:{port}", "--api-key", "test-key")
        assert r_lk.returncode == 0, r_lk.stderr
        assert "Tier: Internal" in r_lk.stdout

        r_wr = _run_iso_cli("wrap", "file://finance/doc.txt", "--text", "Inline RAG text")
        assert r_wr.returncode == 0, r_wr.stderr
        assert '<pod:object locator="file://finance/doc.txt"' in r_wr.stdout

        iso_wm_file = tmp_path / "iso_wm.txt"
        r_wme = _run_iso_cli(
            "watermark-embed",
            "Isolated wheel watermark test",
            "--owner",
            "alice@corp.org",
            "--agent-id",
            "iso-agent",
            "--tier",
            "Internal",
            "--output",
            str(iso_wm_file),
        )
        assert r_wme.returncode == 0, r_wme.stderr

        r_wmi = _run_iso_cli("watermark-inspect", str(iso_wm_file))
        assert r_wmi.returncode == 0, r_wmi.stderr
        assert "Owner: alice@corp.org" in r_wmi.stdout
        assert "Agent ID: iso-agent" in r_wmi.stdout

        r_cm = _run_iso_cli("--check-mode")
        assert r_cm.returncode == 0, r_cm.stderr
        assert "Active Docket Mode:" in r_cm.stdout
    finally:
        httpd.shutdown()
        httpd.server_close()


# ==============================================================================
# TIER 2 — ITEM 7: Fix Gateway Upstream Response Corruption & Never Fabricate HTTP 200
# ==============================================================================
def test_tier2_item7_gateway_preserves_upstream_bytes_and_returns_502_504_on_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Prove multi-line upstream JSON is preserved byte-exact without Content-Length mismatch, and upstream errors return 502/504."""
    keyring = Keyring(key_dir=tmp_path / "keys")
    keyring.ensure_active_key(purpose="snapshot")
    store = InMemorySnapshotStore(keyring)
    store.load_from_envelope(
        sign_statement(build_snapshot_statement(entries={}, sequence_number=1, ttl_seconds=3600), keyring, purpose="snapshot")
    )
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="observe")

    app = create_prevalidator_app(
        enforcer=enforcer,
        upstream_gateway_url="http://upstream.enterprise.internal:4000",
        keys_dir=tmp_path / "keys",
    )

    pretty_json_bytes = (
        b"{\n"
        b'  "id": "chatcmpl-exact-bytes",\n'
        b'  "object": "chat.completion",\n'
        b'  "choices": [\n'
        b"    {\n"
        b'      "index": 0,\n'
        b'      "message": {\n'
        b'        "role": "assistant",\n'
        b'        "content": "Byte-exact response from upstream"\n'
        b"      }\n"
        b"    }\n"
        b"  ]\n"
        b"}\n"
    )

    class DummyClient:
        def __init__(self, mode: str = "ok"):
            self.mode = mode
            self.is_closed = False

        async def post(self, url: str, json: Any = None, headers: Any = None) -> httpx.Response:
            if self.mode == "timeout":
                raise httpx.ConnectTimeout("Upstream timed out")
            if self.mode == "connect_error":
                raise httpx.ConnectError("Connection refused by upstream")
            # Simulate an upstream response whose original Content-Length matches pretty_json_bytes
            return httpx.Response(
                status_code=200,
                content=pretty_json_bytes,
                headers={
                    "content-type": "application/json",
                    "content-length": str(len(pretty_json_bytes)),
                },
            )

    dummy = DummyClient("ok")
    import prevalidator.proxy as proxy_mod

    client = TestClient(app)

    # Monkeypatch httpx.AsyncClient.post on the shared client
    async def mock_post(self, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return await dummy.post(url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    # 1. Pretty-printed upstream JSON response is preserved byte-exact and Content-Length matches actual body
    r_ok = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
    )
    assert r_ok.status_code == 200
    assert r_ok.content == pretty_json_bytes
    assert int(r_ok.headers["content-length"]) == len(pretty_json_bytes)

    # 2. Upstream ConnectError returns HTTP 502 Bad Gateway (NEVER fabricated HTTP 200!)
    dummy.mode = "connect_error"
    r_502 = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
    )
    assert r_502.status_code == 502
    assert r_502.json()["error"]["code"] == "UPSTREAM_UNAVAILABLE"

    # 3. Upstream TimeoutException returns HTTP 504 Gateway Timeout (NEVER fabricated HTTP 200!)
    dummy.mode = "timeout"
    r_504 = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
    )
    assert r_504.status_code == 504
    assert r_504.json()["error"]["code"] == "UPSTREAM_TIMEOUT"


# ==============================================================================
# TIER 2 — ITEM 8: Persist Highest-Accepted Snapshot Version Across Restarts
# ==============================================================================
def test_tier2_item8_snapshot_rollback_protection_persisted_across_restarts(tmp_path: Path):
    """Prove replaying snapshot sequence N-1 after restart is rejected with SnapshotRollbackError / HTTP 409."""
    keys_dir = tmp_path / "keys"
    keyring = Keyring(key_dir=keys_dir)
    keyring.ensure_active_key(purpose="snapshot")
    state_file = tmp_path / "snapshot_hwm.json"

    stmt_9 = build_snapshot_statement(entries={}, sequence_number=9, ttl_seconds=3600)
    env_9 = sign_statement(stmt_9, keyring, purpose="snapshot")

    stmt_10 = build_snapshot_statement(entries={}, sequence_number=10, ttl_seconds=3600)
    env_10 = sign_statement(stmt_10, keyring, purpose="snapshot")

    # 1. Boot first instance and load sequence 10
    store_1 = InMemorySnapshotStore(keyring, state_path=state_file)
    pred_10 = store_1.load_from_envelope(env_10)
    assert pred_10["sequence_number"] == 10
    assert state_file.exists()

    # 2. Simulate process restart: new InMemorySnapshotStore instance reads persisted high-water mark (seq 10)
    store_2 = InMemorySnapshotStore(keyring, state_path=state_file)
    with pytest.raises(SnapshotRollbackError, match="SNAPSHOT_ROLLBACK_REJECTED"):
        store_2.load_from_envelope(env_9)

    # 3. Also verify HTTP 409 Conflict on /v1/admin/reload-snapshot
    enforcer = PrevalidatorEnforcer(snapshot_store=store_2, mode="enforce")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local", keys_dir=keys_dir)
    client = TestClient(app)
    r_reload = client.post(
        "/v1/admin/reload-snapshot",
        headers={"X-POD-Admin-Key": "pod-dev-admin-key"},
        json={"envelope": env_9},
    )
    assert r_reload.status_code == 409
    assert r_reload.json()["detail"]["error_code"] == "SNAPSHOT_ROLLBACK_REJECTED"


# ==============================================================================
# TIER 2 — ITEM 9: Align Python Version Floor & Dependency Pins
# ==============================================================================
def test_tier2_item9_pyproject_and_requirements_version_and_dependency_alignment():
    """Verify pyproject.toml and requirements.txt have Python 3.10-3.13 compatible pins and version 1.0.2."""
    repo_root = Path(__file__).resolve().parent.parent
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    req_text = (repo_root / "requirements.txt").read_text(encoding="utf-8")

    assert 'version = "1.0.2"' in pyproject_text
    assert 'requires-python = ">=3.10"' in pyproject_text
    assert "pycparser==3.12" not in req_text
    assert "pycparser>=2.21,<3.0" in req_text
    import docket
    assert docket.__version__ == "1.0.2"


# ==============================================================================
# TIER 2 — ITEM 10: Unify Helm Chart & Gateway Environment Variable Names
# ==============================================================================
def test_tier2_item10_helm_and_k8s_configmap_env_vars_match_gateway_settings():
    """Parse Helm and Kubernetes ConfigMaps and verify allPOD_*/DOCKET_* gateway env keys are canonical."""
    repo_root = Path(__file__).resolve().parent.parent
    deprecated_keys = {"POD_GATEWAY_MODE", "POD_SNAPSHOT_URL", "POD_ENGINE_URL", "POD_UPSTREAM_URL", "POD_ENFORCE_MODE"}

    configmaps = [
        repo_root / "charts" / "g1-docket" / "templates" / "configmap.yaml",
        repo_root / "deploy" / "helm" / "g1-docket" / "templates" / "configmap.yaml",
        repo_root / "deploy" / "k8s" / "configmap.yaml",
        repo_root / "k8s" / "configmap.yaml",
    ]
    for cm_path in configmaps:
        text = cm_path.read_text(encoding="utf-8")
        for dep in deprecated_keys:
            assert dep not in text, f"Deprecated env var '{dep}' still present in {cm_path}"
        for match in re.finditer(r"^\s*(POD_[A-Z0-9_]+):", text, re.MULTILINE):
            key = match.group(1)
            if key != "POD_PREVALIDATOR_PORT":
                assert key in CANONICAL_GATEWAY_ENV_VARS, f"Unrecognized gateway env var '{key}' in {cm_path}"


# ==============================================================================
# TIER 3 — ITEM 11: Enforce Key Purpose at Verification, Bind Decision Receipts & Guard Federation
# ==============================================================================
def test_tier3_item11_key_purpose_enforcement_decision_receipts_and_federation_verification(tmp_path: Path):
    """Prove key_purpose mismatch is rejected at verification, decision receipts bind request_sha256 + destination, and federation verifies signatures."""
    keyring = Keyring(key_dir=tmp_path / "keys")
    att_key = keyring.generate_key(key_purpose=["attestation"])
    snap_key = keyring.generate_key(key_purpose=["snapshot"])

    # 1. Sign a snapshot statement using the attestation-only key -> verify_dsse_envelope MUST reject with KEY_PURPOSE_MISMATCH
    snap_stmt = build_snapshot_statement(entries={}, sequence_number=1, ttl_seconds=3600)
    bad_snap_env = sign_statement(snap_stmt, keyring, keyid=att_key["keyid"], purpose="snapshot")
    with pytest.raises(SignatureVerificationError, match="KEY_PURPOSE_MISMATCH"):
        verify_dsse_envelope(bad_snap_env, keyring, expected_predicate_type=SNAPSHOT_PREDICATE_TYPE)

    # 2. Sign an attestation statement using the snapshot-only key -> verify_dsse_envelope MUST reject with KEY_PURPOSE_MISMATCH
    att_stmt = build_attestation_statement(
        locator="file://test/doc.txt",
        content_sha256="a" * 64,
        tier="Public",
        owner="sec@enterprise.org",
    )
    bad_att_env = sign_statement(att_stmt, keyring, keyid=snap_key["keyid"], purpose="attestation")
    with pytest.raises(SignatureVerificationError, match="KEY_PURPOSE_MISMATCH"):
        verify_dsse_envelope(bad_att_env, keyring, expected_predicate_type=ATTESTATION_PREDICATE_TYPE)

    # 3. Proper purpose keys verify cleanly
    good_snap_env = sign_statement(snap_stmt, keyring, keyid=snap_key["keyid"], purpose="snapshot")
    assert verify_dsse_envelope(good_snap_env, keyring, expected_predicate_type=SNAPSHOT_PREDICATE_TYPE).verified is True

    # 4. Decision receipt binds request_sha256 and destination
    store = InMemorySnapshotStore(keyring)
    store.load_from_envelope(good_snap_env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="observe")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local", keys_dir=tmp_path / "keys")
    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Receipt test"}]},
    )
    assert resp.status_code == 200
    assert resp.headers.get("X-POD-Request-Sha256")
    assert resp.headers.get("X-POD-Destination") == "mock://local/v1/chat/completions"
    receipt_b64 = resp.headers.get("X-POD-Attestation-Receipt")
    assert receipt_b64
    receipt_obj = json.loads(base64.urlsafe_b64decode(receipt_b64.encode("ascii")).decode("utf-8"))
    assert receipt_obj["request_sha256"] == resp.headers["X-POD-Request-Sha256"]
    assert receipt_obj["destination"] == "mock://local/v1/chat/completions"

    # 5. Federation helper: RegionalPrevalidatorNode rejects unsigned or tampered snapshots
    hub = CentralGovernanceHub(primary_region="us-east-1", keyring=keyring)
    node = RegionalPrevalidatorNode(region_id="eu-west-1", keyring=keyring)
    hub.register_region("eu-west-1", node)

    signed_snap = hub.set_active_entries({})
    assert node.current_sequence == signed_snap["sequence_number"]

    # Unsigned snapshot with higher sequence number MUST be rejected
    unsigned_snap = {
        "snapshot_id": "forged-unsigned",
        "sequence_number": signed_snap["sequence_number"] + 10,
        "entries": {},
    }
    assert node.receive_snapshot(unsigned_snap) is False

    # Tampered signed snapshot MUST be rejected
    tampered_snap = dict(signed_snap)
    tampered_snap["sequence_number"] = signed_snap["sequence_number"] + 1
    assert node.receive_snapshot(tampered_snap, signature=signed_snap["signature"]) is False


# ==============================================================================
# TIER 3 — ITEM 12: Per-Provider Outbound Header Allowlists
# ==============================================================================
def test_tier3_item12_per_provider_outbound_header_allowlists(tmp_path: Path):
    """Prove Cookie, client Authorization, X-POD-Admin-Key, and X-POD-Caller-Key are stripped before upstream forwarding."""
    keyring = Keyring(key_dir=tmp_path / "keys")
    keyring.ensure_active_key()
    store = InMemorySnapshotStore(keyring)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="observe")
    outcome = enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
    )

    incoming = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Request-Id": "req-123",
        "Cookie": "docket_session=super-secret-cookie",
        "Authorization": "Bearer client-internal-jwt",
        "X-POD-Admin-Key": "pod-dev-admin-key",
        "X-POD-Caller-Key": "pod-key-restricted",
        "X-POD-Caller-Token": "internal-caller-jwt",
        "X-Forwarded-Email": "ceo@enterprise.org",
        "OpenAI-Organization": "org-enterprise",
    }
    out_openai = build_outbound_provider_headers(
        provider="openai",
        incoming_headers=incoming,
        outcome=outcome,
        llm_config={"api_key": "sk-upstream-provider-key"},
    )
    lower_keys = {k.lower(): v for k, v in out_openai.items()}
    assert "cookie" not in lower_keys
    assert "x-pod-admin-key" not in lower_keys
    assert "x-pod-caller-key" not in lower_keys
    assert "x-pod-caller-token" not in lower_keys
    assert "x-forwarded-email" not in lower_keys
    assert lower_keys["authorization"] == "Bearer sk-upstream-provider-key"
    assert lower_keys["openai-organization"] == "org-enterprise"
    assert lower_keys["x-request-id"] == "req-123"


# ==============================================================================
# TIER 3 — ITEM 13: Separate Approval State from Downstream Replay/Delivery State
# ==============================================================================
def test_tier3_item13_separate_approval_and_replay_delivery_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Prove approval records APPROVED -> DISPATCHED -> DISPATCH_REJECTED (on 500) vs DELIVERED (on 200)."""
    worm = WORMAuditLedger(db_path=str(tmp_path / "worm13.db"), jsonl_path=str(tmp_path / "worm13.jsonl"))
    qstore = QuarantineStore(db_path=str(tmp_path / "q13.db"))
    keyring = Keyring(key_dir=tmp_path / "keys13")
    keyring.ensure_active_key()
    dk = DualKeyGovernanceManager(quarantine_store=qstore, worm_ledger=worm, keyring=keyring)

    # Case A: Downstream gateway returns HTTP 500 -> item is APPROVED visually in history, but final status is DISPATCH_REJECTED
    qid_a = qstore.stage_quarantine(
        event_type="DOCKET_DENIAL",
        reason_code="DLP_HOLD",
        payload_digest="1" * 64,
        raw_payload={"messages": [{"role": "user", "content": "Test A"}]},
        locator_uri="file://a.txt",
        claimed_tier="Internal",
        triggered_rules=["RULE_A"],
    )
    dk.stage_override(qid_a, "operator1", "Business justification A valid.")
    monkeypatch.setattr(
        dk,
        "replay_to_pipeline",
        lambda payload, ticket: {"replayed": False, "status_code": 500, "error": "Upstream internal server error"},
    )
    res_a = dk.approve_and_release(qid_a, "approver1", perform_replay=True)
    assert res_a["approval_state"] == "APPROVED"
    assert res_a["replay_status"] == "DISPATCH_REJECTED"
    assert res_a["status"] == "DISPATCH_REJECTED"
    assert res_a["lifecycle_history"] == ["APPROVED", "DISPATCHED", "DISPATCH_REJECTED"]

    # Case B: Downstream gateway returns HTTP 200 -> APPROVED -> DISPATCHED -> UPSTREAM_ACCEPTED -> DELIVERED
    qid_b = qstore.stage_quarantine(
        event_type="DOCKET_DENIAL",
        reason_code="DLP_HOLD",
        payload_digest="2" * 64,
        raw_payload={"messages": [{"role": "user", "content": "Test B"}]},
        locator_uri="file://b.txt",
        claimed_tier="Internal",
        triggered_rules=["RULE_B"],
    )
    dk.stage_override(qid_b, "operator1", "Business justification B valid.")
    monkeypatch.setattr(
        dk,
        "replay_to_pipeline",
        lambda payload, ticket: {"replayed": True, "status_code": 200, "gateway_response": {"ok": True}},
    )
    res_b = dk.approve_and_release(qid_b, "approver1", perform_replay=True)
    assert res_b["approval_state"] == "APPROVED"
    assert res_b["replay_status"] in ("UPSTREAM_ACCEPTED", "DELIVERED")
    assert res_b["status"] == "DELIVERED"
    assert res_b["lifecycle_history"] == ["APPROVED", "DISPATCHED", "UPSTREAM_ACCEPTED", "DELIVERED"]


# ==============================================================================
# TIER 3 — ITEM 14: Empirical-Only Compliance & Benchmark Reporting
# ==============================================================================
def test_tier3_item14_empirical_only_compliance_and_benchmark_reporting(tmp_path: Path):
    """Prove unexecuted compliance controls report UNVERIFIED (not PASS) and 0 denial samples report None/N/A (not 0.0 ms)."""
    from benchmarks.benchmark_gateway_concurrency import summarize_decision_latencies
    from scripts.run_govready_assessment import build_govready_summary

    # 1. GovReady summary with no executed controls -> status is UNVERIFIED, passed == 0
    summary_unverified = build_govready_summary(executed_control_results={})
    assert summary_unverified["status"] == "UNVERIFIED"
    assert summary_unverified["passed"] == 0
    assert summary_unverified["unverified"] == 12

    # 2. Enforcer telemetry and benchmark summary with 0 denial samples -> denial_p99_ms is None (never 0.0)
    keyring = Keyring(key_dir=tmp_path / "keys14")
    keyring.ensure_active_key(purpose="snapshot")
    store = InMemorySnapshotStore(keyring)
    store.load_from_envelope(
        sign_statement(build_snapshot_statement(entries={}, sequence_number=1, ttl_seconds=3600), keyring, purpose="snapshot")
    )
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="observe")
    enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "Allowed request"}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
    )
    telemetry = enforcer.get_latency_telemetry()
    assert telemetry["allow_sample_count"] == 1
    assert telemetry["allow_p99_ms"] is not None and telemetry["allow_p99_ms"] > 0.0
    assert telemetry["denial_sample_count"] == 0
    assert telemetry["denial_p99_ms"] is None

    bench_summary = summarize_decision_latencies(allow_samples_ms=[0.12, 0.18], denial_samples_ms=[])
    assert bench_summary["denial_sample_count"] == 0
    assert bench_summary["denial_p99_ms"] is None
    assert bench_summary["denial_p99_display"] == "N/A (0 samples)"
    assert bench_summary["benchmark_gate_passed"] is False


# ==============================================================================
# TIER 3 — ITEM 15: Fix Azure Terraform Container Immutability Policy Schema Validation
# ==============================================================================
def test_tier3_item15_azure_terraform_immutability_policy_schema():
    """Verify terraform/azure/main.tf uses valid azurerm_storage_container_immutability_policy attributes."""
    repo_root = Path(__file__).resolve().parent.parent
    tf_main = (repo_root / "terraform" / "azure" / "main.tf").read_text(encoding="utf-8")
    tf_vars = (repo_root / "terraform" / "azure" / "variables.tf").read_text(encoding="utf-8")

    assert "protected_append_blobs_enabled" not in tf_main
    assert "state                                 =" not in tf_main
    assert "protected_append_writes_enabled       = true" in tf_main
    assert "locked                                = var.immutability_policy_locked" in tf_main
    assert 'variable "immutability_policy_locked"' in tf_vars
