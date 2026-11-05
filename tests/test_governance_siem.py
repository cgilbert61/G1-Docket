#!/usr/bin/env python3
"""Unit tests for G1 Docket Enterprise SIEM & SOC Event Exporter."""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.export_siem_events import (
    to_ocsf_event,
    to_cef_event,
    to_datadog_event,
    SEVERITY_MAP,
)

SAMPLE_DENIAL_RECORD = {
    "timestamp": "2026-11-04T18:05:12.384Z",
    "event_id": "evt_9a4f210d-83b1-4c92-bf44-6014e2d31f08",
    "caller_key": "svc-copilot-agent-prod",
    "caller_clearance": "INTERNAL",
    "target_route": "public_cloud_llm",
    "decision": "DENIED",
    "mode": "enforce",
    "reason_codes": ["CLEARANCE_VIOLATION"],
    "locators": ["s3://corp-lakehouse-prod/hr/executive_compensation_2026.parquet"],
    "classified_tier": "RESTRICTED",
    "observed_sha256": "8f3b4c910e5218d69348d6174a72d3e911223344556677889900aabbccddeeff",
    "latency_us": 142.6,
    "worm_block_id": 18490,
    "envelope_id": "env_77a901c",
}

SAMPLE_ALLOW_RECORD = {
    "timestamp": "2026-11-04T18:05:15.112Z",
    "event_id": "evt_bb4f210d-83b1-4c92-bf44-6014e2d31f09",
    "caller_key": "svc-search-bot",
    "caller_clearance": "PUBLIC",
    "target_route": "local_inference_model",
    "decision": "ALLOWED",
    "mode": "enforce",
    "reason_codes": ["ALLOWED"],
    "locators": ["s3://corp-lakehouse-prod/marketing/press_release_2026.pdf"],
    "classified_tier": "PUBLIC",
    "observed_sha256": "3a1c5d7e9b2f48a0123456789abcdef0123456789abcdef0123456789abcdef0",
    "latency_us": 88.4,
    "worm_block_id": 18491,
    "envelope_id": "env_88b102d",
}


def test_ocsf_denial_event_schema():
    """Verify OCSF event fields, schema compliance, and cryptographic pointers for DENIED request."""
    ocsf = to_ocsf_event(SAMPLE_DENIAL_RECORD)

    assert ocsf["metadata"]["version"] == "1.1.0"
    assert ocsf["metadata"]["product"]["name"] == "G1 Docket Prevalidator"
    assert ocsf["class_uid"] == 4001
    assert ocsf["severity_id"] == 4  # High
    assert ocsf["severity"] == "High"
    assert ocsf["status"] == "Failure"
    assert ocsf["disposition"] == "Block"
    assert ocsf["action"] == "Blocked"
    assert ocsf["actor"]["user"]["name"] == "svc-copilot-agent-prod"
    assert ocsf["target_endpoint"]["service_name"] == "public_cloud_llm"
    assert ocsf["resources"][0]["name"] == "s3://corp-lakehouse-prod/hr/executive_compensation_2026.parquet"
    assert ocsf["resources"][0]["data_tier"] == "RESTRICTED"
    assert ocsf["resources"][0]["hashes"][0]["value"] == "8f3b4c910e5218d69348d6174a72d3e911223344556677889900aabbccddeeff"
    assert ocsf["violation"]["primary_code"] == "CLEARANCE_VIOLATION"
    assert ocsf["cryptographic_proof"]["worm_block_pointer"] == 18490
    assert ocsf["cryptographic_proof"]["dsse_envelope_id"] == "env_77a901c"


def test_ocsf_allow_event_schema():
    """Verify OCSF event fields for ALLOWED request."""
    ocsf = to_ocsf_event(SAMPLE_ALLOW_RECORD)

    assert ocsf["severity_id"] == 1  # Informational
    assert ocsf["severity"] == "Informational"
    assert ocsf["status"] == "Success"
    assert ocsf["disposition"] == "Allow"
    assert ocsf["action"] == "Allowed"
    assert ocsf["violation"]["primary_code"] == "ALLOWED"


def test_cef_event_format():
    """Verify Common Event Format (CEF) string serialization."""
    cef = to_cef_event(SAMPLE_DENIAL_RECORD)

    assert cef.startswith("CEF:0|G1Docket|Prevalidator|1.0.0|CLEARANCE_VIOLATION|")
    assert "src=svc-copilot-agent-prod" in cef
    assert "dst=public_cloud_llm" in cef
    assert "act=drop" in cef
    assert "cs1=enforce" in cef
    assert "cs2=s3://corp-lakehouse-prod/hr/executive_compensation_2026.parquet" in cef
    assert "cs3=DENIED" in cef
    assert "cn1=142" in cef


def test_datadog_event_format():
    """Verify Datadog Security Monitoring JSON payload."""
    dd = to_datadog_event(SAMPLE_DENIAL_RECORD)

    assert dd["ddsource"] == "g1-docket"
    assert dd["service"] == "prevalidator"
    assert dd["status"] == "ERROR"
    assert "CLEARANCE_VIOLATION" in dd["message"]
    assert "env:production" in dd["tags"]
    assert "mode:enforce" in dd["tags"]
    assert dd["attributes"]["class_uid"] == 4001


def test_cli_exporter_runs(tmp_path: Path):
    """Test CLI execution of export_siem_events.py."""
    out_file = tmp_path / "siem_export.json"
    repo_root = Path(__file__).resolve().parent.parent

    res = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "export_siem_events.py"),
            "--format", "all",
            "--limit", "5",
            "--output", str(out_file),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert len(content.strip().splitlines()) >= 1
    # Check that each line is valid JSON with ocsf and cef keys
    first_line = json.loads(content.strip().splitlines()[0])
    assert "ocsf" in first_line
    assert "cef" in first_line
    assert "datadog" in first_line
