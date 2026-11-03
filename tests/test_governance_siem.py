"""
Unit and Integration Tests for Multi-Target SIEM Forwarder.
Verifies data sanitization (zero leakage), persistent buffering,
and delivery across Splunk HEC, Elastic ECS, Syslog CEF, Datadog, Sentinel, CloudWatch, and Webhooks.
"""

import json
import time
from pathlib import Path

import pytest

from governance.mock_sinks import MockHTTPSink, MockSyslogSink
from governance.siem_forwarder import (
    SIEMDestinationConfig,
    SIEMForwarder,
    format_cef_event,
    format_elastic_ecs,
    format_splunk_hec,
    sanitize_for_siem,
)


@pytest.fixture
def mock_http():
    sink = MockHTTPSink(host="127.0.0.1", port=0)
    sink.start()
    yield sink
    sink.stop()


@pytest.fixture
def mock_syslog():
    sink = MockSyslogSink(host="127.0.0.1", port=0)
    sink.start()
    yield sink
    sink.stop()


def test_zero_sensitive_data_leakage_sanitization():
    raw_event = {
        "entry_id": "TEST-1001",
        "event_type": "DOCKET_DENIAL",
        "actor_identity": "employee@corp.com",
        "payload_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "metadata": {
            "reason_code": "UNATTESTED_DATA_OBJECT",
            "clearance_tier": "Confidential",
            "locator_uri": "s3://internal/q4_forecast.xlsx",
            "raw_content": "TOP SECRET FINANCIALS: Profit=$50M, SSN: 000-12-3456",
            "prompt": "Analyze this confidential salary sheet...",
            "body": "Unredacted credit card 4111-2222-3333-4444",
        },
    }

    sanitized = sanitize_for_siem(raw_event)

    # Core metadata preserved
    assert sanitized["event_id"] == "TEST-1001"
    assert sanitized["payload_digest"] == raw_event["payload_digest"]
    assert sanitized["metadata"]["reason_code"] == "UNATTESTED_DATA_OBJECT"
    assert sanitized["metadata"]["clearance_tier"] == "Confidential"

    # Sensitive bodies MUST BE STRIPPED
    assert "raw_content" not in sanitized["metadata"]
    assert "prompt" not in sanitized["metadata"]
    assert "body" not in sanitized["metadata"]


def test_cef_syslog_formatting_and_delivery(tmp_path, mock_syslog):
    buf_db = tmp_path / "siem_buffer.db"
    dest = SIEMDestinationConfig(
        id="syslog_test",
        name="Test CEF Syslog",
        type="syslog",
        enabled=True,
        syslog_host=mock_syslog.host,
        syslog_port=mock_syslog.port,
    )
    forwarder = SIEMForwarder(buffer_db_path=buf_db, destinations=[dest])

    event = {
        "entry_id": "WORM-0001",
        "event_type": "DOCKET_DENIAL",
        "actor_identity": "user:unauthorized",
        "payload_digest": "abcdef123456" * 5 + "abcd",
        "metadata": {"reason_code": "UNATTESTED_DATA_OBJECT", "clearance_tier": "Internal"},
    }

    forwarder.enqueue_event(event)
    processed = forwarder.flush_pending()
    assert processed == 1

    time.sleep(0.1)
    lines = mock_syslog.get_lines()
    assert len(lines) == 1
    cef = lines[0]
    assert cef.startswith("CEF:0|G1|DocketCombine|4.0.0|DOCKET_DENIAL|")
    assert "act=DOCKET_DENIAL" in cef
    assert "src=user:unauthorized" in cef
    assert "cs2=UNATTESTED_DATA_OBJECT" in cef


def test_splunk_hec_and_elastic_ecs_delivery(tmp_path, mock_http):
    buf_db = tmp_path / "siem_buffer.db"

    splunk_dest = SIEMDestinationConfig(
        id="splunk_test",
        name="Test Splunk HEC",
        type="splunk",
        enabled=True,
        endpoint_url=f"{mock_http.url}/services/collector/event",
        api_key="mock-splunk-token",
    )
    elastic_dest = SIEMDestinationConfig(
        id="elastic_test",
        name="Test Elastic ECS",
        type="elastic",
        enabled=True,
        endpoint_url=f"{mock_http.url}/g1-security-events/_doc",
        api_key="mock-elastic-key",
    )
    datadog_dest = SIEMDestinationConfig(
        id="datadog_test",
        name="Test Datadog Logs",
        type="datadog",
        enabled=True,
        endpoint_url=f"{mock_http.url}/api/v2/logs",
        api_key="mock-dd-key",
    )

    forwarder = SIEMForwarder(
        buffer_db_path=buf_db,
        destinations=[splunk_dest, elastic_dest, datadog_dest],
    )

    event = {
        "entry_id": "WORM-0042",
        "event_type": "COMBINE_THREAT_BLOCKED",
        "actor_identity": "attacker:red-team",
        "payload_digest": "99" * 32,
        "metadata": {"reason_code": "INJ-34", "clearance_tier": "Restricted"},
    }

    forwarder.enqueue_event(event)
    processed = forwarder.flush_pending()
    assert processed == 3  # All 3 HTTP targets received event

    captured = mock_http.get_events()
    assert len(captured) == 3

    # Check Splunk HEC payload
    splunk_calls = [c for c in captured if "/services/collector" in c["path"]]
    assert len(splunk_calls) == 1
    assert "Splunk mock-splunk-token" in splunk_calls[0]["headers"].get("authorization", "")
    assert splunk_calls[0]["payload"]["sourcetype"] == "g1:security:event"
    assert splunk_calls[0]["payload"]["event"]["event_type"] == "COMBINE_THREAT_BLOCKED"

    # Check Elastic ECS payload
    elastic_calls = [c for c in captured if "/g1-security-events" in c["path"]]
    assert len(elastic_calls) == 1
    assert elastic_calls[0]["payload"]["event"]["kind"] == "alert"
    assert elastic_calls[0]["payload"]["rule"]["id"] == "INJ-34"

    # Check Datadog payload
    datadog_calls = [c for c in captured if "/api/v2/logs" in c["path"]]
    assert len(datadog_calls) == 1
    assert datadog_calls[0]["headers"].get("dd-api-key") == "mock-dd-key"
    assert datadog_calls[0]["payload"]["service"] == "g1-security-stack"


def test_sentinel_cloudwatch_and_webhook_delivery(tmp_path, mock_http):
    buf_db = tmp_path / "siem_buffer.db"

    sentinel_dest = SIEMDestinationConfig(
        id="sentinel_test",
        name="Test Microsoft Sentinel",
        type="sentinel",
        enabled=True,
        endpoint_url=f"{mock_http.url}/api/logs",
        api_key="mock-sentinel-key",
    )
    cloudwatch_dest = SIEMDestinationConfig(
        id="cloudwatch_test",
        name="Test CloudWatch Logs",
        type="cloudwatch",
        enabled=True,
        endpoint_url=f"{mock_http.url}/cloudwatch/logs",
        log_group_name="/g1/docket/security",
    )
    webhook_dest = SIEMDestinationConfig(
        id="webhook_test",
        name="Test Webhook",
        type="webhook",
        enabled=True,
        endpoint_url=f"{mock_http.url}/v1/logs",
        auth_header="Bearer mock-webhook-token",
    )

    forwarder = SIEMForwarder(
        buffer_db_path=buf_db,
        destinations=[sentinel_dest, cloudwatch_dest, webhook_dest],
    )

    event = {
        "entry_id": "WORM-0099",
        "event_type": "HITL_DUAL_KEY_RELEASE",
        "actor_identity": "alice+bob",
        "payload_digest": "44" * 32,
        "metadata": {"quarantine_id": "Q-1234", "clearance_tier": "Confidential"},
    }

    forwarder.enqueue_event(event)
    processed = forwarder.flush_pending()
    assert processed == 3

    captured = mock_http.get_events()
    assert len(captured) == 3

    # Check Sentinel custom table payload
    sentinel_calls = [c for c in captured if "/api/logs" in c["path"]]
    assert len(sentinel_calls) == 1
    assert sentinel_calls[0]["payload"][0]["EventType_s"] == "HITL_DUAL_KEY_RELEASE"
    assert sentinel_calls[0]["payload"][0]["Actor_s"] == "alice+bob"

    # Check CloudWatch logEvents payload
    cw_calls = [c for c in captured if "/cloudwatch/logs" in c["path"]]
    assert len(cw_calls) == 1
    assert cw_calls[0]["payload"]["logGroupName"] == "/g1/docket/security"
    assert len(cw_calls[0]["payload"]["logEvents"]) == 1

    # Check Webhook payload
    wh_calls = [c for c in captured if "/v1/logs" in c["path"]]
    assert len(wh_calls) == 1
    assert wh_calls[0]["headers"].get("authorization") == "Bearer mock-webhook-token"



def test_persistent_buffer_retry_on_endpoint_failure(tmp_path):
    buf_db = tmp_path / "siem_buffer.db"
    # Target pointing to an unreachable port
    offline_dest = SIEMDestinationConfig(
        id="offline_test",
        name="Offline Endpoint",
        type="webhook",
        enabled=True,
        endpoint_url="http://127.0.0.1:49999/failed-webhook",
        timeout_seconds=0.5,
    )
    forwarder = SIEMForwarder(buffer_db_path=buf_db, destinations=[offline_dest])

    event = {
        "entry_id": "WORM-9999",
        "event_type": "DOCKET_DENIAL",
        "actor_identity": "actor:test",
        "payload_digest": "11" * 32,
    }

    forwarder.enqueue_event(event)
    depths_before = forwarder.get_queue_depth()
    assert depths_before["offline_test"] == 1

    # Attempt flush -> should fail and remain PENDING with backoff
    processed = forwarder.flush_pending()
    assert processed == 0

    depths_after = forwarder.get_queue_depth()
    assert depths_after["offline_test"] == 1  # Event persisted in SQLite buffer!

    st = forwarder.get_destination_status()[0]
    assert st["failed_count"] == 1
    assert st["consecutive_failures"] == 1
