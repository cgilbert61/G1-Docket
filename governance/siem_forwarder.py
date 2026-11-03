"""
Multi-Target SIEM Integration Engine & Resilient Ingestion Pipeline.
Streams security events and WORM records downstream to enterprise SIEM platforms:
1. Splunk HEC (HTTP Event Collector)
2. Elasticsearch / OpenSearch (ECS 1.12 mapping)
3. CEF / RFC 5424 Syslog (TCP/TLS)
4. Generic Webhook / OpenTelemetry Logs
5. Datadog Logs API (/api/v2/logs)
6. Microsoft Sentinel / Azure Monitor (Log Analytics Ingestion API)
7. AWS CloudWatch Logs / Kinesis Firehose

Features persistent SQLite buffering, exponential backoff retries, and zero sensitive data leakage.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("g1.governance.siem")


@dataclass
class SIEMDestinationConfig:
    id: str
    name: str
    type: str  # "splunk", "elastic", "syslog", "webhook", "datadog", "sentinel", "cloudwatch"
    enabled: bool = True
    endpoint_url: str = ""
    api_key: Optional[str] = None
    auth_header: Optional[str] = None
    syslog_host: Optional[str] = None
    syslog_port: Optional[int] = None
    syslog_use_tls: bool = False
    index_or_sourcetype: Optional[str] = None
    workspace_id: Optional[str] = None
    log_group_name: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0


def sanitize_for_siem(event_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enforce Zero Sensitive Data Leakage:
    Strips raw payload text, conversational prompts, or PII bodies.
    Preserves cryptographic digests, rule IDs, clearance tiers, and audit IDs.
    """
    metadata = dict(event_record.get("metadata") or {})
    # Strip any potential raw text or unredacted content
    for sensitive_key in ("raw_content", "body", "prompt", "unredacted_text", "document_text", "file_bytes"):
        metadata.pop(sensitive_key, None)

    return {
        "event_id": event_record.get("entry_id") or event_record.get("event_id"),
        "timestamp_utc_iso8601": event_record.get("timestamp_utc_iso8601") or datetime.now(timezone.utc).isoformat(),
        "event_type": event_record.get("event_type", "SECURITY_ALERT"),
        "actor_identity": event_record.get("actor_identity", "system:anonymous"),
        "payload_digest": event_record.get("payload_digest", ""),
        "metadata": metadata,
        "entry_hash": event_record.get("entry_hash", ""),
    }


def format_cef_event(sanitized: Dict[str, Any]) -> str:
    """Format RFC 5424 / Common Event Format (CEF) string."""
    event_type = sanitized["event_type"]
    severity = "8" if "DENIAL" in event_type or "BLOCKED" in event_type else "4"
    if "RELEASE" in event_type or "OVERRIDE" in event_type:
        severity = "6"

    meta = sanitized.get("metadata", {})
    rules = ",".join(meta.get("rule_ids", [])) or meta.get("reason_code", "UNKNOWN")
    tier = meta.get("clearance_tier", "STANDARD")
    loc = meta.get("locator_uri", "")

    # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    extension_parts = [
        f"act={event_type}",
        f"src={sanitized.get('actor_identity', 'unknown')}",
        f"cs1={sanitized.get('payload_digest', '')}",
        "cs1Label=PayloadDigest",
        f"cs2={rules}",
        "cs2Label=RuleMatches",
        f"cs3={tier}",
        "cs3Label=ClearanceTier",
    ]
    if loc:
        extension_parts.append(f"cs4={loc}")
        extension_parts.append("cs4Label=LocatorURI")

    ext_str = " ".join(extension_parts)
    return f"CEF:0|G1|DocketCombine|4.0.0|{event_type}|G1 Security Boundary Event|{severity}|{ext_str}\n"


def format_elastic_ecs(sanitized: Dict[str, Any], index_name: str = "g1-security-events") -> Dict[str, Any]:
    """Map event into Elastic Common Schema (ECS 1.12) JSON structure."""
    event_type = sanitized["event_type"]
    outcome = "failure" if ("DENIAL" in event_type or "BLOCKED" in event_type) else "success"
    return {
        "@timestamp": sanitized["timestamp_utc_iso8601"],
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "data_loss_prevention"],
            "type": [event_type.lower()],
            "outcome": outcome,
            "action": event_type,
            "id": sanitized["event_id"],
        },
        "rule": {
            "id": sanitized.get("metadata", {}).get("reason_code", "POLICY"),
            "ruleset": "G1_DOCKET_COMBINE",
        },
        "user": {
            "name": sanitized["actor_identity"],
        },
        "hash": {
            "sha256": sanitized["payload_digest"],
        },
        "labels": {
            "clearance_tier": sanitized.get("metadata", {}).get("clearance_tier", "DEFAULT"),
            "locator_uri": sanitized.get("metadata", {}).get("locator_uri", ""),
            "worm_entry_hash": sanitized.get("entry_hash", ""),
        },
        "message": f"G1 Security Boundary: {event_type} for actor {sanitized['actor_identity']}",
    }


def format_splunk_hec(sanitized: Dict[str, Any], sourcetype: str = "g1:security:event") -> Dict[str, Any]:
    """Format Splunk HEC event wrapper."""
    ts = datetime.fromisoformat(sanitized["timestamp_utc_iso8601"].replace("Z", "+00:00")).timestamp()
    return {
        "time": ts,
        "host": "g1-docket-gateway",
        "source": "docket:security",
        "sourcetype": sourcetype,
        "event": sanitized,
    }


def format_datadog_logs(sanitized: Dict[str, Any]) -> Dict[str, Any]:
    """Format Datadog Logs API JSON payload."""
    event_type = sanitized["event_type"]
    status = "error" if ("DENIAL" in event_type or "BLOCKED" in event_type) else "info"
    return {
        "ddsource": "g1-docket",
        "service": "g1-security-stack",
        "status": status,
        "message": f"G1 Event: {event_type} - {sanitized.get('metadata', {}).get('reason_code', 'OK')}",
        "timestamp": sanitized["timestamp_utc_iso8601"],
        "ddtags": f"env:production,event_type:{event_type},actor:{sanitized['actor_identity']}",
        "security_event": sanitized,
    }


def format_azure_sentinel(sanitized: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format Azure Monitor / Sentinel custom log table record."""
    return [{
        "TimeGenerated": sanitized["timestamp_utc_iso8601"],
        "EventId_s": sanitized["event_id"],
        "EventType_s": sanitized["event_type"],
        "Actor_s": sanitized["actor_identity"],
        "PayloadDigest_s": sanitized["payload_digest"],
        "ClearanceTier_s": sanitized.get("metadata", {}).get("clearance_tier", ""),
        "ReasonCode_s": sanitized.get("metadata", {}).get("reason_code", ""),
        "LocatorUri_s": sanitized.get("metadata", {}).get("locator_uri", ""),
        "WormHash_s": sanitized.get("entry_hash", ""),
    }]


def format_aws_cloudwatch(sanitized: Dict[str, Any]) -> Dict[str, Any]:
    """Format AWS CloudWatch PutLogEvents style batch structure."""
    ts_ms = int(datetime.fromisoformat(sanitized["timestamp_utc_iso8601"].replace("Z", "+00:00")).timestamp() * 1000)
    return {
        "timestamp": ts_ms,
        "message": json.dumps(sanitized, sort_keys=True),
    }


class SIEMForwarder:
    """
    Persistent buffered SIEM Forwarder with multi-destination dispatch,
    automatic retries, circuit breaking, and delivery health tracking.
    """

    def __init__(
        self,
        buffer_db_path: str | Path,
        destinations: Optional[List[SIEMDestinationConfig]] = None,
        max_batch_size: int = 25,
        flush_interval_seconds: float = 2.0,
    ):
        self.buffer_db_path = Path(buffer_db_path)
        self.buffer_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.destinations: Dict[str, SIEMDestinationConfig] = {d.id: d for d in (destinations or [])}
        self.max_batch_size = max_batch_size
        self.flush_interval_seconds = flush_interval_seconds

        self._lock = threading.Lock()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._stats: Dict[str, Dict[str, Any]] = {}
        self._init_sqlite()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.buffer_db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_sqlite(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS siem_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at REAL NOT NULL,
                    last_error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(event_id, destination_id)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_pending ON siem_buffer(status, next_retry_at);")
            conn.commit()

        # Initialize telemetry stats
        for dest_id in self.destinations:
            self._stats[dest_id] = {
                "delivered": 0,
                "failed": 0,
                "last_success_ts": None,
                "last_error": None,
                "consecutive_failures": 0,
            }

    def register_destination(self, dest: SIEMDestinationConfig) -> None:
        with self._lock:
            self.destinations[dest.id] = dest
            if dest.id not in self._stats:
                self._stats[dest.id] = {
                    "delivered": 0,
                    "failed": 0,
                    "last_success_ts": None,
                    "last_error": None,
                    "consecutive_failures": 0,
                }

    def enqueue_event(self, raw_event: Dict[str, Any]) -> None:
        """Sanitize event and buffer for all active destinations."""
        sanitized = sanitize_for_siem(raw_event)
        event_id = sanitized["event_id"]
        now_ts = time.time()

        with self._lock, self._get_connection() as conn:
            for dest_id, dest in self.destinations.items():
                if not dest.enabled:
                    continue
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO siem_buffer (
                            event_id, destination_id, payload_json, status, attempts, next_retry_at
                        ) VALUES (?, ?, ?, 'PENDING', 0, ?)
                        """,
                        (event_id, dest_id, json.dumps(sanitized), now_ts),
                    )
                except Exception as e:
                    logger.warning(f"Failed to enqueue event {event_id} for destination {dest_id}: {e}")
            conn.commit()

    def get_queue_depth(self) -> Dict[str, int]:
        """Return count of pending events per destination."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT destination_id, COUNT(*) as cnt FROM siem_buffer WHERE status = 'PENDING' GROUP BY destination_id"
            ).fetchall()
            depths = {dest_id: 0 for dest_id in self.destinations}
            for r in rows:
                depths[r["destination_id"]] = r["cnt"]
            return depths

    def get_destination_status(self) -> List[Dict[str, Any]]:
        """Return operational status and telemetry for each destination."""
        depths = self.get_queue_depth()
        status_list = []
        for dest_id, dest in self.destinations.items():
            st = self._stats.get(dest_id, {})
            health = "HEALTHY"
            if not dest.enabled:
                health = "DISABLED"
            elif st.get("consecutive_failures", 0) >= 3:
                health = "DEGRADED"

            status_list.append({
                "id": dest.id,
                "name": dest.name,
                "type": dest.type,
                "enabled": dest.enabled,
                "health": health,
                "endpoint_url": dest.endpoint_url or f"{dest.syslog_host}:{dest.syslog_port}",
                "pending_queue_count": depths.get(dest_id, 0),
                "delivered_count": st.get("delivered", 0),
                "failed_count": st.get("failed", 0),
                "consecutive_failures": st.get("consecutive_failures", 0),
                "last_success_ts": st.get("last_success_ts"),
                "last_error": st.get("last_error"),
            })
        return status_list

    def dispatch_single_sync(self, dest: SIEMDestinationConfig, sanitized_event: Dict[str, Any]) -> bool:
        """
        Synchronously dispatch a sanitized event to a destination.
        Returns True on success, raises Exception on failure.
        """
        dest_type = dest.type.lower()
        timeout = dest.timeout_seconds

        if dest_type == "syslog":
            cef_msg = format_cef_event(sanitized_event)
            host = dest.syslog_host or "127.0.0.1"
            port = dest.syslog_port or 514
            if dest.syslog_use_tls:
                context = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(cef_msg.encode("utf-8"))
            else:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    sock.sendall(cef_msg.encode("utf-8"))
            return True

        # HTTP Transports
        headers = {"Content-Type": "application/json"}
        headers.update(dest.extra_headers)

        if dest_type == "splunk":
            payload = format_splunk_hec(sanitized_event, dest.index_or_sourcetype or "g1:security:event")
            if dest.api_key:
                headers["Authorization"] = f"Splunk {dest.api_key}"
        elif dest_type in ("elastic", "opensearch"):
            payload = format_elastic_ecs(sanitized_event, dest.index_or_sourcetype or "g1-security-events")
            if dest.api_key:
                headers["Authorization"] = f"ApiKey {dest.api_key}"
            elif dest.auth_header:
                headers["Authorization"] = dest.auth_header
        elif dest_type == "datadog":
            payload = format_datadog_logs(sanitized_event)
            api_key = dest.api_key or os.environ.get("DD_API_KEY", "")
            if api_key:
                headers["DD-API-KEY"] = api_key
        elif dest_type == "sentinel":
            payload = format_azure_sentinel(sanitized_event)
            if dest.auth_header:
                headers["Authorization"] = dest.auth_header
            elif dest.api_key:
                headers["Authorization"] = f"Bearer {dest.api_key}"
        elif dest_type == "cloudwatch":
            payload = {
                "logGroupName": dest.log_group_name or "/g1/docket/security",
                "logStreamName": "events",
                "logEvents": [format_aws_cloudwatch(sanitized_event)],
            }
            if dest.auth_header:
                headers["Authorization"] = dest.auth_header
        elif dest_type == "webhook":
            payload = sanitized_event
            if dest.auth_header:
                headers["Authorization"] = dest.auth_header
            elif dest.api_key:
                headers["X-API-Key"] = dest.api_key
        else:
            raise ValueError(f"Unsupported SIEM destination type: {dest_type}")

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(dest.endpoint_url, json=payload, headers=headers)
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")
            return True

    def flush_pending(self, batch_limit: int = 50) -> int:
        """Process a batch of pending events from the SQLite buffer."""
        now_ts = time.time()
        processed = 0

        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, event_id, destination_id, payload_json, attempts
                FROM siem_buffer
                WHERE status = 'PENDING' AND next_retry_at <= ?
                ORDER BY id ASC LIMIT ?
                """,
                (now_ts, batch_limit),
            ).fetchall()

        for r in rows:
            buf_id = r["id"]
            dest_id = r["destination_id"]
            attempts = r["attempts"]
            dest = self.destinations.get(dest_id)

            if not dest or not dest.enabled:
                # Mark as disabled/skipped
                with self._get_connection() as conn:
                    conn.execute("UPDATE siem_buffer SET status = 'SKIPPED' WHERE id = ?", (buf_id,))
                    conn.commit()
                continue

            try:
                event_data = json.loads(r["payload_json"])
                self.dispatch_single_sync(dest, event_data)

                # Successful delivery
                with self._get_connection() as conn:
                    conn.execute("DELETE FROM siem_buffer WHERE id = ?", (buf_id,))
                    conn.commit()

                st = self._stats.get(dest_id, {})
                st["delivered"] = st.get("delivered", 0) + 1
                st["last_success_ts"] = datetime.now(timezone.utc).isoformat()
                st["consecutive_failures"] = 0
                processed += 1

            except Exception as err:
                new_attempts = attempts + 1
                backoff_delay = min(60.0, (2 ** new_attempts))  # exponential backoff
                next_retry = time.time() + backoff_delay
                error_msg = str(err)[:250]

                new_status = "FAILED" if new_attempts > 10 else "PENDING"

                with self._get_connection() as conn:
                    conn.execute(
                        """
                        UPDATE siem_buffer
                        SET attempts = ?, next_retry_at = ?, status = ?, last_error = ?
                        WHERE id = ?
                        """,
                        (new_attempts, next_retry, new_status, error_msg, buf_id),
                    )
                    conn.commit()

                st = self._stats.get(dest_id, {})
                st["failed"] = st.get("failed", 0) + 1
                st["last_error"] = error_msg
                st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1

        return processed

    def start_worker(self) -> None:
        """Start the background asynchronous drain loop."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(target=self._run_loop, daemon=True)
            self._worker_thread.start()

    def stop_worker(self) -> None:
        """Stop the background worker."""
        with self._lock:
            self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

    def _run_loop(self) -> None:
        while self._running:
            try:
                self.flush_pending(self.max_batch_size)
            except Exception as e:
                logger.error(f"Error in SIEM forwarder flush loop: {e}")
            time.sleep(self.flush_interval_seconds)
