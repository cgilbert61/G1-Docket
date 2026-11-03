"""
Quarantine & Triage Store for blocked un-papered data objects,
tampered DSSE tickets, and Combine cognitive denials.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("g1.governance.quarantine")


class QuarantineStore:
    """Manages quarantined requests awaiting human triage and dual-key signoff."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_sqlite()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_sqlite(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_items (
                    quarantine_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'QUARANTINED',
                    event_type TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    locator_uri TEXT,
                    claimed_tier TEXT,
                    triggered_rules_json TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL,
                    extracted_text TEXT,
                    first_key_json TEXT,
                    second_key_json TEXT,
                    emergency_ticket_json TEXT,
                    replay_status TEXT DEFAULT 'NONE',
                    replay_response_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_quar_status ON quarantine_items(status);")
            conn.commit()

    def stage_quarantine(
        self,
        event_type: str,
        reason_code: str,
        payload_digest: str,
        raw_payload: Dict[str, Any],
        locator_uri: Optional[str] = None,
        claimed_tier: Optional[str] = "Internal",
        triggered_rules: Optional[List[str]] = None,
        extracted_text: Optional[str] = None,
        custom_id: Optional[str] = None,
    ) -> str:
        """Add a blocked request to quarantine."""
        qid = custom_id or f"Q-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO quarantine_items (
                    quarantine_id, status, event_type, reason_code, payload_digest,
                    locator_uri, claimed_tier, triggered_rules_json, raw_payload_json,
                    extracted_text, created_at, updated_at
                ) VALUES (?, 'QUARANTINED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qid,
                    event_type,
                    reason_code,
                    payload_digest,
                    locator_uri or "urn:doc:unspecified",
                    claimed_tier or "Internal",
                    json.dumps(triggered_rules or [reason_code]),
                    json.dumps(raw_payload),
                    extracted_text or "",
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()

        logger.info(f"Staged request {qid} in quarantine for reason: {reason_code}")
        return qid

    def list_items(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM quarantine_items"
            params: List[Any] = []
            if status:
                query += " WHERE status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_item(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM quarantine_items WHERE quarantine_id = ?",
                (quarantine_id,),
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def stage_first_key(self, quarantine_id: str, operator: str, rationale: str) -> Dict[str, Any]:
        """Stage Step 1 override request."""
        now_iso = datetime.now(timezone.utc).isoformat()
        first_key_data = {
            "operator": operator.strip(),
            "rationale": rationale.strip(),
            "signed_at": now_iso,
        }

        with self._lock, self._get_connection() as conn:
            row = conn.execute(
                "SELECT status FROM quarantine_items WHERE quarantine_id = ?",
                (quarantine_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"Quarantine item {quarantine_id} not found.")
            if row["status"] != "QUARANTINED":
                raise ValueError(f"Item {quarantine_id} is in status '{row['status']}', cannot stage Key 1.")

            conn.execute(
                """
                UPDATE quarantine_items
                SET status = 'AWAITING_SECOND_KEY', first_key_json = ?, updated_at = ?
                WHERE quarantine_id = ?
                """,
                (json.dumps(first_key_data), now_iso, quarantine_id),
            )
            conn.commit()

        return first_key_data

    def approve_second_key(
        self,
        quarantine_id: str,
        operator: str,
        notes: str,
        emergency_ticket: Dict[str, Any],
        replay_response: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Sign Step 2 approval, release quarantine, and record emergency ticket."""
        now_iso = datetime.now(timezone.utc).isoformat()
        second_key_data = {
            "operator": operator.strip(),
            "notes": notes.strip(),
            "signed_at": now_iso,
        }

        replay_status = "SUCCESS" if replay_response and "error" not in replay_response else "FAILED"

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE quarantine_items
                SET status = 'RELEASED',
                    second_key_json = ?,
                    emergency_ticket_json = ?,
                    replay_status = ?,
                    replay_response_json = ?,
                    updated_at = ?
                WHERE quarantine_id = ?
                """,
                (
                    json.dumps(second_key_data),
                    json.dumps(emergency_ticket),
                    replay_status,
                    json.dumps(replay_response or {}),
                    now_iso,
                    quarantine_id,
                ),
            )
            conn.commit()

        return second_key_data

    def reject_item(self, quarantine_id: str, operator: str, reason: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE quarantine_items
                SET status = 'REJECTED',
                    second_key_json = json_object('rejected_by', ?, 'reason', ?, 'rejected_at', ?),
                    updated_at = ?
                WHERE quarantine_id = ?
                """,
                (operator, reason, now_iso, now_iso, quarantine_id),
            )
            conn.commit()

    def count_by_status(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM quarantine_items GROUP BY status"
            ).fetchall()
            counts = {"QUARANTINED": 0, "AWAITING_SECOND_KEY": 0, "RELEASED": 0, "REJECTED": 0}
            for r in rows:
                counts[r["status"]] = r["cnt"]
            return counts

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "quarantine_id": row["quarantine_id"],
            "status": row["status"],
            "event_type": row["event_type"],
            "reason_code": row["reason_code"],
            "payload_digest": row["payload_digest"],
            "locator_uri": row["locator_uri"],
            "claimed_tier": row["claimed_tier"],
            "triggered_rules": json.loads(row["triggered_rules_json"]),
            "raw_payload": json.loads(row["raw_payload_json"]),
            "extracted_text": row["extracted_text"],
            "first_key": json.loads(row["first_key_json"]) if row["first_key_json"] else None,
            "second_key": json.loads(row["second_key_json"]) if row["second_key_json"] else None,
            "emergency_ticket": json.loads(row["emergency_ticket_json"]) if row["emergency_ticket_json"] else None,
            "replay_status": row["replay_status"],
            "replay_response": json.loads(row["replay_response_json"]) if row["replay_response_json"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
