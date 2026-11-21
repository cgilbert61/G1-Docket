"""
Cryptographic WORM (Write-Once, Read-Many) Audit Ledger.
Enforces immutable hash-chain integrity, SQLite WAL write-once triggers,
and cross-platform file locking for compliance auditability.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

# Cross-platform atomic file locking
if sys.platform == "win32":
    import msvcrt

    @contextmanager
    def file_lock(file_obj) -> Generator[None, None, None]:
        fileno = file_obj.fileno()
        # Lock 1 byte from beginning of file
        file_obj.seek(0, os.SEEK_SET)
        try:
            msvcrt.locking(fileno, msvcrt.LK_NBLCK, 1)
        except OSError:
            # Fall back to blocking lock
            msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            file_obj.seek(0, os.SEEK_SET)
            try:
                msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
else:
    import fcntl

    @contextmanager
    def file_lock(file_obj) -> Generator[None, None, None]:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            try:
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


GENESIS_PREVIOUS_HASH = "0" * 64

VALID_EVENT_TYPES = {
    "DOCKET_ADMISSION",
    "DOCKET_DENIAL",
    "COMBINE_THREAT_BLOCKED",
    "COMBINE_PII_REDACTED",
    "HITL_OVERRIDE_REQUEST",
    "HITL_DUAL_KEY_RELEASE",
    "HITL_REJECTION",
    "SIEM_DISPATCH",
    "OPERATOR_AUTH_SUCCESS",
    "OPERATOR_AUTH_FAILURE",
    "OPERATOR_AUTH_LOCKOUT",
    "OPERATOR_LOGOUT",
    "OPERATOR_MFA_SUCCESS",
    "OPERATOR_MFA_FAILURE",
}


def canonical_json_bytes(obj: Any) -> bytes:
    """Return deterministically sorted, compact UTF-8 JSON bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_sha256_hex(data: bytes) -> str:
    """Compute 64-char lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


class WORMIntegrityError(Exception):
    """Raised when ledger integrity verification detects hash tampering or broken chain."""


class WORMImmutableViolation(Exception):
    """Raised when an operation attempts to update or delete immutable WORM records."""


class WORMAuditLedger:
    """
    Dual-Store WORM Audit Ledger:
    1. SQLite WAL Store: Indexed for fast GUI queries and protected by strict SQL BEFORE UPDATE /
       BEFORE DELETE triggers that abort any modification.
    2. Canonical JSONL File: Continuous hash-chained append log with cross-platform file locking.
    3. Independent Checkpoint Store: Persists (seq_no, head_hash, updated_at) for completeness proof
       and automatic startup reconciliation.
    """

    def __init__(
        self,
        db_path: str | Path,
        jsonl_path: str | Path,
        checkpoint_path: str | Path | None = None,
    ):
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path)
        self.checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else Path(f"{self.jsonl_path}.checkpoint.json")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_sqlite()
        self.reconcile_storage()

    def _write_checkpoint(self, seq_no: int, head_hash: str) -> Dict[str, Any]:
        cp = {
            "seq_no": int(seq_no),
            "head_hash": str(head_hash),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "db_path": str(self.db_path),
            "jsonl_path": str(self.jsonl_path),
        }
        tmp_path = Path(f"{self.checkpoint_path}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cp, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.checkpoint_path)
        return cp

    def read_checkpoint(self) -> Optional[Dict[str, Any]]:
        if not self.checkpoint_path.exists():
            return None
        try:
            return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def reconcile_storage(self) -> Dict[str, Any]:
        """
        Startup/restart reconciliation between SQLite worm_ledger, the JSONL export file, and the checkpoint:
        - Re-appends any committed SQLite tail entries that were not yet flushed to JSONL before a crash.
        - Raises WORMIntegrityError if existing JSONL entries diverge from SQLite or if SQLite is truncated below checkpoint.
        """
        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM worm_ledger ORDER BY sequence_num ASC"
                ).fetchall()

            db_records: List[Dict[str, Any]] = []
            for r in rows:
                db_records.append({
                    "entry_id": r["entry_id"],
                    "sequence_num": int(r["sequence_num"]),
                    "timestamp_utc_iso8601": r["timestamp_utc_iso8601"],
                    "previous_entry_hash": r["previous_entry_hash"],
                    "event_type": r["event_type"],
                    "actor_identity": r["actor_identity"],
                    "payload_digest": r["payload_digest"],
                    "metadata": json.loads(r["metadata_json"]),
                    "entry_hash": r["entry_hash"],
                })

            cp = self.read_checkpoint()
            if cp is not None:
                cp_seq = int(cp.get("seq_no", 0))
                if len(db_records) < cp_seq:
                    raise WORMIntegrityError(
                        f"LEDGER_DIVERGENCE_DETECTED: SQLite ledger has {len(db_records)} entries, fewer than checkpoint seq_no={cp_seq}."
                    )
                if cp_seq > 0 and db_records[cp_seq - 1]["entry_hash"] != cp.get("head_hash"):
                    raise WORMIntegrityError(
                        f"LEDGER_DIVERGENCE_DETECTED: SQLite hash at seq_no={cp_seq} does not match checkpoint head_hash."
                    )

            jsonl_records: List[Dict[str, Any]] = []
            if self.jsonl_path.exists():
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, start=1):
                        s = line.strip()
                        if not s:
                            continue
                        try:
                            jsonl_records.append(json.loads(s))
                        except json.JSONDecodeError as err:
                            raise WORMIntegrityError(
                                f"LEDGER_DIVERGENCE_DETECTED: Corrupt JSON in {self.jsonl_path} at line {line_num}: {err}"
                            ) from err

            if len(jsonl_records) > len(db_records):
                raise WORMIntegrityError(
                    f"LEDGER_DIVERGENCE_DETECTED: JSONL export has {len(jsonl_records)} entries, exceeding SQLite count {len(db_records)}."
                )

            for idx, j_rec in enumerate(jsonl_records):
                d_rec = db_records[idx]
                if (
                    j_rec.get("sequence_num") != d_rec["sequence_num"]
                    or j_rec.get("entry_hash") != d_rec["entry_hash"]
                    or j_rec.get("previous_entry_hash") != d_rec["previous_entry_hash"]
                ):
                    raise WORMIntegrityError(
                        f"LEDGER_DIVERGENCE_DETECTED: JSONL record at index {idx + 1} diverges from SQLite record."
                    )

            reconciled_count = 0
            if len(db_records) > len(jsonl_records):
                missing_tail = db_records[len(jsonl_records):]
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    with file_lock(f):
                        for rec in missing_tail:
                            f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
                            reconciled_count += 1
                        f.flush()
                        os.fsync(f.fileno())

            if db_records:
                self._write_checkpoint(db_records[-1]["sequence_num"], db_records[-1]["entry_hash"])
            elif cp is None:
                self._write_checkpoint(0, GENESIS_PREVIOUS_HASH)

            return {
                "db_entries": len(db_records),
                "jsonl_entries_before": len(jsonl_records),
                "reconciled_appended": reconciled_count,
                "tip_seq": db_records[-1]["sequence_num"] if db_records else 0,
                "tip_hash": db_records[-1]["entry_hash"] if db_records else GENESIS_PREVIOUS_HASH,
            }

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_sqlite(self) -> None:
        """Create write-once table and install immutable triggers."""
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS worm_ledger (
                    entry_id TEXT PRIMARY KEY,
                    sequence_num INTEGER NOT NULL UNIQUE,
                    timestamp_utc_iso8601 TEXT NOT NULL,
                    previous_entry_hash TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_identity TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # WORM Enforcement Trigger: Abort on UPDATE
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_worm_no_update
                BEFORE UPDATE ON worm_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'WORM Violation: Records in worm_ledger are immutable and cannot be modified');
                END;
            """)

            # WORM Enforcement Trigger: Abort on DELETE
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_worm_no_delete
                BEFORE DELETE ON worm_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'WORM Violation: Records in worm_ledger are write-once and cannot be deleted');
                END;
            """)
            conn.commit()

    def get_tip_hash(self) -> Tuple[int, str]:
        """Return (latest_sequence_num, latest_entry_hash). If empty, returns (0, GENESIS_PREVIOUS_HASH)."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT sequence_num, entry_hash FROM worm_ledger ORDER BY sequence_num DESC LIMIT 1"
            ).fetchone()
            if row:
                return int(row["sequence_num"]), str(row["entry_hash"])
            return 0, GENESIS_PREVIOUS_HASH

    def append_event(
        self,
        event_type: str,
        actor_identity: str,
        payload_digest: str,
        metadata: Optional[Dict[str, Any]] = None,
        custom_entry_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Atomically append an immutable record to both SQLite WAL and canonical JSONL file.
        Hash formula: SHA256(canonical_json(record_without_hash) + previous_entry_hash).
        """
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type '{event_type}'. Must be one of {sorted(VALID_EVENT_TYPES)}")

        now_iso = datetime.now(timezone.utc).isoformat()
        metadata_dict = metadata or {}

        with self._lock:
            seq_num, prev_hash = self.get_tip_hash()
            new_seq = seq_num + 1
            entry_id = custom_entry_id or f"WORM-{new_seq:08d}-{compute_sha256_hex(os.urandom(8))[:8]}"

            # Construct canonical entry excluding entry_hash
            record_sans_hash = {
                "entry_id": entry_id,
                "sequence_num": new_seq,
                "timestamp_utc_iso8601": now_iso,
                "previous_entry_hash": prev_hash,
                "event_type": event_type,
                "actor_identity": actor_identity,
                "payload_digest": payload_digest,
                "metadata": metadata_dict,
            }

            # Cryptographic hash binding
            canonical_bytes = canonical_json_bytes(record_sans_hash)
            combined_bytes = canonical_bytes + prev_hash.encode("ascii")
            entry_hash = compute_sha256_hex(combined_bytes)

            full_record = dict(record_sans_hash)
            full_record["entry_hash"] = entry_hash

            # 1. Commit to SQLite WAL
            with self._get_connection() as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO worm_ledger (
                            entry_id, sequence_num, timestamp_utc_iso8601, previous_entry_hash,
                            event_type, actor_identity, payload_digest, metadata_json, entry_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entry_id,
                            new_seq,
                            now_iso,
                            prev_hash,
                            event_type,
                            actor_identity,
                            payload_digest,
                            json.dumps(metadata_dict, sort_keys=True),
                            entry_hash,
                        ),
                    )
                    conn.commit()
                except sqlite3.IntegrityError as e:
                    raise WORMImmutableViolation(f"Failed to append to WORM database: {e}")

            # 2. Append to Canonical JSONL with cross-platform file locking
            jsonl_line = json.dumps(full_record, sort_keys=True, ensure_ascii=False) + "\n"
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                with file_lock(f):
                    f.write(jsonl_line)
                    f.flush()
                    os.fsync(f.fileno())

            # 3. Persist independent checkpoint (seq_no, head_hash, updated_at)
            self._write_checkpoint(new_seq, entry_hash)

            return full_record

    def get_events(self, limit: int = 50, offset: int = 0, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query indexed WORM events for GUI presentation."""
        with self._get_connection() as conn:
            query = "SELECT * FROM worm_ledger"
            params: List[Any] = []
            if event_type:
                query += " WHERE event_type = ?"
                params.append(event_type)
            query += " ORDER BY sequence_num DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                results.append({
                    "entry_id": r["entry_id"],
                    "sequence_num": r["sequence_num"],
                    "timestamp_utc_iso8601": r["timestamp_utc_iso8601"],
                    "previous_entry_hash": r["previous_entry_hash"],
                    "event_type": r["event_type"],
                    "actor_identity": r["actor_identity"],
                    "payload_digest": r["payload_digest"],
                    "metadata": json.loads(r["metadata_json"]),
                    "entry_hash": r["entry_hash"],
                })
            return results

    def count_events(self, event_type: Optional[str] = None) -> int:
        with self._get_connection() as conn:
            if event_type:
                return conn.execute("SELECT COUNT(*) FROM worm_ledger WHERE event_type = ?", (event_type,)).fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM worm_ledger").fetchone()[0]

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic hash chain and completeness of this ledger instance."""
        return verify_ledger_integrity(
            jsonl_path=self.jsonl_path,
            db_path=self.db_path,
            checkpoint_path=self.checkpoint_path,
        )

    def verify_chain(self) -> Dict[str, Any]:
        """Alias for verify_ledger_integrity()."""
        return self.verify_ledger_integrity()


def _discover_expected_completeness(
    jsonl_path: Path,
    db_path: str | Path | None = None,
    checkpoint_path: str | Path | None = None,
) -> Tuple[int, Optional[str], int, Optional[str]]:
    """
    Return (db_count, db_tip_hash, cp_seq_no, cp_head_hash) by inspecting sibling checkpoint and SQLite files.
    """
    cp_file = Path(checkpoint_path) if checkpoint_path is not None else Path(f"{jsonl_path}.checkpoint.json")
    cp_seq = 0
    cp_hash: Optional[str] = None
    discovered_db_from_cp: Optional[Path] = None
    if cp_file.exists():
        try:
            cp_data = json.loads(cp_file.read_text(encoding="utf-8"))
            cp_seq = int(cp_data.get("seq_no", 0))
            cp_hash = cp_data.get("head_hash")
            if cp_data.get("db_path"):
                discovered_db_from_cp = Path(cp_data["db_path"])
        except Exception:
            pass

    candidate_dbs: List[Path] = []
    if db_path is not None:
        candidate_dbs.append(Path(db_path))
    if discovered_db_from_cp is not None:
        candidate_dbs.append(discovered_db_from_cp)
    candidate_dbs.extend([
        jsonl_path.with_suffix(".db"),
        jsonl_path.with_suffix(".sqlite"),
        jsonl_path.parent / "worm.db",
        jsonl_path.parent / "worm_ledger.sqlite",
    ])

    db_count = 0
    db_tip_hash: Optional[str] = None
    for cand in candidate_dbs:
        if cand.exists() and cand.is_file():
            try:
                with sqlite3.connect(str(cand), timeout=5.0) as conn:
                    row_cnt = conn.execute("SELECT COUNT(*) FROM worm_ledger").fetchone()
                    if row_cnt:
                        db_count = int(row_cnt[0])
                    row_tip = conn.execute(
                        "SELECT sequence_num, entry_hash FROM worm_ledger ORDER BY sequence_num DESC LIMIT 1"
                    ).fetchone()
                    if row_tip:
                        db_tip_hash = str(row_tip[1])
                break
            except Exception:
                continue

    return db_count, db_tip_hash, cp_seq, cp_hash


def verify_ledger_integrity(
    jsonl_path: str | Path,
    db_path: str | Path | None = None,
    checkpoint_path: str | Path | None = None,
) -> Dict[str, Any]:
    """
    Standalone verification utility that audits the full cryptographic hash-chain
    from genesis (0*64) to the tip, AND verifies completeness against the SQLite ledger
    and stored checkpoint. Flags any byte-level tampering, missing links, deleted entries,
    or missing/truncated export files.
    """
    path = Path(jsonl_path)
    db_count, db_tip_hash, cp_seq, cp_hash = _discover_expected_completeness(
        path, db_path=db_path, checkpoint_path=checkpoint_path
    )
    expected_min_entries = max(db_count, cp_seq)

    if not path.exists():
        if expected_min_entries > 0:
            return {
                "valid": False,
                "chain_valid": False,
                "error_type": "LEDGER_EXPORT_MISSING_OR_TRUNCATED",
                "reason": "LEDGER_EXPORT_MISSING_OR_TRUNCATED",
                "total_entries": 0,
                "db_entries": db_count,
                "checkpoint_seq_no": cp_seq,
                "genesis_hash": GENESIS_PREVIOUS_HASH,
                "tip_hash": GENESIS_PREVIOUS_HASH,
                "message": (
                    f"LEDGER_EXPORT_MISSING_OR_TRUNCATED: Export file '{path}' is missing, "
                    f"but SQLite has {db_count} entries and checkpoint seq_no is {cp_seq}."
                ),
            }
        return {
            "valid": True,
            "chain_valid": True,
            "total_entries": 0,
            "db_entries": 0,
            "checkpoint_seq_no": 0,
            "genesis_hash": GENESIS_PREVIOUS_HASH,
            "tip_hash": GENESIS_PREVIOUS_HASH,
            "message": "Empty ledger (file does not exist yet).",
        }

    expected_prev_hash = GENESIS_PREVIOUS_HASH
    count = 0
    first_hash: Optional[str] = None
    tip_hash: Optional[str] = None

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except json.JSONDecodeError as err:
                return {
                    "valid": False,
                    "chain_valid": False,
                    "error_type": "JSON_CORRUPTION",
                    "line_number": line_num,
                    "message": f"Malformed JSON on line {line_num}: {err}",
                }

            claimed_hash = record.get("entry_hash")
            claimed_prev = record.get("previous_entry_hash")
            seq_num = record.get("sequence_num")

            # Check previous hash link
            if claimed_prev != expected_prev_hash:
                return {
                    "valid": False,
                    "chain_valid": False,
                    "error_type": "BROKEN_CHAIN_LINK",
                    "line_number": line_num,
                    "sequence_num": seq_num,
                    "claimed_previous_hash": claimed_prev,
                    "expected_previous_hash": expected_prev_hash,
                    "message": f"Hash chain broken at line {line_num} (sequence {seq_num}).",
                }

            # Recalculate hash of record excluding entry_hash
            sans_hash = {k: v for k, v in record.items() if k != "entry_hash"}
            canonical_bytes = canonical_json_bytes(sans_hash)
            computed_hash = compute_sha256_hex(canonical_bytes + expected_prev_hash.encode("ascii"))

            if computed_hash != claimed_hash:
                return {
                    "valid": False,
                    "chain_valid": False,
                    "error_type": "TAMPERED_RECORD",
                    "line_number": line_num,
                    "sequence_num": seq_num,
                    "claimed_hash": claimed_hash,
                    "computed_hash": computed_hash,
                    "message": f"Tampered record at line {line_num}! Computed hash does not match recorded hash.",
                }

            if count == 0:
                first_hash = claimed_hash
            tip_hash = claimed_hash
            expected_prev_hash = claimed_hash
            count += 1

    if count < expected_min_entries:
        return {
            "valid": False,
            "chain_valid": False,
            "error_type": "LEDGER_EXPORT_MISSING_OR_TRUNCATED",
            "reason": "LEDGER_EXPORT_MISSING_OR_TRUNCATED",
            "total_entries": count,
            "db_entries": db_count,
            "checkpoint_seq_no": cp_seq,
            "genesis_hash": GENESIS_PREVIOUS_HASH,
            "tip_hash": tip_hash or GENESIS_PREVIOUS_HASH,
            "message": (
                f"LEDGER_EXPORT_MISSING_OR_TRUNCATED: Export file has {count} entries, "
                f"fewer than expected ({expected_min_entries}; db_count={db_count}, checkpoint_seq_no={cp_seq})."
            ),
        }

    expected_tip = cp_hash or db_tip_hash
    if expected_tip and expected_tip != GENESIS_PREVIOUS_HASH and (tip_hash or GENESIS_PREVIOUS_HASH) != expected_tip:
        return {
            "valid": False,
            "chain_valid": False,
            "error_type": "LEDGER_TIP_HASH_MISMATCH",
            "reason": "LEDGER_TIP_HASH_MISMATCH",
            "total_entries": count,
            "db_entries": db_count,
            "checkpoint_seq_no": cp_seq,
            "tip_hash": tip_hash or GENESIS_PREVIOUS_HASH,
            "expected_tip_hash": expected_tip,
            "message": "Export tip hash does not match checkpoint/SQLite head hash.",
        }

    return {
        "valid": True,
        "chain_valid": True,
        "total_entries": count,
        "total_records": count,
        "db_entries": db_count,
        "checkpoint_seq_no": cp_seq,
        "genesis_hash": GENESIS_PREVIOUS_HASH,
        "first_entry_hash": first_hash or GENESIS_PREVIOUS_HASH,
        "tip_hash": tip_hash or GENESIS_PREVIOUS_HASH,
        "message": f"Ledger integrity verified successfully. {count} records cryptographically validated.",
    }
