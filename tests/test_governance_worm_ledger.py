"""
Unit and Integration Tests for Cryptographic WORM Audit Ledger.
Verifies Merkle hash chaining, SQLite WAL immutability triggers,
and byte-level tamper detection.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from governance.worm_ledger import (
    GENESIS_PREVIOUS_HASH,
    WORMAuditLedger,
    WORMIntegrityError,
    verify_ledger_integrity,
)


@pytest.fixture
def worm_paths(tmp_path):
    db_file = tmp_path / "worm.db"
    jsonl_file = tmp_path / "worm.jsonl"
    return db_file, jsonl_file


def test_genesis_block_and_hash_chaining(worm_paths):
    db_file, jsonl_file = worm_paths
    ledger = WORMAuditLedger(db_path=db_file, jsonl_path=jsonl_file)

    # 1. First event uses genesis hash
    e1 = ledger.append_event(
        event_type="DOCKET_ADMISSION",
        actor_identity="agent:docket-prevalidator",
        payload_digest="a" * 64,
        metadata={"locator": "file:///doc1.txt", "tier": "Internal"},
    )
    assert e1["sequence_num"] == 1
    assert e1["previous_entry_hash"] == GENESIS_PREVIOUS_HASH
    assert len(e1["entry_hash"]) == 64

    # 2. Second event chains to e1's hash
    e2 = ledger.append_event(
        event_type="DOCKET_DENIAL",
        actor_identity="agent:docket-prevalidator",
        payload_digest="b" * 64,
        metadata={"reason_code": "UNATTESTED_DATA_OBJECT"},
    )
    assert e2["sequence_num"] == 2
    assert e2["previous_entry_hash"] == e1["entry_hash"]

    # 3. Third event chains to e2's hash
    e3 = ledger.append_event(
        event_type="COMBINE_THREAT_BLOCKED",
        actor_identity="agent:combine-gateway",
        payload_digest="c" * 64,
        metadata={"rule_id": "INJ-34"},
    )
    assert e3["sequence_num"] == 3
    assert e3["previous_entry_hash"] == e2["entry_hash"]

    # Verify tip
    tip_seq, tip_hash = ledger.get_tip_hash()
    assert tip_seq == 3
    assert tip_hash == e3["entry_hash"]

    # Audit file integrity
    audit = verify_ledger_integrity(jsonl_file)
    assert audit["valid"] is True
    assert audit["total_entries"] == 3
    assert audit["tip_hash"] == e3["entry_hash"]


def test_sqlite_wal_triggers_prevent_update_and_delete(worm_paths):
    db_file, jsonl_file = worm_paths
    ledger = WORMAuditLedger(db_path=db_file, jsonl_path=jsonl_file)

    e1 = ledger.append_event(
        event_type="DOCKET_ADMISSION",
        actor_identity="user:secops",
        payload_digest="d" * 64,
        metadata={"tier": "Public"},
    )

    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()

    # Attempt UPDATE -> Must be aborted by WORM trigger
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_update:
        cursor.execute("UPDATE worm_ledger SET actor_identity = 'attacker' WHERE sequence_num = 1")
    assert "WORM Violation: Records in worm_ledger are immutable" in str(exc_update.value)

    # Attempt DELETE -> Must be aborted by WORM trigger
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_delete:
        cursor.execute("DELETE FROM worm_ledger WHERE sequence_num = 1")
    assert "WORM Violation: Records in worm_ledger are write-once" in str(exc_delete.value)

    conn.close()


def test_tamper_detection_on_modified_line(worm_paths):
    db_file, jsonl_file = worm_paths
    ledger = WORMAuditLedger(db_path=db_file, jsonl_path=jsonl_file)

    for i in range(5):
        ledger.append_event(
            event_type="DOCKET_ADMISSION",
            actor_identity=f"user_{i}",
            payload_digest=f"{i}" * 64,
            metadata={"index": i},
        )

    # Verify initial chain is valid
    audit_init = verify_ledger_integrity(jsonl_file)
    assert audit_init["valid"] is True
    assert audit_init["total_entries"] == 5

    # Tamper with Line 3 by changing 1 character in payload_digest
    lines = jsonl_file.read_text(encoding="utf-8").splitlines()
    tampered_record = json.loads(lines[2])  # Line 3 (index 2)
    tampered_record["actor_identity"] = "malicious_spoofed_identity"
    lines[2] = json.dumps(tampered_record, sort_keys=True)
    jsonl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Run verification -> Must detect tampering on Line 3
    audit_tampered = verify_ledger_integrity(jsonl_file)
    assert audit_tampered["valid"] is False
    assert audit_tampered["error_type"] == "TAMPERED_RECORD"
    assert audit_tampered["line_number"] == 3


def test_tamper_detection_on_deleted_line(worm_paths):
    db_file, jsonl_file = worm_paths
    ledger = WORMAuditLedger(db_path=db_path, jsonl_path=jsonl_file) if False else WORMAuditLedger(db_path=db_file, jsonl_path=jsonl_file)

    for i in range(4):
        ledger.append_event(
            event_type="DOCKET_ADMISSION",
            actor_identity=f"user_{i}",
            payload_digest=f"{i}" * 64,
        )

    # Delete Line 2
    lines = jsonl_file.read_text(encoding="utf-8").splitlines()
    del lines[1]
    jsonl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verification must catch broken chain link
    audit = verify_ledger_integrity(jsonl_file)
    assert audit["valid"] is False
    assert audit["error_type"] == "BROKEN_CHAIN_LINK"
    assert audit["line_number"] == 2
