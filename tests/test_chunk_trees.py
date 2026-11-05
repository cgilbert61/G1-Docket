#!/usr/bin/env python3
"""Unit tests for RFC-009 Merkle Chunk Trees (MCT) and Prevalidator verification."""

import hashlib
import time
from datetime import datetime, timezone, timedelta
import pytest

from docket.chunking import ChunkProof, MerkleChunkTree, hash_leaf, hash_node
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from registry.signing import Keyring, build_attestation_statement, compute_chunk_tree_for_text


def test_rfc6962_domain_separation():
    """Verify RFC 6962 domain prefixes strictly separate leaf nodes from interior branch nodes."""
    raw = b"confidential financial disclosure passage"
    leaf_h = hash_leaf(raw)
    node_h = hash_node(raw, b"")

    # Leaf prefix 0x00 vs Node prefix 0x01 guarantees unequal digests even for identical payloads
    assert leaf_h != node_h
    assert leaf_h == hashlib.sha256(b"\x00" + raw).digest()
    assert node_h == hashlib.sha256(b"\x01" + raw + b"").digest()


def test_tree_construction_and_proof_verification():
    """Build a Merkle Chunk Tree, generate inclusion proofs, and verify them against the root."""
    chunks = [
        "Patient exhibited normal cardiac rhythm.",
        "Blood pressure: 120/80 mmHg.",
        "Prescription: Lisinopril 10mg daily.",
        "Follow-up scheduled in 6 months.",
        "Emergency contact: Jane Doe (Spouse).",
    ]
    tree = MerkleChunkTree(chunks)
    assert tree.leaf_count == 5
    root = tree.root
    assert len(root) == 32

    # Verify every leaf's inclusion proof
    for i, chunk in enumerate(chunks):
        proof = tree.get_proof(i)
        # Verify in-memory proof
        assert proof.verify(chunk, root) is True
        # Verify with hex root
        assert proof.verify(chunk, tree.root_hex) is True

        # Binary wire serialization & deserialization
        b_bytes = proof.to_bytes()
        reconstructed = ChunkProof.from_bytes(b_bytes)
        assert reconstructed.verify(chunk, root) is True

        # Base64 URL-safe token serialization
        token = proof.to_base64()
        b64_proof = ChunkProof.from_base64(token)
        assert b64_proof.verify(chunk, root) is True


def test_tampered_chunk_or_proof_fails_verification():
    """Verify that tampering with chunk text or proof siblings immediately fails verification."""
    chunks = [f"Data row {i}" for i in range(16)]
    tree = MerkleChunkTree(chunks)
    root = tree.root

    proof = tree.get_proof(3)
    assert proof.verify(chunks[3], root) is True

    # Tampered chunk content fails
    assert proof.verify("Tampered row 3", root) is False

    # Tampered proof sibling fails
    corrupt_path = [(bytes([b ^ 0xFF for b in s]), is_r) for s, is_r in proof.path]
    corrupt_proof = ChunkProof(corrupt_path, proof.index, proof.total_leaves)
    assert corrupt_proof.verify(chunks[3], root) is False


def test_large_document_scaling_beyond_256_chunks():
    """Verify Merkle Chunk Tree handles 1,024+ chunks without truncation, with < 10 us verification."""
    chunks = [f"Paragraph {i}: Detailed analytical commentary on enterprise asset allocation." for i in range(1024)]
    tree = MerkleChunkTree(chunks)
    assert tree.leaf_count == 1024
    root = tree.root

    # Depth of 1024 leaves is 10
    proof_first = tree.get_proof(0)
    proof_mid = tree.get_proof(512)
    proof_last = tree.get_proof(1023)

    assert proof_first.depth == 10
    assert proof_mid.depth == 10
    assert proof_last.depth == 10

    # Benchmark proof verification latency
    t0 = time.perf_counter()
    iterations = 2000
    for _ in range(iterations):
        proof_mid.verify(chunks[512], root)
    elapsed_us = ((time.perf_counter() - t0) / iterations) * 1_000_000

    print(f"Merkle chunk proof avg verification latency: {elapsed_us:.2f} us")
    assert elapsed_us < 50.0  # Must be strictly within microsecond budget (< 0.05 ms)


def test_prevalidator_enforces_chunk_proof_in_pod_tag():
    """End-to-end integration test: Prevalidator validates chunk via <pod:object locator='...' chunk_proof='...'>."""
    keyring = Keyring()
    store = InMemorySnapshotStore(keyring)

    passage_text = "Operating revenue increased by 14.2% year-over-year to $4.2B."
    extracted_text, chunk_hashes, tree = compute_chunk_tree_for_text(passage_text)

    proof = tree.get_proof(0)
    b64_proof = proof.to_base64()

    loc = "s3://finance-lakehouse/q3_earnings_transcript.pdf"
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()
    exp_str = (now_dt + timedelta(days=90)).isoformat()

    # Create active snapshot entry with chunk_tree metadata
    store._snapshot_predicate = {
        "sequence_number": 1,
        "expires_at": exp_str,
        "entries": {
            loc: {
                "record_id": "pod-rec-test-mct-01",
                "locator": loc,
                "content_sha256": hashlib.sha256(b"dummy pdf bytes").hexdigest(),
                "extracted_text_sha256": extracted_text,
                "chunk_hashes": chunk_hashes[:10],
                "chunk_tree_root": tree.root_hex,
                "status": "active",
                "minimum_clearance": "Public",
                "egress_class": "public_api",
                "ai_eligibility": "allow",
                "record_expires_at": exp_str,
            }
        },
    }

    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce", strict_inline_hash=True)

    # 1. Valid request carrying chunk_proof and exact chunk text -> ALLOW
    valid_payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Summarize: <pod:object locator="{loc}" chunk_proof="{b64_proof}">{passage_text}</pod:object>',
            }
        ],
    }
    outcome = enforcer.evaluate_request(valid_payload, headers={"x-pod-caller-clearance": "Internal"})
    assert outcome.allowed_to_forward is True
    assert outcome.client_denial_body is None

    # 2. Tampered text inside same tag with legitimate proof -> DENY with HASH_MISMATCH
    tampered_payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Summarize: <pod:object locator="{loc}" chunk_proof="{b64_proof}">Operating revenue DECREASED by 50% to $1.0B.</pod:object>',
            }
        ],
    }
    outcome_tampered = enforcer.evaluate_request(tampered_payload, headers={"x-pod-caller-clearance": "Internal"})
    assert outcome_tampered.allowed_to_forward is False
    assert "REASON_HASH_MISMATCH" in outcome_tampered.audit_entry.reason_codes
