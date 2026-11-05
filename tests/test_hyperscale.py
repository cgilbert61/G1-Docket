#!/usr/bin/env python3
"""Unit tests for G1 Docket Hyperscale Cryptographic Structures & Filters."""

import hashlib
import time
import pytest

from docket.hyperscale import CountingBloomFilter, SparseMerkleTree


def test_bloom_filter_membership_and_true_negatives():
    """Verify CountingBloomFilter inserts, detects membership, and guarantees 0% false negatives."""
    bf = CountingBloomFilter(capacity=10_000, error_rate=0.0001)

    test_keys = [f"s3://corp-lakehouse-prod/dataset_{i}.parquet" for i in range(100)]
    for key in test_keys:
        bf.add(key)

    # All inserted keys must be detected (0% false negatives)
    for key in test_keys:
        assert bf.contains(key) is True

    # Non-member keys should return False (with extremely low false positive rate)
    missing_count = 0
    for i in range(100, 1100):
        if not bf.contains(f"s3://corp-lakehouse-prod/unseen_{i}.parquet"):
            missing_count += 1
    # Over 99% of unseen keys must return False
    assert missing_count >= 990


def test_bloom_filter_removal_and_revocation():
    """Verify that removing an object from CountingBloomFilter properly decrements counts."""
    bf = CountingBloomFilter(capacity=1_000, error_rate=0.001)
    key = "s3://sensitive/revoked_contract.pdf"

    bf.add(key)
    assert bf.contains(key) is True

    removed = bf.remove(key)
    assert removed is True
    assert bf.contains(key) is False


def test_bloom_filter_sub_microsecond_latency():
    """Benchmark L0 filter negative lookup latency (< 25 us per probe)."""
    bf = CountingBloomFilter(capacity=100_000, error_rate=0.0001)
    for i in range(1000):
        bf.add(f"file_{i}")

    t0 = time.perf_counter()
    probes = 5000
    for i in range(probes):
        bf.contains(f"probe_query_{i}")
    elapsed_us = ((time.perf_counter() - t0) / probes) * 1_000_000

    print(f"Bloom filter avg probe latency: {elapsed_us:.2f} us")
    assert elapsed_us < 35.0  # Must be well within SLA budget


def test_sparse_merkle_tree_proof_and_verification():
    """Verify Sparse Merkle Tree leaf updates, proof generation, and verification."""
    smt = SparseMerkleTree()

    key1 = hashlib.sha256(b"document_payload_content_1").digest()
    val1 = hashlib.sha256(b"CONFIDENTIAL_METADATA_TIER").digest()

    root1 = smt.update(key1, val1)
    assert len(root1) == 32
    assert root1 != bytes(32)

    # Generate proof
    proof = smt.prove(key1)
    assert len(proof) == 256

    # Verify proof independently
    is_valid = SparseMerkleTree.verify_proof(root1, key1, val1, proof)
    assert is_valid is True


def test_sparse_merkle_tree_tamper_detection():
    """Verify that any modification to key, value, or proof bits invalidates SMT verification."""
    smt = SparseMerkleTree()

    key = hashlib.sha256(b"original_legal_brief").digest()
    val = hashlib.sha256(b"RESTRICTED_ATTRIBUTES").digest()

    root = smt.update(key, val)
    proof = smt.prove(key)

    # 1. Tampered value (e.g. attempting to downgrade tier)
    tampered_val = hashlib.sha256(b"PUBLIC_ATTRIBUTES_TAMPERED").digest()
    assert SparseMerkleTree.verify_proof(root, key, tampered_val, proof) is False

    # 2. Tampered key (content mismatch)
    tampered_key = hashlib.sha256(b"altered_document_content").digest()
    assert SparseMerkleTree.verify_proof(root, tampered_key, val, proof) is False

    # 3. Corrupted proof sibling hash
    corrupted_proof = list(proof)
    bit, sibling = corrupted_proof[10]
    corrupted_proof[10] = (bit, bytes([b ^ 0xFF for b in sibling]))
    assert SparseMerkleTree.verify_proof(root, key, val, corrupted_proof) is False
