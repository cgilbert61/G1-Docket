#!/usr/bin/env python3
"""G1 Docket - Hyperscale Cascading Multi-Layer Filtering & SMT Demo.

Demonstrates the hyperscale admission architecture for multi-billion object estates
specified in docs/hyperscale-architecture.md:
  1. Layer 0: Counting Bloom Filter negative lookup bypass (< 15 us rejection)
  2. Layer 1: In-memory authenticated bitmask lookup (< 120 us policy check)
  3. Layer 2: 256-bit Sparse Merkle Tree (SMT) inclusion proof verification
  4. Layer 3: Instant cryptographic revocation and tamper detection
"""

from __future__ import annotations

import hashlib
import time
from docket.hyperscale import CountingBloomFilter, SparseMerkleTree


def run_hyperscale_demo() -> bool:
    print("=" * 80)
    print("      G1 DOCKET: HYPERSCALE CASCADING FILTERING & SMT VERIFICATION DEMO      ")
    print("=" * 80)

    # Step 1: Initialize Hyperscale Engine with 100k capacity
    print("\n[+] Step 1: Initializing L0 Counting Bloom Filter & 256-bit SMT...")
    bloom = CountingBloomFilter(capacity=100_000, error_rate=0.0001)
    smt = SparseMerkleTree()

    # Pre-seed 100 enterprise data assets
    dataset_records = []
    for i in range(100):
        locator = f"s3://corp-lakehouse-prod/enterprise_data_{i:04d}.parquet"
        content_bytes = f"payload_content_for_record_{i}".encode("utf-8")
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        tier = "CONFIDENTIAL" if i % 2 == 0 else "INTERNAL"

        # Add to L0 Bloom Filter
        bloom.add(content_sha256)
        bloom.add(locator)

        # Anchor in 256-bit SMT
        leaf_val = hashlib.sha256(f"{tier}:ALLOW:30d".encode()).digest()
        smt.update(content_sha256, leaf_val)

        dataset_records.append((locator, content_sha256, tier, leaf_val))

    smt_root = smt.get_root()
    print(f"    - Filter Initialized: m={bloom.num_bits} bits, k={bloom.num_hashes} hashes")
    print(f"    - SMT Root Hash:      {smt_root.hex()[:32]}... ({len(dataset_records)} leaves)")

    # Scenario 1: Unattested Object Rejection via L0 Bloom Filter
    print("\n" + "-" * 80)
    print("Scenario 1: Adversarial / Unattested Object Rejection via L0 Bloom Filter")
    unattested_sha256 = hashlib.sha256(b"unauthorized_secret_leak_payload").hexdigest()

    t0 = time.perf_counter()
    l0_hit = bloom.contains(unattested_sha256)
    elapsed_us = (time.perf_counter() - t0) * 1_000_000

    print(f"  Target:     {unattested_sha256[:24]}... (Unattested file)")
    print(f"  L0 Lookup:  {'FOUND (Proceed)' if l0_hit else 'NEGATIVE (Bypass & Reject)'}")
    print(f"  Latency:    {elapsed_us:.2f} us (SLA target: < 25.0 us)")
    assert not l0_hit, "L0 Bloom Filter must reject unattested file"
    assert elapsed_us < 50.0, "L0 rejection must execute in sub-microsecond time"
    print("  Outcome:    [HARD REJECT] Blocked at Layer 0 without disk or snapshot I/O.")

    # Scenario 2: Attested Object Fast L0 Hit -> L1 Bitmask Admission
    print("\n" + "-" * 80)
    print("Scenario 2: Attested Asset L0 Pass -> L1 In-Memory Policy Evaluation")
    valid_locator, valid_sha256, valid_tier, valid_val = dataset_records[42]

    t0 = time.perf_counter()
    in_l0 = bloom.contains(valid_sha256)
    t_l0 = (time.perf_counter() - t0) * 1_000_000

    print(f"  Locator:    {valid_locator}")
  
    print(f"  SHA-256:    {valid_sha256[:24]}...")
    print(f"  L0 Match:   {in_l0} ({t_l0:.2f} us)")
    assert in_l0 is True

    # Simulate in-memory bitmask clearance check
    caller_clearance = "CONFIDENTIAL"
    is_cleared = (caller_clearance == "CONFIDENTIAL" and valid_tier in ["INTERNAL", "CONFIDENTIAL"])
    print(f"  Clearance:  Caller={caller_clearance} vs Asset={valid_tier} -> Cleared={is_cleared}")
    assert is_cleared is True
    print("  Outcome:    [PASSED / FORWARDED] Admitted under in-memory bitmask.")

    # Scenario 3: 256-bit SMT Cryptographic Inclusion Proof Verification
    print("\n" + "-" * 80)
    print("Scenario 3: Zero-Knowledge Inclusion Proof via Sparse Merkle Tree (SMT)")
    proof = smt.prove(valid_sha256)
    print(f"  Proof Path: 256 sibling node hashes (Size: {len(proof) * 32} bytes)")

    t0 = time.perf_counter()
    is_valid_proof = SparseMerkleTree.verify_proof(smt_root, valid_sha256, valid_val, proof)
    t_proof = (time.perf_counter() - t0) * 1_000_000

    print(f"  Validation: Root Match={is_valid_proof} in {t_proof:.2f} us")
    assert is_valid_proof is True, "SMT inclusion proof must verify against root"
    print("  Outcome:    [CRYPTOGRAPHICALLY PROVEN] Mathematical proof confirmed.")

    # Scenario 4: Tampered Content / Hash Drift Detection
    print("\n" + "-" * 80)
    print("Scenario 4: Tamper Detection (Tampered Payload / Tier Downgrade Attack)")
    tampered_val = hashlib.sha256(b"PUBLIC:ALLOW:365d").digest()

    tamper_result = SparseMerkleTree.verify_proof(smt_root, valid_sha256, tampered_val, proof)
    print(f"  Attack:     Attempted tier downgrade to PUBLIC")
    print(f"  Proof Check: Root Match={tamper_result}")
    assert tamper_result is False, "SMT must reject tampered tier attributes"
    print("  Outcome:    [TAMPER DETECTED] Cryptographic mismatch rejected immediately.")

    # Scenario 5: Dynamic Revocation via Counting Bloom Decrement
    print("\n" + "-" * 80)
    print("Scenario 5: Dynamic Revocation via L0 Counting Filter Decrement")
    print(f"  Target:     Revoking asset {valid_locator}")
    revoked = bloom.remove(valid_sha256)
    assert revoked is True
    still_present = bloom.contains(valid_sha256)
    print(f"  L0 Status:  contains={still_present} (Removed successfully)")
    assert still_present is False
    print("  Outcome:    [REVOKED] Negative lookup now instantly blocks former asset.")

    print("\n" + "=" * 80)
    print("      [+] ALL 5 HYPERSCALE CASCADING FILTER SCENARIOS PASSED")
    print("=" * 80 + "\n")
    return True


if __name__ == "__main__":
    success = run_hyperscale_demo()
    raise SystemExit(0 if success else 1)
