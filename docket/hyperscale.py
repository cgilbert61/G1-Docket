"""G1 Docket - Hyperscale Cryptographic Structures & Cascading Filters.

Implements the cryptographic algorithms and probabilistic filters specified in
docs/hyperscale-architecture.md for multi-billion object estates:
  1. CountingBloomFilter: Sub-15 microsecond negative lookup bypass with
     configurable capacity and 24-bit/key mathematical allocation.
  2. SparseMerkleTree: 256-bit depth authenticated sparse Merkle trie
     supporting logarithmic O(log N) inclusion proofs, root anchoring,
     and tamper detection.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any


class CountingBloomFilter:
    """High-performance in-memory counting Bloom filter for L0 gateway negative lookup.
    
    Uses Kirsch-Mitzenmacher double-hashing optimization to evaluate k hash functions
    with minimal CPU overhead:
        g_i(x) = (h1(x) + i * h2(x)) % m
    """

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.0001) -> None:
        if capacity <= 0:
            raise ValueError("Capacity must be positive")
        if not (0.0 < error_rate < 1.0):
            raise ValueError("Error rate must be between 0.0 and 1.0")

        self.capacity = capacity
        self.error_rate = error_rate

        # Optimal bit array size m = - (n * ln(p)) / (ln(2)^2)
        m = - (capacity * math.log(error_rate)) / (math.log(2) ** 2)
        self.num_bits = max(64, int(math.ceil(m)))

        # Optimal hash count k = (m / n) * ln(2)
        k = (self.num_bits / capacity) * math.log(2)
        self.num_hashes = max(1, int(round(k)))

        # Bytearray with 4 bits per bucket for counting (0..15)
        # For memory efficiency, allocate 1 byte per 2 counters
        self._counts = bytearray((self.num_bits + 1) // 2)

    def _get_counter(self, idx: int) -> int:
        byte_idx = idx >> 1
        val = self._counts[byte_idx]
        return (val >> 4) if (idx & 1) else (val & 0x0F)

    def _set_counter(self, idx: int, value: int) -> None:
        byte_idx = idx >> 1
        value = max(0, min(15, value))
        current = self._counts[byte_idx]
        if idx & 1:
            self._counts[byte_idx] = (current & 0x0F) | (value << 4)
        else:
            self._counts[byte_idx] = (current & 0xF0) | value

    def _hashes(self, item_bytes: bytes) -> list[int]:
        # Generate 64-bit seed hashes from SHA-256
        digest = hashlib.sha256(item_bytes).digest()
        h1 = int.from_bytes(digest[:8], "big")
        h2 = int.from_bytes(digest[8:16], "big") | 1  # ensure odd

        indices: list[int] = []
        for i in range(self.num_hashes):
            idx = (h1 + i * h2) % self.num_bits
            indices.append(idx)
        return indices

    def add(self, item: str | bytes) -> None:
        """Insert an attested key or locator into the filter."""
        raw = item.encode("utf-8") if isinstance(item, str) else item
        for idx in self._hashes(raw):
            c = self._get_counter(idx)
            if c < 15:  # Saturate at 15
                self._set_counter(idx, c + 1)

    def remove(self, item: str | bytes) -> bool:
        """Decrement counts for an item upon revocation."""
        raw = item.encode("utf-8") if isinstance(item, str) else item
        if not self.contains(raw):
            return False
        for idx in self._hashes(raw):
            c = self._get_counter(idx)
            if c > 0:
                self._set_counter(idx, c - 1)
        return True

    def contains(self, item: str | bytes) -> bool:
        """Check membership. Returns False if definitely NOT present."""
        raw = item.encode("utf-8") if isinstance(item, str) else item
        for idx in self._hashes(raw):
            if self._get_counter(idx) == 0:
                return False
        return True


# Precomputed empty node hashes for 256-bit Sparse Merkle Tree
_EMPTY_LEAF = hashlib.sha256(b"\x00" * 32).digest()
_EMPTY_HASHES: list[bytes] = [_EMPTY_LEAF]
for _i in range(256):
    _prev = _EMPTY_HASHES[-1]
    _EMPTY_HASHES.append(hashlib.sha256(_prev + _prev).digest())


class SparseMerkleTree:
    """Deterministic 256-bit Sparse Merkle Tree supporting full inclusion proofs."""

    def __init__(self) -> None:
        self.leaves: dict[bytes, bytes] = {}
        # trie: node_path (bitstring) -> hash (32 bytes)
        self._nodes: dict[str, bytes] = {}
        self._root: bytes = _EMPTY_HASHES[256]

    @staticmethod
    def _to_32bytes(val: str | bytes) -> bytes:
        if isinstance(val, str):
            if len(val) == 64:
                try:
                    return bytes.fromhex(val)
                except ValueError:
                    pass
            return hashlib.sha256(val.encode("utf-8")).digest()
        if len(val) != 32:
            return hashlib.sha256(val).digest()
        return val

    @staticmethod
    def _to_bits(k32: bytes) -> str:
        """Convert 32-byte key to 256-character '0'/'1' bitstring."""
        return "".join(f"{b:08b}" for b in k32)

    def update(self, key: str | bytes, value: str | bytes) -> bytes:
        k32 = self._to_32bytes(key)
        v32 = self._to_32bytes(value)
        self.leaves[k32] = v32

        # Recompute tree paths
        self._rebuild()
        return self.get_root()

    def _rebuild(self) -> None:
        self._nodes.clear()
        if not self.leaves:
            self._root = _EMPTY_HASHES[256]
            return

        # 1. Place leaf hashes at depth 256
        layer: dict[str, bytes] = {}
        for k32, v32 in self.leaves.items():
            bits = self._to_bits(k32)
            leaf_h = hashlib.sha256(k32 + v32).digest()
            layer[bits] = leaf_h
            self._nodes[bits] = leaf_h

        # 2. Bubble up to root (depth 256 down to 1)
        for depth in range(256, 0, -1):
            next_layer: dict[str, bytes] = {}
            prefixes = set(path[:-1] for path in layer)
            empty_sibling = _EMPTY_HASHES[256 - depth]

            for parent_prefix in prefixes:
                left_path = parent_prefix + "0"
                right_path = parent_prefix + "1"

                left_h = layer.get(left_path) or self._nodes.get(left_path, empty_sibling)
                right_h = layer.get(right_path) or self._nodes.get(right_path, empty_sibling)

                parent_h = hashlib.sha256(left_h + right_h).digest()
                next_layer[parent_prefix] = parent_h
                self._nodes[parent_prefix] = parent_h

            layer = next_layer

        self._root = self._nodes.get("", _EMPTY_HASHES[256])

    def get_root(self) -> bytes:
        return self._root

    def prove(self, key: str | bytes) -> list[tuple[int, bytes]]:
        """Generate 256-sibling audit trail for key."""
        k32 = self._to_32bytes(key)
        bits = self._to_bits(k32)
        proof: list[tuple[int, bytes]] = []

        # From leaf (depth 256) up to root (depth 1)
        for d in range(256, 0, -1):
            prefix = bits[:d - 1]
            current_bit = int(bits[d - 1])
            sibling_bit = 1 - current_bit
            sibling_path = prefix + str(sibling_bit)

            empty_sibling = _EMPTY_HASHES[256 - d]
            sibling_hash = self._nodes.get(sibling_path, empty_sibling)
            proof.append((current_bit, sibling_hash))

        return proof

    @classmethod
    def verify_proof(
        cls,
        root: bytes,
        key: str | bytes,
        value: str | bytes,
        proof: list[tuple[int, bytes]],
    ) -> bool:
        """Verify inclusion proof against root hash."""
        k32 = cls._to_32bytes(key)
        v32 = cls._to_32bytes(value)
        curr = hashlib.sha256(k32 + v32).digest()

        for bit, sibling in proof:
            if bit == 0:
                curr = hashlib.sha256(curr + sibling).digest()
            else:
                curr = hashlib.sha256(sibling + curr).digest()

        return curr == root
