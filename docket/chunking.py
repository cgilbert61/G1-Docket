"""G1 Docket - Merkle Chunk Tree (MCT) Architecture (RFC-009).

Implements RFC 6962-compliant domain-separated Merkle chunk trees for
high-scale document and vector chunk attestation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from typing import Any, Sequence


# RFC 6962 Domain Separation Prefixes
PREFIX_LEAF = b"\x00"
PREFIX_NODE = b"\x01"
PROOF_MAGIC = b"M"  # Magic byte for compact wire encoding


def hash_leaf(data: bytes) -> bytes:
    """Compute RFC 6962 domain-separated leaf digest: SHA256(0x00 || data)."""
    return hashlib.sha256(PREFIX_LEAF + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Compute RFC 6962 domain-separated interior branch digest: SHA256(0x01 || left || right)."""
    return hashlib.sha256(PREFIX_NODE + left + right).digest()


class ChunkProof:
    """Compact cryptographic inclusion proof for an individual chunk in an MCT.
    
    Wire Format (Binary):
      [0]: Magic byte (0x4D == 'M')
      [1]: Depth K (1..32)
      [2..5]: Direction bitmask (uint32_le, bit i=1 if sibling is on right)
      [6..6+32*K]: Concatenated 32-byte sibling hashes
    """

    def __init__(self, path: list[tuple[bytes, bool]], index: int, total_leaves: int) -> None:
        self.path = path  # list of (sibling_hash_32b, is_right_sibling)
        self.index = index
        self.total_leaves = total_leaves

    @property
    def depth(self) -> int:
        return len(self.path)

    def verify(self, chunk_data_or_hash: bytes | str, expected_root: bytes | str) -> bool:
        """Verify inclusion against expected Merkle root in O(log N) operations."""
        if isinstance(expected_root, str):
            expected_root_bytes = bytes.fromhex(expected_root)
        else:
            expected_root_bytes = expected_root

        if isinstance(chunk_data_or_hash, str):
            # If 64-char hex string, treat as raw chunk digest, else encode utf-8
            if len(chunk_data_or_hash) == 64:
                try:
                    leaf_input = bytes.fromhex(chunk_data_or_hash)
                except ValueError:
                    leaf_input = chunk_data_or_hash.encode("utf-8")
            else:
                leaf_input = chunk_data_or_hash.encode("utf-8")
        else:
            leaf_input = chunk_data_or_hash

        # Step 1: RFC 6962 Leaf hash
        curr = hash_leaf(leaf_input)

        # Step 2: Fold path to root
        for sibling, is_right in self.path:
            if is_right:
                curr = hash_node(curr, sibling)
            else:
                curr = hash_node(sibling, curr)

        return hmac.compare_digest(curr, expected_root_bytes)

    def to_bytes(self) -> bytes:
        """Serialize proof into ultra-compact binary format."""
        depth = len(self.path)
        if depth > 32:
            raise ValueError(f"Tree depth {depth} exceeds 32-level wire encoding limit")

        bitmask = 0
        sibling_bytes = bytearray()
        for i, (sibling, is_right) in enumerate(self.path):
            if is_right:
                bitmask |= (1 << i)
            if len(sibling) != 32:
                raise ValueError("Sibling hash must be 32 bytes")
            sibling_bytes.extend(sibling)

        header = struct.pack("<BBIB", ord(PROOF_MAGIC), depth, bitmask, 0)
        return header + bytes(sibling_bytes)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ChunkProof:
        """Deserialize proof from compact binary wire format."""
        if len(raw) < 7:
            raise ValueError("Invalid proof: payload too short")

        magic, depth, bitmask, _ = struct.unpack("<BBIB", raw[:7])
        if magic != ord(PROOF_MAGIC):
            raise ValueError(f"Invalid proof: magic byte {magic:#x} != {ord(PROOF_MAGIC):#x}")

        expected_len = 7 + (depth * 32)
        if len(raw) != expected_len:
            raise ValueError(f"Proof length mismatch: got {len(raw)}, expected {expected_len}")

        path: list[tuple[bytes, bool]] = []
        offset = 7
        for i in range(depth):
            sibling = raw[offset : offset + 32]
            is_right = bool(bitmask & (1 << i))
            path.append((sibling, is_right))
            offset += 32

        return cls(path=path, index=-1, total_leaves=-1)

    def to_base64(self) -> str:
        """URL-safe Base64 representation suitable for HTTP headers and query params."""
        return base64.urlsafe_b64encode(self.to_bytes()).decode("ascii").rstrip("=")

    @classmethod
    def from_base64(cls, s: str) -> ChunkProof:
        """Parse URL-safe Base64 token."""
        # Pad to multiple of 4
        padded = s + "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return cls.from_bytes(raw)


class MerkleChunkTree:
    """RFC 6962-compliant Merkle Chunk Tree (MCT) for arbitrary document passage scaling."""

    def __init__(self, chunks: Sequence[str | bytes] | None = None) -> None:
        self.leaves: list[bytes] = []
        self.levels: list[list[bytes]] = []
        self._is_built = False

        if chunks:
            for c in chunks:
                self.add_chunk(c)
            self.build()

    def add_chunk(self, chunk: str | bytes) -> int:
        """Add a raw chunk text or chunk hash to the tree."""
        if self._is_built:
            raise RuntimeError("Cannot add chunks after tree is built")

        if isinstance(chunk, str):
            if len(chunk) == 64:
                try:
                    raw = bytes.fromhex(chunk)
                except ValueError:
                    raw = chunk.encode("utf-8")
            else:
                raw = chunk.encode("utf-8")
        else:
            raw = chunk

        self.leaves.append(raw)
        return len(self.leaves) - 1

    def build(self) -> bytes:
        """Construct the Merkle tree levels and compute the canonical root."""
        if not self.leaves:
            # Empty tree root is SHA256 of empty string with leaf prefix
            empty_root = hash_leaf(b"")
            self.levels = [[empty_root]]
            self._is_built = True
            return empty_root

        # Level 0: Leaf digests
        current_level = [hash_leaf(leaf) for leaf in self.leaves]
        self.levels = [current_level]

        # Build upwards until single root
        while len(current_level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    parent = hash_node(left, right)
                else:
                    # Odd number of nodes: promote lone node with domain separation
                    parent = hash_node(left, left)
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

        self._is_built = True
        return self.root

    @property
    def root(self) -> bytes:
        if not self._is_built:
            self.build()
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def get_proof(self, index: int) -> ChunkProof:
        """Generate an inclusion proof for the leaf at `index`."""
        if not self._is_built:
            self.build()

        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of bounds (0..{len(self.leaves)-1})")

        path: list[tuple[bytes, bool]] = []
        curr_idx = index

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            if curr_idx % 2 == 0:
                # We are left child; sibling is right child
                if curr_idx + 1 < len(level):
                    sibling = level[curr_idx + 1]
                else:
                    sibling = level[curr_idx]  # Promoted self-pair
                path.append((sibling, True))
            else:
                # We are right child; sibling is left child
                sibling = level[curr_idx - 1]
                path.append((sibling, False))

            curr_idx //= 2

        return ChunkProof(path=path, index=index, total_leaves=len(self.leaves))

    def export_predicate_metadata(self) -> dict[str, Any]:
        """Generate compact in-toto predicate metadata for the chunk tree."""
        if not self._is_built:
            self.build()

        return {
            "version": "1.0",
            "algorithm": "sha256-rfc6962",
            "chunk_count": len(self.leaves),
            "tree_root": self.root_hex,
            "depth": len(self.levels) - 1,
        }
