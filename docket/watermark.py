"""G1 Docket — Cryptographic Prompt Watermarking & Forensic Provenance.

Provides invisible (zero-width Unicode steganography) and structural cryptographic
provenance watermarks embedded into prompts and LLM completions.

When prompt text or LLM transcripts are subsequently leaked, exported, or audited,
forensic investigators can extract the watermark to verify:
  1. Active DSSE snapshot sequence number at time of evaluation.
  2. Cryptographic caller identity (caller_key).
  3. Precise UTC timestamp.
  4. Non-repudiation HMAC-SHA256 signature proving G1 Docket origin.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# Zero-width Unicode characters for steganographic embedding:
# - ZW_ZERO (\u200B): Represents bit 0
# - ZW_ONE  (\u200C): Represents bit 1
# - ZW_FLAG (\u200D): Start/end framing delimiter
ZW_ZERO = "\u200B"
ZW_ONE = "\u200C"
ZW_FLAG = "\u200D"

DEFAULT_WATERMARK_SECRET = b"g1-docket-provenance-watermark-key-v1"


@dataclass(frozen=True)
class WatermarkPayload:
    """Decoded cryptographic provenance watermark."""

    version: int
    snapshot_sequence: int
    timestamp_epoch: int
    caller_key: str
    signature: str
    signature_valid: bool

    @property
    def timestamp_iso(self) -> str:
        """Return ISO-8601 formatted UTC timestamp."""
        return datetime.fromtimestamp(self.timestamp_epoch, tz=timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "version": self.version,
            "snapshot_sequence": self.snapshot_sequence,
            "timestamp_epoch": self.timestamp_epoch,
            "timestamp_iso": self.timestamp_iso,
            "caller_key": self.caller_key,
            "signature": self.signature,
            "signature_valid": self.signature_valid,
        }


def _compute_watermark_sig(
    version: int,
    snapshot_sequence: int,
    timestamp_epoch: int,
    caller_key: str,
    secret_key: bytes,
) -> bytes:
    """Compute an 8-byte (64-bit) truncated HMAC-SHA256 signature."""
    mac = hmac.new(secret_key, digestmod=hashlib.sha256)
    mac.update(struct.pack(">BII", version, snapshot_sequence, timestamp_epoch))
    mac.update(caller_key.encode("utf-8"))
    return mac.digest()[:8]


def encode_watermark_bytes(
    snapshot_sequence: int,
    caller_key: str,
    timestamp_epoch: int | None = None,
    secret_key: bytes = DEFAULT_WATERMARK_SECRET,
    version: int = 1,
) -> bytes:
    """Pack watermark fields into a compact binary frame."""
    ts = int(time.time()) if timestamp_epoch is None else timestamp_epoch
    key_bytes = caller_key.encode("utf-8")
    if len(key_bytes) > 255:
        key_bytes = key_bytes[:255]

    sig = _compute_watermark_sig(version, snapshot_sequence, ts, caller_key, secret_key)
    # Header: [version: 1B, seq: 4B, ts: 4B, key_len: 1B] + key_bytes + [sig: 8B]
    header = struct.pack(">BIIB", version, snapshot_sequence, ts, len(key_bytes))
    return header + key_bytes + sig


def decode_watermark_bytes(
    raw_bytes: bytes,
    secret_key: bytes = DEFAULT_WATERMARK_SECRET,
) -> WatermarkPayload | None:
    """Parse a compact binary frame into a WatermarkPayload, verifying its signature."""
    if len(raw_bytes) < 18:  # 1 + 4 + 4 + 1 + 0 + 8
        return None

    version, seq, ts, key_len = struct.unpack_from(">BIIB", raw_bytes, 0)
    expected_len = 10 + key_len + 8
    if len(raw_bytes) != expected_len:
        return None

    key_bytes = raw_bytes[10 : 10 + key_len]
    caller_key = key_bytes.decode("utf-8", errors="replace")
    embedded_sig = raw_bytes[10 + key_len : 10 + key_len + 8]

    computed_sig = _compute_watermark_sig(version, seq, ts, caller_key, secret_key)
    is_valid = hmac.compare_digest(embedded_sig, computed_sig)

    return WatermarkPayload(
        version=version,
        snapshot_sequence=seq,
        timestamp_epoch=ts,
        caller_key=caller_key,
        signature=embedded_sig.hex(),
        signature_valid=is_valid,
    )


def embed_invisible_watermark(
    text: str,
    snapshot_sequence: int,
    caller_key: str,
    timestamp_epoch: int | None = None,
    secret_key: bytes = DEFAULT_WATERMARK_SECRET,
) -> str:
    """Embed an invisible zero-width Unicode cryptographic watermark into text."""
    payload_bytes = encode_watermark_bytes(
        snapshot_sequence=snapshot_sequence,
        caller_key=caller_key,
        timestamp_epoch=timestamp_epoch,
        secret_key=secret_key,
    )

    # Convert binary payload to zero-width bit sequence
    zw_bits: list[str] = [ZW_FLAG]
    for byte in payload_bytes:
        for bit_idx in range(7, -1, -1):
            bit = (byte >> bit_idx) & 1
            zw_bits.append(ZW_ONE if bit else ZW_ZERO)
    zw_bits.append(ZW_FLAG)

    watermark_str = "".join(zw_bits)
    # Embed at end of first line or end of text
    if "\n" in text:
        first_line, rest = text.split("\n", 1)
        return f"{first_line}{watermark_str}\n{rest}"
    return f"{text}{watermark_str}"


def extract_invisible_watermark(
    text: str,
    secret_key: bytes = DEFAULT_WATERMARK_SECRET,
) -> WatermarkPayload | None:
    """Extract and verify an invisible zero-width Unicode cryptographic watermark from text."""
    # Find bounded sequence: ZW_FLAG ... ZW_FLAG
    start_idx = text.find(ZW_FLAG)
    if start_idx == -1:
        return None
    end_idx = text.find(ZW_FLAG, start_idx + 1)
    if end_idx == -1:
        return None

    bit_chars = text[start_idx + 1 : end_idx]
    bits: list[int] = []
    for ch in bit_chars:
        if ch == ZW_ZERO:
            bits.append(0)
        elif ch == ZW_ONE:
            bits.append(1)

    if len(bits) < 18 * 8 or len(bits) % 8 != 0:
        return None

    raw_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        for b in bits[i : i + 8]:
            byte_val = (byte_val << 1) | b
        raw_bytes.append(byte_val)

    return decode_watermark_bytes(bytes(raw_bytes), secret_key=secret_key)


def has_invisible_watermark(text: str) -> bool:
    """Check if the text contains zero-width watermark characters."""
    return ZW_FLAG in text and (ZW_ZERO in text or ZW_ONE in text)


def format_structural_watermark(
    snapshot_sequence: int,
    caller_key: str,
    timestamp_epoch: int | None = None,
    secret_key: bytes = DEFAULT_WATERMARK_SECRET,
) -> str:
    """Generate a structural XML/HTML provenance comment."""
    ts = int(time.time()) if timestamp_epoch is None else timestamp_epoch
    sig = _compute_watermark_sig(1, snapshot_sequence, ts, caller_key, secret_key).hex()
    iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return f'<!-- pod:provenance seq="{snapshot_sequence}" caller="{caller_key}" timestamp="{iso_ts}" sig="{sig}" -->'
