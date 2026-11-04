"""Unit tests for G1 Docket Cryptographic Prompt Watermarking."""

from __future__ import annotations

import time
import pytest

from docket import (
    DocketClient,
    WatermarkPayload,
    embed_invisible_watermark,
    extract_invisible_watermark,
    format_structural_watermark,
    has_invisible_watermark,
)
from docket.watermark import (
    DEFAULT_WATERMARK_SECRET,
    decode_watermark_bytes,
    encode_watermark_bytes,
)


def test_watermark_binary_encode_decode():
    seq = 3159
    caller = "pod-key-analyst"
    ts = int(time.time())

    raw_bytes = encode_watermark_bytes(
        snapshot_sequence=seq,
        caller_key=caller,
        timestamp_epoch=ts,
    )
    assert len(raw_bytes) > 18

    payload = decode_watermark_bytes(raw_bytes)
    assert payload is not None
    assert payload.snapshot_sequence == seq
    assert payload.caller_key == caller
    assert payload.timestamp_epoch == ts
    assert payload.signature_valid is True
    assert payload.version == 1


def test_watermark_tamper_detection():
    raw_bytes = encode_watermark_bytes(
        snapshot_sequence=100,
        caller_key="pod-key-public",
    )
    # Tamper with snapshot sequence in binary frame (flip byte at offset 4)
    tampered_bytes = bytearray(raw_bytes)
    tampered_bytes[4] ^= 0xFF

    payload = decode_watermark_bytes(bytes(tampered_bytes))
    assert payload is not None
    # Signature verification must fail
    assert payload.signature_valid is False


def test_invisible_watermark_embed_and_extract():
    sample_text = "Summarize the Q3 corporate sales report for the board."
    seq = 4210
    caller = "pod-key-executive"

    assert not has_invisible_watermark(sample_text)

    watermarked_text = embed_invisible_watermark(
        text=sample_text,
        snapshot_sequence=seq,
        caller_key=caller,
    )
    assert has_invisible_watermark(watermarked_text)

    # Visible text remains completely unchanged
    cleaned_visible = watermarked_text.replace("\u200B", "").replace("\u200C", "").replace("\u200D", "")
    assert cleaned_visible == sample_text

    # Extract watermark
    payload = extract_invisible_watermark(watermarked_text)
    assert payload is not None
    assert payload.snapshot_sequence == seq
    assert payload.caller_key == caller
    assert payload.signature_valid is True

    # Multi-line text embedding
    multiline = "Line 1\nLine 2\nLine 3"
    w_multiline = embed_invisible_watermark(multiline, seq, caller)
    assert extract_invisible_watermark(w_multiline) is not None


def test_structural_watermark():
    comment = format_structural_watermark(
        snapshot_sequence=3159,
        caller_key="pod-key-analyst",
    )
    assert '<!-- pod:provenance' in comment
    assert 'seq="3159"' in comment
    assert 'caller="pod-key-analyst"' in comment
    assert 'sig="' in comment


def test_docket_client_watermark_helpers():
    text = "Analyze confidential revenue forecast."
    watermarked = DocketClient.embed_watermark(text, snapshot_sequence=999, caller_key="pod-key-admin")
    extracted = DocketClient.extract_watermark(watermarked)

    assert extracted is not None
    assert extracted["snapshot_sequence"] == 999
    assert extracted["caller_key"] == "pod-key-admin"
    assert extracted["signature_valid"] is True
