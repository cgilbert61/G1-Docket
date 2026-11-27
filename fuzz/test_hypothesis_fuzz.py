"""Property-based fuzzing suite for G1-Docket using Hypothesis.

Exercises G1-Docket's untrusted-input boundaries:
- DSSE v1 envelope verification (fail-closed, no unhandled exceptions)
- JSON Schema & semantic tier/TTL validation (attestation, snapshot, DSSE)
- Canonical text normalization & deterministic chunk hashing
- Presidio/regex sensitive content classification (never crashes, never leaks raw PII)
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from engine.classifier import PresidioClassifier
from registry.schema_validator import (
    DSSE_PAYLOAD_TYPE,
    SchemaValidationError,
    parse_iso8601,
    validate_attestation_predicate,
    validate_dsse_envelope_structure,
    validate_snapshot_predicate,
)
from registry.signing import (
    Keyring,
    SignatureVerificationError,
    compute_extracted_text_and_chunk_hashes,
    normalize_canonical_text,
    verify_dsse_envelope,
)

_TMP_KEYRING_DIR = Path(tempfile.mkdtemp(prefix="docket_fuzz_keys_"))
_KEYRING = Keyring(_TMP_KEYRING_DIR)
_KEYRING.ensure_active_key()
_CLASSIFIER = PresidioClassifier()

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10**9, max_value=10**9),
    st.text(max_size=64),
)
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.lists(children, max_size=5)
    | st.dictionaries(st.text(max_size=24), children, max_size=5),
    max_leaves=15,
)

_SETTINGS = settings(
    max_examples=120,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@_SETTINGS
@given(envelope=_JSON_VALUES)
def test_fuzz_verify_dsse_envelope_fails_closed(envelope):
    """Arbitrary objects must fail closed with SignatureVerificationError."""
    with pytest.raises(SignatureVerificationError):
        verify_dsse_envelope(envelope, _KEYRING)


@_SETTINGS
@given(
    payload_bytes=st.binary(max_size=256),
    sig_bytes=st.binary(max_size=128),
    keyid=st.text(max_size=32),
)
def test_fuzz_verify_dsse_structured_forgeries_rejected(payload_bytes, sig_bytes, keyid):
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [
            {
                "keyid": keyid,
                "sig": base64.b64encode(sig_bytes).decode("ascii"),
            }
        ],
    }
    with pytest.raises(SignatureVerificationError):
        verify_dsse_envelope(envelope, _KEYRING)


@_SETTINGS
@given(obj=st.dictionaries(st.text(max_size=24), _JSON_SCALARS, max_size=8))
def test_fuzz_schema_validators_fail_cleanly(obj):
    for fn in (
        validate_attestation_predicate,
        validate_snapshot_predicate,
        validate_dsse_envelope_structure,
    ):
        try:
            fn(obj)
        except SchemaValidationError:
            pass


@_SETTINGS
@given(text=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=600))
def test_fuzz_canonical_text_and_chunk_hashes_deterministic(text):
    norm1 = normalize_canonical_text(text)
    norm2 = normalize_canonical_text(text)
    assert norm1 == norm2
    assert b"\r" not in norm1

    h1, chunks1 = compute_extracted_text_and_chunk_hashes(text)
    h2, chunks2 = compute_extracted_text_and_chunk_hashes(text)
    assert h1 == h2 and chunks1 == chunks2
    assert len(h1) == 64
    assert len(chunks1) <= 256


@_SETTINGS
@given(text=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=400))
def test_fuzz_classifier_never_crashes_and_returns_counts_only(text):
    findings = _CLASSIFIER.scan_text_segment(text)
    for f in findings:
        assert f.count >= 1
        assert 0.0 <= f.max_confidence <= 1.0


@_SETTINGS
@given(ts=st.text(max_size=40))
def test_fuzz_parse_iso8601_handles_arbitrary_strings(ts):
    try:
        dt = parse_iso8601(ts)
        assert dt.tzinfo is not None
    except ValueError:
        pass
