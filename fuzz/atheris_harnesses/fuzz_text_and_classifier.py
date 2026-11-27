"""Atheris coverage-guided fuzzer for G1-Docket text normalization, chunk hashing & classifier."""

import sys

import atheris

with atheris.instrument_imports():
    from engine.classifier import PresidioClassifier
    from registry.signing import (
        compute_extracted_text_and_chunk_hashes,
        normalize_canonical_text,
    )

_CLASSIFIER = PresidioClassifier()


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(512)
    norm = normalize_canonical_text(text)
    assert b"\r" not in norm
    digest, chunks = compute_extracted_text_and_chunk_hashes(text)
    assert len(digest) == 64 and len(chunks) <= 256
    _CLASSIFIER.scan_text_segment(text)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
