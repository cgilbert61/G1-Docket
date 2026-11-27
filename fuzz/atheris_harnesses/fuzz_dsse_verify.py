"""Atheris coverage-guided fuzzer for G1-Docket DSSE envelope verification."""

import base64
import json
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from registry.schema_validator import DSSE_PAYLOAD_TYPE
    from registry.signing import Keyring, SignatureVerificationError, verify_dsse_envelope

_KEYRING = Keyring(Path(tempfile.mkdtemp(prefix="docket_atheris_keys_")))
_KEYRING.ensure_active_key()


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 1)
    if mode == 0:
        try:
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(256))
        except Exception:
            return
    else:
        obj = {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(fdp.ConsumeBytes(256)).decode("ascii"),
            "signatures": [
                {
                    "keyid": fdp.ConsumeUnicodeNoSurrogates(24),
                    "sig": base64.b64encode(fdp.ConsumeBytes(64)).decode("ascii"),
                }
            ],
        }
    try:
        verify_dsse_envelope(obj, _KEYRING)
        raise AssertionError("Untrusted fuzzed DSSE envelope unexpectedly verified!")
    except SignatureVerificationError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
