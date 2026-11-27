# G1-Docket Empirical Fuzz Testing Report

- **Generated:** `2026-11-27T15:10:51Z`
- **Environment:** Docker `python:3.11-slim` (`g1-docket-fuzz:latest`), `pytest 9.2.0`, `hypothesis 6.170.20`, `atheris 3.0.0`
- **Repository:** `D:\attestation` (`cgilbert61/G1-Docket`)

## Fuzzer Execution Matrix

| Fuzzer | Scope | Status | Empirical Result |
| :--- | :--- | :--- | :--- |
| **Hypothesis** (`fuzz/test_hypothesis_fuzz.py`) | 6 property-based fuzz targets (`verify_dsse_envelope`, schema validators, canonical text & chunk hashing, `PresidioClassifier`, `parse_iso8601`) | `EXECUTED` | **6/6 targets PASS** (`720` generated examples, `0` failures) |
| **Atheris** (`fuzz/atheris_harnesses/`) | 2 coverage-guided `libFuzzer` harnesses (`fuzz_dsse_verify.py`, `fuzz_text_and_classifier.py`) | `EXECUTED` | **2/2 harnesses PASS** (`4,000` libFuzzer runs — 2,000 each — `0` crashes) |

## Running Locally

```powershell
docker build -f fuzz/Dockerfile.atheris -t g1-docket-fuzz:latest .
docker run --rm g1-docket-fuzz:latest
```
