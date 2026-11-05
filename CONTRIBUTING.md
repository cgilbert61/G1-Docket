# Contributing to G1 Docket

Thank you for your interest in contributing to **G1 Docket by G1163RT Security Labs**! G1 Docket is an enterprise zero-trust cryptographic data attestation engine and AI prevalidation gateway designed for mission-critical inference pipelines.

We welcome contributions from the community, whether reporting bugs, improving documentation, submitting feature enhancements, or optimizing cryptographic verification hot-paths.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Architectural Invariants](#architectural-invariants)
3. [Development Environment Setup](#development-environment-setup)
4. [Testing & Quality Verification](#testing--quality-verification)
5. [Pull Request Workflow](#pull-request-workflow)
6. [Coding Guidelines & Style](#coding-guidelines--style)
7. [Reporting Bugs & Feature Requests](#reporting-bugs--feature-requests)
8. [Security Disclosures](#security-disclosures)

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating in our issues, discussions, or pull requests.

---

## Architectural Invariants

Before writing code for G1 Docket, ensure your changes respect our core architectural invariants (see [Core Architectural Principles](docs/core-architecture.md)):

1. **Zero Database Lookups on the Inference Hot-Path**:
   - The Prevalidator evaluation path (`/v1/chat/completions` and `/v1/messages`) MUST evaluate policies against in-memory snapshots only. No SQL or remote network queries are permitted on the hot path.
2. **Sub-Millisecond Evaluation Latency Budget**:
   - Policy evaluations must execute within a strict latency budget: p50 < 100 μs, p99 < 5.0 ms (see [Benchmarks & Sizing](docs/benchmarks-sizing.md)).
3. **Cryptographic Non-Repudiation**:
   - Attestations must follow the In-Toto v1 Statement specification and be encapsulated in Ed25519 DSSE envelopes (`application/vnd.in-toto+json`).
4. **Append-Only WORM Audit Trail**:
   - Every policy decision, whether allowed, stripped, masked, or quarantined, must produce an immutable audit entry anchored to an HMAC or cryptographic digest.

---

## Development Environment Setup

### Prerequisites

- Python 3.11 or later
- Docker and Docker Compose (v2.20+)
- Git

### Local Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/cgilbert61/G1-Docket.git
   cd G1-Docket
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install the package in editable mode with development dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

4. **Verify container services (Optional for end-to-end testing)**:
   ```bash
   docker compose up -d postgres registry snapshot-publisher prevalidator
   ```

---

## Testing & Quality Verification

All contributions must pass the test suite and conform to formatting standards.

### Running Unit & Integration Tests

```bash
# Run all unit tests
pytest

# Run tests with coverage report
pytest --cov=docket --cov=engine --cov=prevalidator tests/

# Run multi-region federation tests
pytest tests/test_federation.py
```

### Running the End-to-End Governance Verification

```bash
python examples/simulate_enterprise_governance.py
```

### Code Formatting & Linting

We enforce clean, standard Python code style using `ruff`:

```bash
# Run linter checks
ruff check .

# Format code
ruff format .
```

---

## Pull Request Workflow

1. **Create a branch**:
   Use descriptive branch naming conventions:
   - `feat/feature-name`
   - `fix/bug-description`
   - `docs/doc-update`
   - `perf/hotpath-optimization`

2. **Commit your changes**:
   Write clear, concise commit messages following Conventional Commits:
   ```bash
   git commit -m "feat(prevalidator): optimize in-memory radix lookup for wildcards"
   ```

3. **Rebase against `main`**:
   Ensure your branch is rebased cleanly on latest `main`:
   ```bash
   git fetch origin
   git rebase origin/main
   ```

4. **Push and open a Pull Request**:
   Push your branch to your fork and submit a PR against `cgilbert61/G1-Docket:main`.
   Fill out the provided [Pull Request Template](.github/pull_request_template.md).

---

## Coding Guidelines & Style

- **Type Hints**: All new functions and public methods MUST include full Python type annotations (`typing` / built-in generics).
- **Light-First Institutional UI Theme**: For frontend changes (`prevalidator/templates/` or `governance/templates/`), strictly follow the institutional theme rules:
  - Background: Slate-50 (`#F8FAFC`), Cards: `#FFFFFF`, Text: Slate-900 (`#0F172A`).
  - No dark-mode defaults, gradients, floating decorative blobs, or hover-scale animations.
  - Numbers and metrics must use `font-variant-numeric: tabular-nums` or monospace font.
- **Documentation**: If adding or altering public APIs, client SDK functions, or configuration parameters, update the corresponding documentation in `docs/` and `README.md`.

---

## Reporting Bugs & Feature Requests

- **Bug Reports**: Please open an issue using the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md). Include reproducible code snippets, environment details, and relevant logs.
- **Feature Requests**: Open an issue using the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md) describing the business context, proposed architectural fit, and expected behavior.

---

## Security Disclosures

Do **NOT** report security vulnerabilities via public GitHub issues. Please follow our [Security Policy](SECURITY.md) to report vulnerabilities privately to our security team.
