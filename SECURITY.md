# Security Policy

At **G1163RT Security Labs**, the security, cryptographic integrity, and forensic non-repudiation of **G1 Docket** are foundational to our mission. We take all potential security vulnerabilities seriously and appreciate the contributions of researchers, operators, and the security community.

---

## Supported Versions

We provide security updates and patches for the following versions of G1 Docket:

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `0.2.x` | :white_check_mark: | Current active release branch (`main`) |
| `0.1.x` | :white_check_mark: | Critical cryptographic & CVE patches only |
| `< 0.1.0` | :x: | Unsupported prototype releases |

---

## Reporting a Vulnerability

**Please do NOT file public GitHub issues for suspected security vulnerabilities.**

To report a vulnerability responsibly:

1. **Email Coordinated Disclosure**:
   Send details of the vulnerability to:
   - **`security@g1163rt.com`**
   - Subject: `[SECURITY] G1 Docket Vulnerability Report - <Brief Summary>`

2. **GitHub Private Security Advisory**:
   Alternatively, use GitHub's private vulnerability reporting feature on our repository:
   - Navigate to the **Security** tab of [cgilbert61/G1-Docket](https://github.com/cgilbert61/G1-Docket/security).
   - Click **Report a vulnerability** to open a confidential advisory draft.

### Information to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A descriptive summary of the vulnerability and its potential impact.
- Affected component(s) (e.g., Prevalidator Gateway `:18082`, Engine `:18083`, Governance Triage `:18084`, Registry `:18080`, or Client SDK).
- Clear, step-by-step instructions or a minimal reproducible proof-of-concept (PoC).
- Any known mitigations or remediation suggestions.
- Your preferred name or handle for security advisory credit.

---

## Vulnerability Handling & Response Process

Once a vulnerability report is received, our security team follows this coordinated process:

1. **Acknowledgment**: We acknowledge receipt of your report within **24 hours**.
2. **Initial Triage**: We assess the severity, reproduce the issue, and provide an initial assessment within **72 hours**.
3. **Remediation & Patching**: We develop and test a corrective patch within a private branch.
4. **Coordinated Disclosure**: We coordinate the public release date with you. Once the patch is merged and released, we publish a GitHub Security Advisory (GHSA) and credit the reporter.

---

## Core Security Invariants

When evaluating potential vulnerabilities, keep in mind G1 Docket's architectural trust boundaries:

1. **DSSE Cryptographic Envelopes**:
   - Attestations are signed with Ed25519 asymmetric keys. A tampering attacker without private signing keys must not be able to forge or tamper with an attestation statement.
2. **Zero-Trust Hot-Path Isolation**:
   - The Prevalidator evaluation engine evaluates objects strictly against cryptographically verified in-memory snapshots (`pod_snapshot.dsse.json`). Compromise of an external database must not alter hot-path admission decisions.
3. **Four-Eyes Dual-Key Quorum**:
   - Quarantined payloads cannot be released by a single actor; release requires a distinct authorized secondary approver identity and generates an immutable `HITL_DUAL_KEY_RELEASE` WORM record.
4. **Append-Only WORM Ledger**:
   - Forensic provenance records and audit logs are append-only. Modifying historical WORM records constitutes an integrity violation.

---

## Responsible Disclosure & Safe Harbor

We commit to not pursuing legal action against security researchers who:
- Make a good-faith effort to avoid privacy violations, destruction of data, or interruption of production services.
- Keep the details of any discovered vulnerabilities confidential until coordinated public disclosure.
- Act in accordance with applicable laws and do not engage in extortion, blackmail, or unauthorized data exfiltration.

Thank you for helping keep G1 Docket secure!
