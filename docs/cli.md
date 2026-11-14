# G1 Docket — Operator Command-Line Interface (`docket` / `pod`)

The G1 Docket CLI (`docket` or `pod`) provides full operational control over cryptographic key management, automated and on-demand attestation crawling, real-time snapshot publication, and authoritative lifecycle actions.

---

## 1. Installation & Binary Aliasing

The CLI is automatically installed when setting up G1 Docket:

```bash
pip install -e .
```

Both `docket` and `pod` binaries are registered and execute identically.

```bash
docket --help
# or
pod --help
```

---

## 2. Command Overview

| Command | Category | Description |
| :--- | :--- | :--- |
| **`keygen`** | Key Management | Generate or rotate Ed25519 / ECDSA operator signing keys |
| **`attest`** | Attestation | Discover, classify, and sign attestation records for files, folders, or databases |
| **`lookup`** | Inspection | Fetch the active attestation statement for a canonical locator URI |
| **`verify`** | Cryptography | Verify Ed25519 DSSE envelopes against public keys and on-disk files |
| **`publish-snapshot`**| Snapshots | Export a monotonic DSSE-signed snapshot for Prevalidator ingestion |
| **`list-expiring`** | Governance | Query records reaching their expiration horizon within $N$ days |
| **`renew`** | Governance | Extend record validity if content SHA-256 fingerprint remains unchanged |
| **`raise-tier`** | Policy | Immediately elevate an asset's classification tier (`Confidential`, `Restricted`) |
| **`lower-tier`** | Policy | Downgrade tier with dual-approver four-eyes cryptographic sign-off |
| **`revoke`** | Policy | Immediately revoke an attestation record |
| **`review-list`** | HITL | List pending human review triage items |
| **`review-approve`** | HITL | Approve and finalize classification for an object in review |
| **`doctor`** | Diagnostics | Probe cluster endpoints, check latencies, and audit WORM chain |
| **`login`** | Authentication | Authenticate operator credentials with optional RFC 6238 TOTP 2FA |
| **`whoami`** | Authentication | Inspect active operator session, roles, and expiration horizon |
| **`logout`** | Authentication | Revoke active session token locally and against governance server |
| **`watermark-inspect`** | Forensics | Extract and verify cryptographic provenance watermark from text or file |
| **`watermark-embed`** | Forensics | Embed an invisible zero-width cryptographic watermark into a file |

---

## 3. Cluster Diagnostics (`doctor`)

Probe all core services across the admission control cluster, inspect active posture, and audit the cryptographic WORM Merkle chain in a single command:

```bash
docket doctor
# or
pod doctor
```

Example Output:
```text
======================================================================
                 G1 DOCKET CLUSTER HEALTH & DIAGNOSTICS               
======================================================================
 [PASS] Prevalidator Gateway       -> Online (mode=enforce, seq=2998) [477.6ms]
 [PASS] Governance & SIEM          -> Online (worm_events=134, quarantine=72) [6.3ms]
 [PASS] Authoritative Registry     -> Online [38.1ms]
 [PASS] Snapshot Publisher         -> Online [25.5ms]
----------------------------------------------------------------------
 [PASS] WORM Audit Merkle Chain    -> Valid (134 events verified) [20.7ms]
======================================================================
 [OK] All cluster admission control services are operational.
```

---

## 4. Cryptographic Key Management

### Generate Initial Operator Keypair
```bash
docket keygen --algorithm Ed25519 --key-dir ./.pod_keys
```

### Rotate Operator Signing Key
Rotates the active private key while preserving public keys in the keyring to verify historical signatures:
```bash
docket keygen --rotate --key-dir ./.pod_keys
```

---

## 5. Attesting Enterprise Assets

### Attest a Single File
```bash
docket attest ./reports/q3_earnings.docx \
  --owner "cfo@company.org" \
  --output ./attestation_q3.dsse.json
```

### Attest a Local Directory Share
Recursively inspects scannable files, applies DLP classifiers, registers records, and emits signed DSSE statements:
```bash
docket attest /shared/legal_docs \
  --owner "legal-ops@company.org"
```

### Attest a Database Table
```bash
docket attest "postgresql://user:pass@db:5432/corp_data" \
  --owner "data-eng@company.org" \
  --locator "postgres://db:5432/corp_data/finance_ledger"
```

---

## 6. Inspection & Verification

### Look Up Current Attestation State
```bash
docket lookup "file:///shared/legal_docs/master_services_agreement.pdf"
```

### Cryptographically Verify DSSE Envelope
Validates the Ed25519 signature against the active keyring and confirms the SHA-256 digest matches the physical file:
```bash
docket verify ./attestation_q3.dsse.json \
  --file ./reports/q3_earnings.docx
```

---

## 7. Snapshot Publishing (Zero-DB Deployment)

Publishes a monotonic DSSE snapshot containing all active attestation records. Prevalidator edge proxies poll or receive this snapshot for sub-millisecond in-memory zero-DB lookups:

```bash
docket publish-snapshot \
  --output ./snapshots/active_snapshot.dsse.json \
  --ttl-seconds 3600
```

---

## 8. Lifecycle & Four-Eyes Tier Downgrade

### Immediately Raise Classification Tier
Elevates security tier to block unauthorized model egress immediately:
```bash
docket raise-tier "s3://lake/hr/payroll.csv" Restricted
```

### Lower Classification Tier (Four-Eyes Dual Approver Required)
To prevent accidental declassification or malicious downgrades, lowering a tier requires at least two distinct authorized approver identities:
```bash
docket lower-tier "s3://lake/hr/payroll.csv" Confidential \
  --approver "sec-lead@company.org" \
  --approver "ciso@company.org" \
  --rationale "PII columns masked and verified"
```

### Revoke an Attested Object
Immediately renders the object `REVOKED` in subsequent snapshots:
```bash
docket revoke "s3://lake/temp/dump.sql" \
  --reason "Contains unmasked test credentials"
```

---

## 9. Expiration & Automated Renewal

### List Records Expiring Soon
```bash
docket list-expiring --within-days 14
```

### Renew Record on Unchanged Digest
Extends the attestation period if the observed hash matches the original signature:
```bash
docket renew "file:///shared/legal_docs/master_services_agreement.pdf" \
  --file /shared/legal_docs/master_services_agreement.pdf
```

---

## 10. Forensic Watermarking & Provenance Attribution

### Inspect Text or File for Cryptographic Watermark
Detects invisible zero-width Unicode steganography (`\u200B`, `\u200C`, `\u200D`) or structural XML comments, validates the HMAC-SHA256 signature against the gateway secret, and outputs JSON attribution metadata:

```bash
docket watermark-inspect "Leaked customer report text..."
# Or from a file:
docket watermark-inspect /path/to/suspicious_transcript.txt
```

Example JSON Output:
```json
{
  "inspected_target": "/path/to/suspicious_transcript.txt",
  "watermark_found": true,
  "format": "invisible_steganography",
  "version": 1,
  "snapshot_sequence": 3168,
  "timestamp_epoch": 1793829946,
  "timestamp_iso": "2026-11-04T22:05:46+00:00",
  "caller_key": "pod-key-analyst",
  "signature": "ca9957d2f03d94ee",
  "signature_valid": true
}
```

### Embed Invisible Watermark into a File
Binds a document to the active DSSE snapshot sequence number and caller identity without modifying its visual appearance:

```bash
docket watermark-embed confidential_memo.md \
  --caller-key pod-key-analyst \
  --output watermarked_memo.md
```

---

## 11. Environment Mode & Governance Audit (`check_mode`)

G1 Docket distinguishes between **Demo** and **Production** environments using `DOCKET_ENVIRONMENT` (or legacy `DOCKET_DEMO_MODE`).

To audit the active environment mode, operational safeguards, and Dual-Key governance enforcement:

```bash
python scripts/check_mode.py
```

Or select **Option 25** in the interactive menu (`python scripts/interactive_menu.py`).

### Environmental Safeguards Comparison:

| Policy Enforcement | Demo Mode (`demo`) | Production Mode (`production`) |
| :--- | :--- | :--- |
| **SSO & Operator Auth** | Permissive (allows `demo-analyst`, `demo-steward`) | Strict: Enforces corporate IdP SSO subject matching |
| **Four-Eyes Dual-Key** | Single-key simulated review permitted | Strict: Self-approvals (`key1 == key2`) or mock identities blocked |
| **WORM Audit Trail** | Memory / Local SQLite ledger | Immutable append-only SQLite/PostgreSQL with Merkle chaining |
| **Cluster Health Indicator** | Marked with `[DEMO - NON-ENFORCING]` badges | Institutional production assertion |

---

## 12. Operator Authentication & Session Management (`login`, `whoami`, `logout`)

The CLI commands `login`, `whoami`, and `logout` provide zero-trust session management for cluster operators interacting with the G1 Docket Governance and Triage subsystem.

### Authenticate an Operator Session (`login`)
Prompts for password securely and accepts an optional 6-digit RFC 6238 TOTP hardware/authenticator code:

```bash
docket login --username admin --endpoint http://127.0.0.1:8000
# or with TOTP code
docket login --username admin --totp 123456
```

Upon successful PBKDF2 verification, an HMAC-SHA256 signed session token is minted and persisted with restricted permissions (`0600`) to `~/.docket/session.json`.

### Inspect Active Operator Identity (`whoami`)
Displays the authenticated operator's username, assigned RBAC roles, target endpoint, and session validity status:

```bash
docket whoami
```

Example Output:
```text
Authenticated Operator: admin
Roles: admin, triage_operator, security_approver
Server Endpoint: http://127.0.0.1:8000
Session Token: 4668ba454a8e...
Status: ACTIVE (Sliding 30-minute idle window)
```

### Revoke Session (`logout`)
Terminates the active session both locally (removing `~/.docket/session.json`) and notifies the Governance server to cryptographically append an `OPERATOR_LOGOUT` audit record to the WORM Merkle ledger:

```bash
docket logout
```

---

## 13. Cryptographic Key Re-Signing (`resign-records`)

When rotating an authoritative signing key or migrating to a dedicated Hardware Security Module (HSM) / Cloud KMS key, the `resign-records` command re-signs active attestation statements without altering record metadata:

```bash
docket resign-records --keyid "key-2026-q4-hsm"
# or re-sign only records created under an older key ID:
docket resign-records --keyid "key-2026-q4-hsm" --only-older-than-key "key-2026-q3-legacy"
```

Each re-signed record receives a newly countersigned In-Toto v1 DSSE envelope, preserving full provenance history in the WORM audit trail.

---

## 14. Compliance Evidence Packaging (`export-evidence`)

Generates a cryptographically sealed SOC 2 Type II audit evidence bundle containing immutable WORM Merkle chains, verification certificates, and Audit Runway exit criteria telemetry:

```bash
docket export-evidence --output-dir ./audit_evidence_bundles
```

The resulting `.zip` bundle includes a top-level `MANIFEST_SHA256.json` and can be verified offline and in air-gapped environments using:

```bash
python scripts/docket_verify_standalone.py audit_evidence_bundles/G1_DOCKET_SOC2_EVIDENCE_YYYYMMDD_HHMMSS.zip
```




