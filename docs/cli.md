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

---

## 3. Cryptographic Key Management

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

## 4. Attesting Enterprise Assets

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

## 5. Inspection & Verification

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

## 6. Snapshot Publishing (Zero-DB Deployment)

Publishes a monotonic DSSE snapshot containing all active attestation records. Prevalidator edge proxies poll or receive this snapshot for sub-millisecond in-memory zero-DB lookups:

```bash
docket publish-snapshot \
  --output ./snapshots/active_snapshot.dsse.json \
  --ttl-seconds 3600
```

---

## 7. Lifecycle & Four-Eyes Tier Downgrade

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

## 8. Expiration & Automated Renewal

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
