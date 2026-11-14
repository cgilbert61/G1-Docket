# Enterprise Governance Configuration and Implementation Record

This document records the enterprise configuration, steward routing architecture, and production hardening procedures implemented in **G1 Docket**. It serves as an authoritative reference for compliance officers, SecOps engineers, and platform administrators transitioning G1 Docket from local demonstration/evaluation mode into production operations.

---

## 1. Architectural Overview & Separation of Concerns

G1 Docket supports dual-mode operation toggled by environment variables:

| Operating Mode | Primary Variable | Characteristics |
| :--- | :--- | :--- |
| **Demo Mode** | `DOCKET_ENVIRONMENT=demo`<br>`DOCKET_DEMO_MODE=true` | In-memory/ephemeral keyrings, synthetic demo directories (`pc_demo_folder/`), 1-click dual signoff HITL triage shortcuts, and mock identity fallbacks. |
| **Production Mode** | `DOCKET_ENVIRONMENT=production`<br>`DOCKET_DEMO_MODE=false` | Strict enterprise steward routing, cloud catalog tag ingestion (Databricks, Snowflake, Purview), OIDC/SAML JWT identity extraction, HSM/KMS keyrings (GCP Cloud KMS, AWS KMS, HashiCorp Vault), and SIEM audit streaming. |

---

## 2. Placeholder Address Remediation

All legacy hardcoded placeholder addresses (`@contoso.com`, `@example.org`) have been eliminated in favor of dynamic resolvers with environment overrides:

### A. Attestation Registry (`registry/signing.py`)
- Hardcoded email tables replaced by dynamic `get_effective_steward(tier, explicit_steward)`:
  - Resolves from `DOCKET_STEWARD_RESTRICTED`, `DOCKET_STEWARD_CONFIDENTIAL`, `DOCKET_STEWARD_INTERNAL`, and `DOCKET_STEWARD_PUBLIC`.
  - Fallbacks default to `DOCKET_DEFAULT_STEWARD` and `DOCKET_COMPANY_DOMAIN`.
- Asset ownership resolves from catalog hints or `DOCKET_DEFAULT_OWNER`.

### B. Scanner & Crawler Engines (`engine/pipeline.py`, `engine/service.py`)
- `crawl_file_share`, `crawl_database`, and `AttestDirectoryRequest` now pull default owners dynamically from `os.getenv("DOCKET_DEFAULT_OWNER", "data-operations@yourcompany.com")` rather than static mock strings.

### C. Cloud Storage Connectors (`engine/storage_connectors.py`)
- Cloud warehouse connectors dynamically extract native owner tags:
  - **Snowflake**: Maps `COMMENT` or `TAG:steward` to `ownership.steward`.
  - **Databricks Unity Catalog**: Maps `Table.owner` to `ownership.owner`.
  - **Microsoft Purview**: Maps `Experts` and `Owners` attributes to attestation predicates.

---

## 3. Configuration Reference

### Environment Variables (`.env`)

```bash
# ==============================================================================
# Enterprise Governance & Data Steward Configuration
# ==============================================================================
# Mode Switcher: 'production' disables demo shortcuts, mock approvers, and local fallbacks
DOCKET_ENVIRONMENT=production
DOCKET_DEMO_MODE=false

# Corporate Identity & Organization Defaults
DOCKET_COMPANY_DOMAIN=yourcompany.com
DOCKET_DEFAULT_ORG_UNIT="Enterprise Data & AI Governance"
DOCKET_DEFAULT_OWNER="data-operations@yourcompany.com"
DOCKET_DEFAULT_STEWARD="governance-team@yourcompany.com"

# Tier-Based Steward Routing (Distribution Lists or Security Mailboxes)
DOCKET_STEWARD_RESTRICTED="privacy-compliance@yourcompany.com"
DOCKET_STEWARD_CONFIDENTIAL="infosec-stewards@yourcompany.com"
DOCKET_STEWARD_INTERNAL="data-engineering@yourcompany.com"
DOCKET_STEWARD_PUBLIC="open-data@yourcompany.com"

# Production Storage & Crawl Targets
DOCKET_CRAWL_DIRECTORY="\\\\corp.local\\shares\\analytics\\lakehouse"
POD_REGISTRY_DB_URL="postgresql://docket_admin:SecureSecret@db.corp.local:5432/docket_production"
WORM_JSONL_PATH="/var/log/docket/audit_worm.jsonl"

# Hardware Security Module / Cloud KMS Signing
POD_KEY_DIR="/var/run/secrets/docket_keys"
POD_KMS_TYPE="gcp"
GCP_KMS_KEY_URI="gcpkms://projects/prod-sec/locations/us-central1/keyRings/docket-ring/cryptoKeys/attestation-key"

# Upstream LLM Inference Gateway & API Auth
POD_UPSTREAM_GATEWAY_URL="https://gateway.ai.corp.local"
POD_ADMIN_API_KEY="sk-live-docket-admin-enterprise-key-here"
POD_CONTROL_PLANE_TOKEN="docket-cplane-jwt-here"
```

---

## 4. Production Security Hardening

### A. Four-Eyes Principle & SSO Identity Binding
- In `governance/triage_server.py`, the Human-in-the-Loop (HITL) approval endpoint verifies:
  1. `requester_id` != `approver_id` (cryptographically enforces two distinct human reviewers).
  2. Identity claims are extracted from verified headers injected by corporate reverse proxies / API gateways:
     - `X-Forwarded-Email`
     - `CF-Access-Authenticated-User-Email`
     - Bearer JWT `email` / `upn` claims.
- When `DOCKET_DEMO_MODE=false`, the **"1-Click Dual Signoff & Replay"** and **"Autofill Demo Approver"** buttons in `governance/templates/components/modal_triage.html` are suppressed.

### B. Pre-Flight Configuration Verification Script
The repository provides an automated environment checker:

```bash
# Verify current environment posture
python scripts/check_mode.py
```

The script conducts automated checks:
- Mode detection (`DEMO` vs `PRODUCTION`).
- Keyring integrity and KMS path accessibility.
- Placeholder credential detection (flags default tokens or `@example.org` emails in production mode).
- Upstream gateway and database URI validations.

---

## 5. Verification & Conformance Sign-Off

The complete system undergoes regression testing via the unified 22-phase verification runner:

```bash
python scripts/run_all_verifications.py
```

- **All 22 Verification Phases**: **PASSED (100% Green)**
- **GitHub Actions CI Matrix (Python 3.11, 3.12, 3.13, Helm)**: **PASSED (Run `43533690251`)**
- **Repository Credential Audit**: **0 Live Secrets Detected**
