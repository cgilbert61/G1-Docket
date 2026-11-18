# G1 Docket System Security Plan (SSP)

**System Name:** G1 Docket Data Attestation Framework & Zero-DB-Call Prevalidator  
**FISMA ID:** G1-DOCKET-001  
**Assessment Platform:** GovReady-Q (v0.9.1)  
**Baseline Catalog:** NIST SP 800-53 Rev 4  
**Date:** 2026-11-18 21:57:12 UTC  

## Executive Summary

Enterprise cryptographic data attestation engine and zero-DB-call AI gateway prevalidator enforcing in-flight LLM governance.

## Control Implementation Summaries

### AC-3: Access Enforcement

- **Family:** Access Control
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer.evaluate_request() & resolve_caller_clearance()`

**Implementation Narrative:**

G1 Docket prevalidator (prevalidator/enforcer.py) intercepts all model prompt traffic (/v1/chat/completions, /v1/messages) in-memory before reaching upstream LLMs. It resolves caller clearance from verified JWT tokens (X-POD-Caller-Token) or API keys, evaluates presented object locators against active signed snapshots, and enforces minimum clearance thresholds with zero database calls. Violations result in deterministic uniform denials without policy leakage.

### AC-4: Information Flow Enforcement

- **Family:** Access Control
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer.resolve_target_egress() & custom_policy_hooks`

**Implementation Narrative:**

Enforces destination egress classes (internal_only vs commercial_cloud) mapped to target models. Data attested above Public tier is strictly prevented from egressing to commercial LLM routes (EGRESS_DENIED). Custom ABAC hooks enforce departmental isolation and data residency boundaries based on caller and object jurisdiction.

### AU-2: Audit Events

- **Family:** Audit and Accountability
- **Status:** Implemented
- **Enforcement Mechanism:** `AuditLogEntry dataclass & PrevalidatorEnforcer.audit_log`

**Implementation Narrative:**

Every admission evaluation produces an immutable AuditLogEntry containing timestamp, mode (enforce/observe), decision (allow/strip/mask/deny), reason codes, locators evaluated, caller clearance, egress class, caller identity, and sub-millisecond decision latency (decision_latency_ms, decision_latency_us).

### AU-9: Protection of Audit Information

- **Family:** Audit and Accountability
- **Status:** Implemented
- **Enforcement Mechanism:** `WormAuditLedger & SHA-256 tamper-evident block linking`

**Implementation Narrative:**

Audit records are serialized and committed to an append-only WORM (Write Once Read Many) cryptographic audit ledger (governance/worm_ledger.py). Log entries cannot be overwritten, modified, or deleted without breaking cryptographic hash chains.

### AU-10: Non-repudiation

- **Family:** Audit and Accountability
- **Status:** Implemented
- **Enforcement Mechanism:** `registry/signing.py verify_dsse_envelope() & Keyring`

**Implementation Narrative:**

Attestation records and published snapshots are sealed using DSSE (Dead Simple Signing Envelope) specifications with Ed25519 digital signatures. Keys are bound to verified key IDs and keyrings, ensuring non-repudiation of all issued attestations.

### SC-8: Transmission Confidentiality and Integrity

- **Family:** System and Communications Protection
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer._verify_inner_text_cryptographically()`

**Implementation Narrative:**

In-flight transmission integrity is enforced by matching live SHA-256 digests of <pod:object> inner content against the cryptographically attested content_sha256 or Merkle chunk proofs. In-flight tampering or hash drift triggers REASON_HASH_MISMATCH and immediate request denial.

### SC-12: Cryptographic Key Establishment and Management

- **Family:** System and Communications Protection
- **Status:** Implemented
- **Enforcement Mechanism:** `Keyring & POD_DELEGATE_VERIFY_KEY separation`

**Implementation Narrative:**

Strict cryptographic key isolation is enforced. Data plane prevalidator gateways maintain verification-only public keys (POD_DELEGATE_VERIFY_KEY, Keyring verify keys). Private signing keys reside strictly within control plane registry services or hardware KMS modules, preventing key extraction from gateway processes.

### SC-13: Cryptographic Protection

- **Family:** System and Communications Protection
- **Status:** Implemented
- **Enforcement Mechanism:** `cryptography.hazmat.primitives.asymmetric.ed25519 & hashlib.sha256`

**Implementation Narrative:**

Uses FIPS-compatible and modern cryptographic primitives: RFC-8032 Ed25519 asymmetric signatures, RFC-009 Merkle Chunk Trees (MCT), and SHA-256 cryptographic hashes for whole-object and chunk-level integrity verification.

### SI-7: Software, Firmware, and Information Integrity

- **Family:** System and Information Integrity
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer tag parser, PresidioClassifier & untagged quota`

**Implementation Narrative:**

Detects and blocks prompt smuggling, XML tag tampering, and unverified data injection. Untagged-context quotas prevent context flooding (REASON_UNATTESTED_CONTEXT_OVERFLOW). Presidio DLP classifier operates as a defense-in-depth fallback to mask unclassified sensitive data entities ([MASKED_*]) on allowed paths.

### IA-2: Identification and Authentication (organizational Users)

- **Family:** Identification and Authentication
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer.resolve_caller_clearance() & resolve_caller_context()`

**Implementation Narrative:**

Gateway callers are authenticated via signed JWT tokens (X-POD-Caller-Token) containing verified subject, clearance, department, and owner claims, or authenticated caller API keys (X-POD-Caller-Key). In auth-enforced production mode, anonymous or unowned agent requests are rejected with UNOWNED_AGENT_BLOCKED.

### IA-8: Identification and Authentication (non-organizational Users)

- **Family:** Identification and Authentication
- **Status:** Implemented
- **Enforcement Mechanism:** `docket/integrations.py wrap_delegated_context() & PrevalidatorEnforcer.process_delegates()`

**Implementation Narrative:**

Multi-agent autonomous delegation chains (<pod:delegate>) are cryptographically signed at each hop with Ed25519 signatures over canonical UTF-8 strings. The chain cryptographically binds all intermediate agent hops back to a verified human root accountable owner, enforcing monotonic non-escalating clearance tiers.

### CA-7: Continuous Monitoring

- **Family:** Security Assessment and Authorization
- **Status:** Implemented
- **Enforcement Mechanism:** `PrevalidatorEnforcer.generate_prometheus_metrics() & delta crawler`

**Implementation Narrative:**

Provides real-time Prometheus telemetry (/metrics) exposing total evaluations, policy denials by reason code, and decision duration percentiles (P50, P95, P99). Continuous Delta Crawler polls underlying data stores for document updates, automatically revoking stale attestation records upon content drift.

