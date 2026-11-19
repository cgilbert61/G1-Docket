# Unified Authentication & Access Control (RBAC) Guide

**G1 Docket & Combine Governance Subsystem (`v4.0.0`)**  
*Document Version: 1.0.0 — G1163RT Security Labs*

---

## 1. Architectural Overview & Single Sign-On (SSO)

G1 Docket implements a **Unified Session Authentication Engine** built on salted PBKDF2-HMAC-SHA256 password hashing, HMAC-SHA256 signed session tokens, sliding inactivity timeouts, brute-force rate-limiting, and Role-Based Access Control (RBAC).

Both core web interfaces share this unified authentication architecture:
- **Prevalidator Gateway & Policy Console**: `http://localhost:18082`
- **HITL Governance, WORM Ledger & SIEM Console**: `http://localhost:18084`

```
 ┌────────────────────────────────────────────────────────┐
 │                   Corporate Operator                   │
 └───────────────────────────┬────────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │  Unified Browser Cookie / SSO   │
            │      "docket_session"           │
            └────────┬───────────────┬────────┘
                     ▼               ▼
         ┌───────────────────┐   ┌───────────────────┐
         │    Port :18082    │   │    Port :18084    │
         │   Prevalidator    │   │    Governance     │
         │ Gateway & Console │   │ Console & Ledger  │
         └─────────┬─────────┘   └─────────┬─────────┘
                   │                       │
                   └───────────┬───────────┘
                               ▼
               Shared Session Signing Secret
               (DOCKET_SESSION_SECRET env /
                .pod_keys/governance_session_secret.key)
```

### Key Architectural Properties:
1. **Bidirectional Single Sign-On (SSO)**:
   - Both consoles run under the shared host domain (`localhost` or your corporate subdomain `*.corp.internal`).
   - Authenticating on port `18082` issues an HTTP-only `docket_session` cookie valid for all services on the domain. Navigating to port `18084` recognizes the operator seamlessly without requiring a second sign-in, and vice versa.
2. **Machine-to-Machine (M2M) Exemption**:
   - AI agent frameworks (LangChain, LlamaIndex, CrewAI, AutoGen) and inference SDKs calling `/v1/chat/completions`, `/v1/messages`, `/v1/models`, `/healthz`, or `/metrics` are **exempt** from browser session cookies.
   - They authenticate via standard API key headers (`Authorization: Bearer <key>`, `X-POD-Caller-Key`, `X-POD-Admin-Key`).
3. **Strict Route Protection**:
   - In production or when `DOCKET_REQUIRE_AUTH=true`, all unauthenticated browser requests to `GET /`, `GET /dlp`, etc., immediately return `HTTP 302` redirecting to `/login?next=<path>`. No system data, scorecards, or telemetry are visible prior to authentication.

---

## 2. Institutional Default Accounts & Credentials

G1 Docket ships with pre-configured institutional accounts designed to enforce the **Four-Eyes Dual-Control Principle** required by SOC 2, HIPAA, and ISO 27001:

| Operator ID | Default Password | Role | Display Name | Environment Override Variable |
| :--- | :--- | :--- | :--- | :--- |
| `admin` | `DocketAdmin2026!Secure` | `admin` | Enterprise Admin | `DOCKET_ADMIN_PASSWORD` |
| `operator1` | `TriageOperator2026!` | `triage_operator` | Triage Specialist (Key 1) | `DOCKET_OPERATOR_PASSWORD` |
| `approver1` | `SecurityLead2026!` | `security_approver` | Security Officer (Key 2) | `DOCKET_APPROVER_PASSWORD` |
| `auditor1` | `AuditInspector2026!` | `auditor` | SOC2 Compliance Auditor | `DOCKET_AUDITOR_PASSWORD` |
| `mfa_operator` | `MfaOperator2026!` | `security_approver` | 2FA Enforced Officer (Key 2) | `DOCKET_MFA_PASSWORD`<br>`DOCKET_MFA_SECRET` |

> [!IMPORTANT]
> The default credentials above are for local evaluation and testing. Before deploying G1 Docket into production or internet-facing staging environments, you **must** customize passwords or integrate enterprise SSO using the instructions in Section 3.

---

## 3. Role-Based Access Control (RBAC) Matrix

Every authenticated session is tagged with an institutional role that governs available operations across both ports:

| Capability / Route | `admin` | `security_approver` | `triage_operator` | `auditor` (Read-Only) |
| :--- | :---: | :---: | :---: | :---: |
| **Inspect Dashboards & Telemetry** (`GET /`, `GET /dlp`) | Yes | Yes | Yes | Yes |
| **Inspect Signed Snapshots & Scorecards** | Yes | Yes | Yes | Yes |
| **View WORM Ledger & SIEM Telemetry** (`:18084`) | Yes | Yes | Yes | Yes |
| **Run Attestation & Directory Prevalidation** | Yes | Yes | Yes | **Blocked (403)** |
| **Submit Key 1 Quarantine Exemption Request** | Yes | Yes | Yes | **Blocked (403)** |
| **Co-Sign Key 2 Emergency Ticket** | Yes | Yes | **Blocked (403)** | **Blocked (403)** |
| **Toggle Gateway Mode (`enforce` / `observe`)** | Yes | Yes | **Blocked (403)** | **Blocked (403)** |
| **Configure LLM Providers & DLP Connectors** | Yes | **Blocked (403)** | **Blocked (403)** | **Blocked (403)** |

### Strict Auditor Isolation:
When an operator with the `auditor` role (such as `auditor1`) attempts to execute a mutating action (e.g. `POST /v1/prevalidate-directory`, `POST /v1/admin/attest-directory`, or changing gateway modes), the system strictly rejects the request:
```json
{
  "detail": "Read-only auditor role is not permitted to trigger live directory prevalidation scans or file attestations."
}
```

---

## 4. How to Make the System Your Own

### Method A: Overriding Default Passwords via Environment Variables

To customize passwords for the built-in institutional accounts, set the corresponding environment variables in your `.env` file or `docker-compose.yml`:

```bash
# In your .env file:
DOCKET_ADMIN_PASSWORD="YourEnterpriseAdminSecret2026!#"
DOCKET_OPERATOR_PASSWORD="YourTriageOperatorSecret2026!#"
DOCKET_APPROVER_PASSWORD="YourSecurityLeadSecret2026!#"
DOCKET_AUDITOR_PASSWORD="YourExternalAuditorSecret2026!#"
DOCKET_MFA_PASSWORD="YourMfaOfficerSecret2026!#"
DOCKET_MFA_SECRET="JBSWY3DPEHPK3PXP"  # Base32 TOTP secret (or generate a random one)
```

Restart the stack to apply the new passwords:
```bash
docker compose up -d prevalidator governance
```

---

### Method B: Provisioning Custom Corporate Accounts (`DOCKET_AUTH_USERS_JSON`)

To provision completely custom users (matching your organization's exact directory usernames and roles), pass a JSON array via the `DOCKET_AUTH_USERS_JSON` environment variable:

```bash
export DOCKET_AUTH_USERS_JSON='[
  {
    "username": "sarah.chen",
    "password_hash": "MySecurePassword123!",
    "role": "admin",
    "display_name": "Sarah Chen (Director of AI Security)",
    "email": "sarah.chen@acme.corp"
  },
  {
    "username": "triage-lead",
    "password_hash": "TriageTeam2026!Sec",
    "role": "triage_operator",
    "display_name": "SecOps Triage Lead",
    "email": "secops-triage@acme.corp"
  },
  {
    "username": "kroll-auditor",
    "password_hash": "ComplianceAudit2026!",
    "role": "auditor",
    "display_name": "SOC2 Lead Assessor",
    "email": "auditor@external.audit"
  }
]'
```

> [!TIP]
> If `password_hash` contains a `$` salt delimiter (e.g. `salt$hash`), G1 Docket uses the existing PBKDF2 hash directly. If it is plain text, G1 Docket automatically salts and hashes it upon initialization using 100,000 PBKDF2-HMAC-SHA256 iterations.

---

### Method C: Enterprise Single Sign-On (SSO) & OIDC Integration

G1 Docket natively supports enterprise Identity Providers (IdPs) including **Microsoft Entra ID (Azure AD)**, **Okta**, **Google Workspace**, and **Ping Identity**.

#### 1. Cryptographic OIDC Signature Verification via JWKS
Both the **Governance Door** (`Authorization: Bearer <token>`) and the **Prevalidator Caller-Token Door** (`X-POD-Caller-Token: <token>`) verify enterprise IdP cryptographic signatures via JSON Web Key Sets (JWKS) whenever an issuer is configured. Claims-only acceptance is **not** a supported operating mode in production.

- **Supported Signature Algorithms**: `RS256`, `ES256`.
- **Automatic JWKS Discovery**: Discovers public signing keys dynamically from `{issuer}/.well-known/openid-configuration` (or `{issuer}/.well-known/jwks.json`).
- **High-Throughput In-Memory Caching**: Signing keys are cached via `jwt.PyJWKClient` (1-hour key lifespan) ensuring sub-millisecond added latency (< 0.1 ms p95 overhead).
- **Strict Claims Verification**: `iss` (issuer), `aud` (audience), `exp` (expiration), and `nbf` (not-before) claims are strictly enforced cryptographically before identity and RBAC/ABAC role claims are mapped.

```bash
# Configure in .env or Kubernetes Secret:
DOCKET_OIDC_ISSUER="https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
DOCKET_OIDC_AUDIENCE="api://g1-docket-governance"

# Prevalidator caller tokens can inherit from DOCKET_OIDC_* or be configured independently:
POD_OIDC_ISSUER="https://identity.enterprise.gov/v2.0"
POD_OIDC_AUDIENCE="https://docket.enterprise.gov/api"
```

> [!IMPORTANT]
> When `DOCKET_ENVIRONMENT=production` or `DOCKET_REQUIRE_AUTH=true`, unverified OIDC-shaped tokens are rejected fail-closed. If `POD_JWT_SECRET` is unset and no caller OIDC issuer is configured, the Prevalidator will refuse to start.

#### 2. Reverse-Proxy / Ingress Header Forwarding
If G1 Docket sits behind an enterprise reverse proxy or Cloud Identity-Aware Proxy (e.g., Cloudflare Access, AWS ALB, Azure App Proxy, Google IAP, OAuth2-Proxy), G1 Docket extracts and maps the forwarded operator headers.

> [!WARNING]
> The reverse-proxy header forwarding pattern is supported **only** when G1 Docket is deployed in a private network perimeter and is reachable **exclusively** through the verifying gateway. Direct client access to G1 Docket ports bypassing the proxy must be blocked at the network/ingress level.

| Header | Purpose | Example |
| :--- | :--- | :--- |
| `X-Forwarded-Email` | Authenticated operator email | `alice@acme.corp` |
| `X-Forwarded-Roles` / `X-Forwarded-Groups` | Corporate group mapping | `G1-Docket-Admins`, `SecOps-Approvers` |
| `Remote-User` / `X-Forwarded-User` | Alternate user identifier | `alice` |

**Automatic Group-to-Role Mapping:**
- Any role/group containing `admin` &rarr; mapped to `admin`
- Any role/group containing `approver`, `ciso`, `security`, `officer`, or `lead` &rarr; mapped to `security_approver`
- Any role/group containing `audit` &rarr; mapped to `auditor`
- All other corporate identities &rarr; mapped to `triage_operator`

---

### Method D: Customizing Cluster Session Signing Secret

To ensure session tokens are tamper-proof and resilient across cluster restarts, set a persistent, high-entropy 256-bit cluster secret:

```bash
# Generate a secure 32-byte secret
openssl rand -hex 32

# Set in .env or Kubernetes Secrets:
DOCKET_SESSION_SECRET="f39b6e82c18d9e7a4b0c123456789abcdef0123456789abcdef0123456789abc"
```

---

## 5. Security & Brute-Force Rate Limiting

The authentication engine includes built-in protection against automated credential stuffing and brute-force attacks:
- **Maximum Failed Attempts**: 5 consecutive failed login attempts.
- **Lockout Duration**: 300 seconds (5 minutes).
- **Lockout Scope**: Tracked both per client IP address and per user account.
- **Audit Logging**: Every authentication attempt (successful login, password failure, 2FA failure, lockout, and logout) is cryptographically signed and appended to the immutable WORM audit ledger (`governance/worm_ledger.py`).

---

## 6. Verification & Health Checks

To verify authentication health across both ports:

```bash
# Check Prevalidator healthz (M2M exemption)
curl -s http://localhost:18082/healthz

# Verify login page accessibility
curl -s http://localhost:18082/login | grep "Operator Sign In"

# Verify current session identity
curl -s -b "docket_session=<TOKEN>" http://localhost:18082/api/whoami

# Run full automated auth test suite
pytest -v tests/test_prevalidator_auth.py
```
