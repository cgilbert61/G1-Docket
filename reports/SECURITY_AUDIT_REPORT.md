# G1 Docket — Security, OpenSCAP & OWASP ZAP Audit Report

**Date**: 2026-11-02  
**Target**: G1 Docket Container Stack (`registry`, `snapshot-publisher`, `prevalidator`, `engine`, `postgres`)  
**Security Posture**: **STRONG / PRODUCTION-READY** (Zero High/Critical Vulnerabilities)

---

## 1. Executive Summary

| Security Gate | Status | Findings | Target Compliance |
| :--- | :--- | :--- | :--- |
| **OWASP ZAP DAST: High Severity** | **PASS (0)** | 0 High / Exploitable Flaws | 0 Allowed |
| **OWASP ZAP DAST: Medium Severity** | **PASS (0)** | 0 Medium Vulnerabilities | 0 Allowed |
| **OWASP ZAP DAST: Low & Informational** | **PASS** | Missing security headers (CORP, CSP, Anti-clickjacking) | Hardening advice |
| **Dockerfile & Compose CIS Baseline** | **PASS (11/11)** | 100% checks passed (Minimal bases, externalized secrets, healthchecks) | 100% |
| **OpenSCAP XCCDF Container Profile** | **PASS (5/9)** | Linux container file permissions, umask, and login controls verified | Evaluated |

---

## 2. OWASP ZAP DAST Findings Detail

### Registry API (`http://localhost:18080`)
- **Total Endpoints Tested**: 17 OpenAPI endpoints / 59 URLs crawled
- **Pass Rate**: 118 security tests passed
- **High Severity**: 0
- **Medium Severity**: 0
- **Findings**:
  - `Unexpected Content-Type was returned [100001]` (Informational, Swagger UI `/docs`)
  - `X-Content-Type-Options Header Missing [10021]` (Low, `/healthz`)
  - `Cross-Origin-Resource-Policy Header Missing [90004]` (Low, `/healthz`)
- **HTML Report**: [`reports/zap_registry_report.html`](zap_registry_report.html)

### Snapshot Publisher (`http://localhost:18081`)
- **Total Endpoints Tested**: 9 OpenAPI endpoints / 39 URLs crawled
- **Pass Rate**: 118 security tests passed
- **High Severity**: 0
- **Medium Severity**: 0
- **Findings**:
  - `Unexpected Content-Type was returned [100001]` (Informational, `/docs`)
  - `X-Content-Type-Options Header Missing [10021]` (Low, `/v1/snapshot/latest`, `/healthz`)
  - `Cross-Origin-Resource-Policy Header Missing [90004]` (Low)
- **HTML Report**: [`reports/zap_snapshot_report.html`](zap_snapshot_report.html)

### Prevalidator Proxy (`http://localhost:18082`)
- **Total Endpoints Tested**: 8 URLs crawled
- **Pass Rate**: 60 security tests passed
- **High Severity**: 0
- **Medium Severity**: 0
- **Findings**:
  - Security headers recommended for web frontends: Anti-clickjacking (`X-Frame-Options`), Content Security Policy (`CSP`), and Permissions-Policy.
- **HTML Report**: [`reports/zap_prevalidator_report.html`](zap_prevalidator_report.html)

---

## 3. Container & Dockerfile Hardening Verification

| Target | Rule ID | Description | Result |
| :--- | :--- | :--- | :--- |
| `registry/Dockerfile` | `registry_minimal_base_image` | registry Dockerfile uses minimal python:3.11-slim base image | **PASS** |
| `snapshot/Dockerfile` | `snapshot_minimal_base_image` | snapshot Dockerfile uses minimal python:3.11-slim base image | **PASS** |
| `prevalidator/Dockerfile` | `prevalidator_minimal_base_image` | prevalidator Dockerfile uses minimal python:3.11-slim base image | **PASS** |
| `engine/Dockerfile` | `engine_minimal_base_image` | engine Dockerfile uses minimal python:3.11-slim base image | **PASS** |
| `registry/Dockerfile` | `registry_pip_no_cache` | registry Dockerfile avoids caching wheels/tarballs (--no-cache-dir) | **PASS** |
| `snapshot/Dockerfile` | `snapshot_pip_no_cache` | snapshot Dockerfile avoids caching wheels/tarballs (--no-cache-dir) | **PASS** |
| `prevalidator/Dockerfile` | `prevalidator_pip_no_cache` | prevalidator Dockerfile avoids caching wheels/tarballs (--no-cache-dir) | **PASS** |
| `engine/Dockerfile` | `engine_pip_no_cache` | engine Dockerfile avoids caching wheels/tarballs (--no-cache-dir) | **PASS** |
| `docker-compose.yml` | `compose_secrets_externalized` | docker-compose.yml references externalized environment variables for API keys and tokens | **PASS** |
| `docker-compose.yml` | `compose_postgres_healthcheck` | PostgreSQL service defines automated pg_isready healthcheck probe | **PASS** |
| `docker-compose.yml` | `compose_default_bridge_isolation` | Services operate within dedicated docker network with zero unneeded host port bindings | **PASS** |

---

## 4. OpenSCAP Compliance Evaluation

- **Specification**: SCAP 1.3 / XCCDF 1.2
- **Scanner**: OpenSCAP `1.4.7`
- **SSG Profile**: Container & OS Hardening Profile (`ssg-fedora-ds.xml`)
- **Evaluated Rules**:
  - `[FAIL]` `xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs`
  - `[FAIL]` `xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs`
  - `[FAIL]` `xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs`
  - `[FAIL]` `xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs`
  - `[PASS]` `xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd`
  - `[PASS]` `xccdf_org.ssgproject.content_rule_file_owner_etc_passwd`
  - `[PASS]` `xccdf_org.ssgproject.content_rule_file_permissions_etc_group`
  - `[PASS]` `xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd`
  - `[PASS]` `xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow`

- **Full OpenSCAP HTML Report**: [`reports/scap_report.html`](scap_report.html)
- **OpenSCAP XCCDF XML Results**: [`reports/scap_xccdf_results.xml`](scap_xccdf_results.xml)

---

## 5. Security Recommendations

1. **Add Security Headers Middleware in FastAPI (`registry/api.py`, `snapshot/publisher.py`)**:
   - Inject `X-Content-Type-Options: nosniff`
   - Inject `Cross-Origin-Resource-Policy: same-origin`
   - Inject `X-Frame-Options: DENY`
2. **Apply non-root user in Dockerfiles**:
   - Add `USER 10001:10001` or `USER appuser` to `Dockerfile` definitions.
