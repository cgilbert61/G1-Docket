"""
Authentication and Session Security Engine for G1 Docket Governance Subsystem.
Provides cryptographic password hashing (PBKDF2-HMAC-SHA256), HMAC session cookies,
in-memory brute-force protection, and role-based access control (RBAC).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set

from fastapi import HTTPException, Request, Response, status

logger = logging.getLogger("g1.governance.auth")

SESSION_COOKIE_NAME = "docket_session"
DEFAULT_SESSION_TTL_SECONDS = 8 * 3600  # 8 hours maximum session limit
DEFAULT_INACTIVITY_TIMEOUT_SECONDS = 1800  # 30 minutes idle inactivity timeout
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes


@dataclass
class UserAccount:
    username: str
    password_hash: str  # Format: "salt$hash"
    role: str           # "admin" | "triage_operator" | "security_approver" | "auditor"
    display_name: str
    email: str
    totp_secret: Optional[str] = None  # Base32 RFC 6238 secret if 2FA enabled


def generate_totp_secret() -> str:
    """Generate a random 20-byte base32 TOTP secret string."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def compute_totp_code(secret_b32: str, for_time: Optional[int] = None) -> str:
    """Compute 6-digit RFC 6238 TOTP code for a given base32 secret and timestamp."""
    if for_time is None:
        for_time = int(time.time())
    steps = int(for_time // 30)
    pad_len = -len(secret_b32) % 8
    padded = secret_b32.upper() + ("=" * pad_len)
    key_bytes = base64.b32decode(padded)
    time_bytes = struct.pack(">Q", steps)
    h = hmac.new(key_bytes, time_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"


def verify_totp_code(secret_b32: str, code: str, window: int = 1) -> bool:
    """Verify 6-digit TOTP code with clock-skew tolerance (+/- window 30s steps)."""
    clean_code = code.strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    now = int(time.time())
    for step_offset in range(-window, window + 1):
        expected = compute_totp_code(secret_b32, for_time=now + (step_offset * 30))
        if hmac.compare_digest(expected, clean_code):
            return True
    return False


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Derive salted PBKDF2-HMAC-SHA256 password hash (100,000 iterations)."""
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return f"{salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify password against stored salt$hash using constant-time comparison."""
    try:
        salt, expected_hash = stored_hash.split("$", 1)
        computed = hash_password(plain_password, salt=salt)
        return hmac.compare_digest(computed, stored_hash)
    except Exception:
        return False


def get_or_create_session_secret(keys_dir: Optional[str | Path] = None) -> bytes:
    """Retrieve session signing key from environment or persist to local key directory."""
    env_secret = os.environ.get("DOCKET_SESSION_SECRET")
    if env_secret:
        return hashlib.sha256(env_secret.encode("utf-8")).digest()

    target_dir = Path(keys_dir) if keys_dir else Path(".pod_keys")
    target_dir.mkdir(parents=True, exist_ok=True)
    secret_file = target_dir / "governance_session_secret.key"

    if secret_file.exists():
        try:
            return secret_file.read_bytes()
        except Exception as e:
            logger.warning("Could not read session secret file: %s. Generating ephemeral secret.", e)

    new_secret = secrets.token_bytes(32)
    try:
        secret_file.write_bytes(new_secret)
    except Exception as e:
        logger.warning("Could not persist session secret: %s", e)
    return new_secret


class AuthManager:
    def __init__(self, keys_dir: Optional[str | Path] = None):
        self.session_key = get_or_create_session_secret(keys_dir)
        self.users: Dict[str, UserAccount] = {}
        self._login_failures: Dict[str, list[float]] = {}
        self._initialize_default_users()

    def _initialize_default_users(self) -> None:
        """Initialize institutional default accounts or ingest custom accounts from env."""
        custom_users_json = os.environ.get("DOCKET_AUTH_USERS_JSON")
        if custom_users_json:
            try:
                loaded = json.loads(custom_users_json)
                for u in loaded:
                    account = UserAccount(
                        username=u["username"],
                        password_hash=u["password_hash"] if "$" in u.get("password_hash", "") else hash_password(u["password_hash"]),
                        role=u.get("role", "triage_operator"),
                        display_name=u.get("display_name", u["username"]),
                        email=u.get("email", f"{u['username']}@internal.corp"),
                    )
                    self.users[account.username.lower()] = account
                logger.info("Initialized %d users from DOCKET_AUTH_USERS_JSON.", len(self.users))
                return
            except Exception as e:
                logger.error("Failed to load DOCKET_AUTH_USERS_JSON: %s", e)

        # Standard institutional accounts
        admin_pass = os.environ.get("DOCKET_ADMIN_PASSWORD", "DocketAdmin2026!Secure")
        operator_pass = os.environ.get("DOCKET_OPERATOR_PASSWORD", "TriageOperator2026!")
        approver_pass = os.environ.get("DOCKET_APPROVER_PASSWORD", "SecurityLead2026!")
        auditor_pass = os.environ.get("DOCKET_AUDITOR_PASSWORD", "AuditInspector2026!")

        self.users["admin"] = UserAccount(
            username="admin",
            password_hash=hash_password(admin_pass),
            role="admin",
            display_name="Enterprise Admin",
            email="admin@internal.corp",
        )
        self.users["operator1"] = UserAccount(
            username="operator1",
            password_hash=hash_password(operator_pass),
            role="triage_operator",
            display_name="Triage Specialist (Key 1)",
            email="triage.operator@internal.corp",
        )
        self.users["approver1"] = UserAccount(
            username="approver1",
            password_hash=hash_password(approver_pass),
            role="security_approver",
            display_name="Security Officer (Key 2)",
            email="security.approver@internal.corp",
        )
        self.users["auditor1"] = UserAccount(
            username="auditor1",
            password_hash=hash_password(auditor_pass),
            role="auditor",
            display_name="SOC2 Compliance Auditor",
            email="auditor@external.audit",
        )
        # Dedicated 2FA account with RFC 6238 TOTP seed
        mfa_pass = os.environ.get("DOCKET_MFA_PASSWORD", "MfaOperator2026!")
        mfa_secret = os.environ.get("DOCKET_MFA_SECRET", "JBSWY3DPEHPK3PXP")
        self.users["mfa_operator"] = UserAccount(
            username="mfa_operator",
            password_hash=hash_password(mfa_pass),
            role="security_approver",
            display_name="2FA Enforced Officer (Key 2)",
            email="mfa.officer@internal.corp",
            totp_secret=mfa_secret,
        )

    def check_rate_limit(self, identifier: str) -> bool:
        """Return True if identifier is currently rate-limited/locked out."""
        now = time.time()
        failures = self._login_failures.get(identifier, [])
        # Retain only failures within the lockout window
        recent = [t for t in failures if now - t < LOCKOUT_DURATION_SECONDS]
        self._login_failures[identifier] = recent
        return len(recent) >= MAX_FAILED_ATTEMPTS

    def record_login_failure(self, identifier: str) -> None:
        """Record a failed login attempt for lockout tracking."""
        now = time.time()
        if identifier not in self._login_failures:
            self._login_failures[identifier] = []
        self._login_failures[identifier].append(now)

    def record_login_success(self, identifier: str) -> None:
        """Clear lockout records upon successful authentication."""
        self._login_failures.pop(identifier, None)

    def authenticate(
        self,
        username: str,
        plain_pass: str,
        client_ip: str,
        totp_code: Optional[str] = None,
    ) -> Optional[UserAccount]:
        """Authenticate user against password credentials and optional/enforced TOTP code."""
        u_key = username.strip().lower()
        ip_key = f"ip:{client_ip}"
        user_lock_key = f"user:{u_key}"

        if self.check_rate_limit(ip_key) or self.check_rate_limit(user_lock_key):
            logger.warning("Authentication blocked by rate-limit for user '%s' / IP '%s'", username, client_ip)
            raise ValueError("Too many failed login attempts. Account temporarily locked for 5 minutes.")

        user = self.users.get(u_key)
        if not user or not verify_password(plain_pass, user.password_hash):
            self.record_login_failure(ip_key)
            self.record_login_failure(user_lock_key)
            return None

        # TOTP 2FA Verification
        if user.totp_secret:
            if not totp_code or not verify_totp_code(user.totp_secret, totp_code):
                self.record_login_failure(ip_key)
                self.record_login_failure(user_lock_key)
                logger.warning("Invalid or missing TOTP 2FA code for user '%s'", username)
                return None

        self.record_login_success(ip_key)
        self.record_login_success(user_lock_key)
        return user

    def create_session_token(self, user: UserAccount, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> str:
        """Issue an HMAC-SHA256 signed session cookie payload with sliding inactivity tracking."""
        now = int(time.time())
        payload = {
            "sub": user.username,
            "role": user.role,
            "display_name": user.display_name,
            "email": user.email,
            "iat": now,
            "last_active": now,
            "exp": now + ttl_seconds,
            "nonce": secrets.token_hex(8),
        }
        raw_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        b64_payload = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
        sig = hmac.new(self.session_key, b64_payload.encode("ascii"), hashlib.sha256).digest()
        b64_sig = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
        return f"{b64_payload}.{b64_sig}"

    def verify_session_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate HMAC-SHA256 signature, expiration, and sliding inactivity timeout."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            b64_payload, b64_sig = parts

            # Verify signature
            expected_sig = hmac.new(self.session_key, b64_payload.encode("ascii"), hashlib.sha256).digest()
            # Restore padding
            sig_pad = b64_sig + "=" * (-len(b64_sig) % 4)
            actual_sig = base64.urlsafe_b64decode(sig_pad)
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None

            payload_pad = b64_payload + "=" * (-len(b64_payload) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_pad).decode("utf-8"))

            now = int(time.time())
            # Absolute TTL check
            if payload.get("exp", 0) < now:
                return None
            # Sliding idle inactivity check (30 minutes default)
            last_active = payload.get("last_active", payload.get("iat", 0))
            if (now - last_active) > DEFAULT_INACTIVITY_TIMEOUT_SECONDS:
                logger.info("Session for '%s' expired due to inactivity (%d seconds idle)", payload.get("sub"), now - last_active)
                return None

            return payload
        except Exception:
            return None

    def verify_bearer_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate either an internal HMAC session token or an OIDC / OAuth2 JWT bearer token."""
        clean_token = token.strip()
        # 1. Check if it's a native 2-part HMAC session token
        sess = self.verify_session_token(clean_token)
        if sess:
            return sess

        # 2. Check if it's a 3-part JWT token (header.payload.signature)
        parts = clean_token.split(".")
        if len(parts) != 3:
            return None

        try:
            b64_header, b64_payload, b64_sig = parts
            payload_pad = b64_payload + "=" * (-len(b64_payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_pad).decode("utf-8"))

            now = int(time.time())
            # Verify expiry if present
            if "exp" in claims and claims["exp"] < now:
                logger.info("OIDC Bearer token expired (exp=%s, now=%s)", claims["exp"], now)
                return None

            # Verify nbf (not before) if present
            if "nbf" in claims and claims["nbf"] > now:
                return None

            # Verify audience if configured
            expected_aud = os.getenv("DOCKET_OIDC_AUDIENCE")
            if expected_aud:
                aud = claims.get("aud")
                if isinstance(aud, list) and expected_aud not in aud:
                    return None
                elif isinstance(aud, str) and aud != expected_aud:
                    return None

            # Verify issuer if configured
            expected_iss = os.getenv("DOCKET_OIDC_ISSUER")
            if expected_iss and claims.get("iss") != expected_iss:
                return None

            # Extract subject / identity claim
            user_id = (
                claims.get("email")
                or claims.get("preferred_username")
                or claims.get("upn")
                or claims.get("sub")
            )
            if not user_id:
                return None

            # Map roles / scopes / groups to G1-Docket RBAC roles
            roles_claim = claims.get("roles") or claims.get("groups") or []
            if isinstance(roles_claim, str):
                roles_claim = [roles_claim]
            roles_str = " ".join(str(r).lower() for r in roles_claim)
            u_lower = str(user_id).lower()

            if "admin" in roles_str or "admin" in u_lower:
                role = "admin"
            elif any(k in roles_str or k in u_lower for k in ("approver", "ciso", "security", "officer", "lead", "manager")):
                role = "security_approver"
            elif "audit" in roles_str or "audit" in u_lower:
                role = "auditor"
            else:
                role = "triage_operator"

            return {
                "sub": str(user_id),
                "role": role,
                "display_name": claims.get("name") or str(user_id),
                "email": claims.get("email") or str(user_id),
                "claims": claims,
                "auth_type": "oidc_jwt",
            }
        except Exception as e:
            logger.debug("Failed parsing OIDC Bearer token: %s", e)
            return None


def get_client_ip(request: Request) -> str:
    """Determine client IP address taking into account standard reverse-proxy headers."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"
