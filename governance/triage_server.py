"""
FastAPI Human-in-the-Loop (HITL) Governance, Audit, and Triage Server.
Runs on port 18083 (administratively segregated from inference port 18082).
Serves the institutional HTMX/Tailwind dashboard, REST triage APIs,
and real-time Server-Sent Events (SSE) telemetry feed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from governance.auth import AuthManager, SESSION_COOKIE_NAME, get_client_ip, verify_password
from governance.cicd_security import fetch_cicd_status, fetch_secret_audit
from governance.config import load_governance_config
from governance.dual_key import DualKeyGovernanceManager, FourEyesViolationError
from governance.mock_sinks import MockReceiverCluster
from governance.quarantine import QuarantineStore
from governance.siem_forwarder import SIEMDestinationConfig, SIEMForwarder, sanitize_for_siem
from governance.worm_ledger import WORMAuditLedger, verify_ledger_integrity

logger = logging.getLogger("g1.governance.server")

# Active SSE client subscriber queues
_sse_subscribers: List[asyncio.Queue] = []


class SIEMConfigUpdateRequest(BaseModel):
    enabled: bool = True
    endpoint_url: Optional[str] = ""
    api_key: Optional[str] = None
    auth_header: Optional[str] = None
    index_or_sourcetype: Optional[str] = None
    syslog_host: Optional[str] = None
    syslog_port: Optional[int] = None
    syslog_use_tls: bool = False
    workspace_id: Optional[str] = None
    log_group_name: Optional[str] = None
    timeout_seconds: Optional[float] = 10.0


async def broadcast_event(event_dict: Dict[str, Any]) -> None:
    """Broadcast an event to all connected SSE browser clients."""
    msg = f"data: {json.dumps(event_dict)}\n\n"
    for q in list(_sse_subscribers):
        try:
            await q.put(msg)
        except Exception:
            if q in _sse_subscribers:
                _sse_subscribers.remove(q)


def is_demo_mode() -> bool:
    """
    Determine if Docket Governance is running in demo mode or production mode.
    Prioritizes DOCKET_ENVIRONMENT ('demo' | 'production'), with backward
    compatibility for DOCKET_DEMO_MODE ('true' | 'false').
    """
    env_val = os.getenv("DOCKET_ENVIRONMENT", "").strip().lower()
    if env_val in ("production", "prod"):
        return False
    if env_val in ("demo", "dev", "test"):
        return True
    legacy = os.getenv("DOCKET_DEMO_MODE", "").strip().lower()
    if legacy in ("false", "0", "no"):
        return False
    if legacy in ("true", "1", "yes"):
        return True
    return True


def extract_authenticated_operator(request: Request) -> Optional[str]:
    """Extract authenticated corporate operator email from bearer token, session cookie, or standard enterprise proxy/IdP headers."""
    # 1. Check verified bearer token or session cookie
    auth_mgr = getattr(getattr(request, "app", None), "state", None)
    if auth_mgr and hasattr(auth_mgr, "auth_manager"):
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
            sess = auth_mgr.auth_manager.verify_bearer_token(token)
            if sess and sess.get("sub"):
                return sess["sub"]

        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie:
            sess = auth_mgr.auth_manager.verify_session_token(cookie)
            if sess and sess.get("sub"):
                return sess["sub"]

    # 2. Check enterprise reverse proxy/IdP headers
    candidate_headers = [
        "x-forwarded-email",
        "x-auth-request-email",
        "cf-access-authenticated-user-email",
        "x-ms-client-principal-name",
        "x-goog-authenticated-user-email",
        "x-forwarded-user",
        "remote-user",
    ]
    for h in candidate_headers:
        val = request.headers.get(h)
        if val:
            clean = val.strip()
            if clean.startswith("accounts.google.com:"):
                clean = clean.split(":", 1)[1]
            if clean:
                return clean
    return None


def get_current_user_session(request: Request) -> Optional[Dict[str, Any]]:
    """Retrieve full authenticated user session data if present."""
    auth_mgr = getattr(getattr(request, "app", None), "state", None)
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")

    x_admin = (request.headers.get("x-pod-admin-key") or request.headers.get("x-pod-control-token") or "").strip()
    if x_admin and x_admin in {admin_key, control_token}:
        return {
            "sub": "admin",
            "role": "admin",
            "display_name": "Enterprise Admin (API Key)",
            "email": "admin@internal.corp",
        }

    if auth_mgr and hasattr(auth_mgr, "auth_manager"):
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
            if token in {admin_key, control_token}:
                return {
                    "sub": "admin",
                    "role": "admin",
                    "display_name": "Enterprise Admin (Bearer Key)",
                    "email": "admin@internal.corp",
                }
            sess = auth_mgr.auth_manager.verify_bearer_token(token)
            if sess:
                return sess

        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie:
            sess = auth_mgr.auth_manager.verify_session_token(cookie)
            if sess:
                return sess

    idp_user = extract_authenticated_operator(request)
    if idp_user:
        u_lower = idp_user.lower()
        role_hdr = (request.headers.get("x-forwarded-roles") or request.headers.get("x-forwarded-groups") or "").lower()
        if any(r in role_hdr for r in ("untrusted", "guest", "unauthorized", "anonymous", "none")):
            role = "unauthorized"
        elif "admin" in role_hdr or "admin" in u_lower:
            role = "admin"
        elif "secops" in role_hdr or "secops" in u_lower:
            role = "secops"
        elif "reviewer" in role_hdr or "reviewer" in u_lower:
            role = "reviewer"
        elif any(k in role_hdr or k in u_lower for k in ("approver", "ciso", "security", "officer", "lead", "manager", "chief", "signer")):
            role = "security_approver"
        elif "audit" in role_hdr or "audit" in u_lower:
            role = "auditor"
        elif any(k in role_hdr or k in u_lower for k in ("operator", "triage", "requester")):
            role = "triage_operator"
        else:
            role = "security_approver" if request.url.path.endswith("approve-override") else "triage_operator"

        return {
            "sub": idp_user,
            "role": role,
            "display_name": idp_user,
            "email": idp_user,
        }
    return None


QUARANTINE_READ_ROLES = {"admin", "secops", "security_approver", "reviewer", "triage_operator", "auditor"}
QUARANTINE_STAGE_ROLES = {"admin", "secops", "security_approver", "reviewer", "triage_operator"}
QUARANTINE_APPROVE_ROLES = {"admin", "secops", "security_approver", "reviewer"}
INTEGRATION_ADMIN_ROLES = {"admin", "secops", "security_approver"}


def require_session_and_role(request: Request, allowed_roles: set[str]) -> Dict[str, Any]:
    """Enforce authenticated session (401) and explicit role membership (403)."""
    sess = get_current_user_session(request)
    if not sess or not sess.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AUTHENTICATION_REQUIRED: Valid operator session or bearer token required.",
        )
    role = str(sess.get("role") or "").strip().lower()
    if role not in allowed_roles:
        if role == "auditor":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Auditor role has read-only privileges and cannot perform this action.",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"INSUFFICIENT_ROLE_PRIVILEGES: Role '{role}' is not authorized (requires one of {sorted(allowed_roles)}).",
        )
    return sess


def _serialize_siem_destination_write_only(dest: SIEMDestinationConfig) -> Dict[str, Any]:
    """Return SIEM destination config with secrets strictly write-only (never returning plaintext secrets)."""
    return {
        "id": dest.id,
        "name": dest.name,
        "type": dest.type,
        "enabled": dest.enabled,
        "endpoint_url": dest.endpoint_url or "",
        "api_key_configured": bool(dest.api_key),
        "auth_header_configured": bool(dest.auth_header),
        "configured": bool(dest.api_key or dest.auth_header or dest.endpoint_url or dest.syslog_host),
        "index_or_sourcetype": dest.index_or_sourcetype or "",
        "syslog_host": dest.syslog_host or "",
        "syslog_port": dest.syslog_port or 514,
        "syslog_use_tls": dest.syslog_use_tls,
        "workspace_id": dest.workspace_id or "",
        "log_group_name": dest.log_group_name or "",
        "timeout_seconds": dest.timeout_seconds,
    }


class StageKey1Request(BaseModel):
    requester_id: Optional[str] = None
    rationale: str


class ApproveKey2Request(BaseModel):
    approver_id: Optional[str] = None
    notes: Optional[str] = ""
    ttl_seconds: Optional[int] = 7200


class RejectRequest(BaseModel):
    reviewer_id: Optional[str] = None
    reason: str


class BoundaryInterceptRequest(BaseModel):
    event_type: str = "DOCKET_DENIAL"
    reason_code: str = "POLICY_EVALUATION"
    payload_digest: str
    raw_payload: Optional[Dict[str, Any]] = None
    locator_uri: Optional[str] = "urn:doc:unspecified"
    claimed_tier: Optional[str] = "Internal"
    triggered_rules: Optional[List[str]] = None
    extracted_text: Optional[str] = None
    actor_identity: Optional[str] = "boundary:prevalidator"
    caller_clearance: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


def create_governance_app(config_path: Optional[str | Path] = None) -> FastAPI:
    cfg = load_governance_config(config_path)

    # Initialize persistence stores
    worm_ledger = WORMAuditLedger(
        db_path=cfg["storage"]["worm_sqlite_path"],
        jsonl_path=cfg["storage"]["worm_jsonl_path"],
    )
    quarantine_store = QuarantineStore(
        db_path=cfg["storage"]["quarantine_db_path"],
    )
    siem_forwarder = SIEMForwarder(
        buffer_db_path=cfg["storage"]["siem_buffer_db_path"],
        destinations=cfg["siem_destinations"],
    )
    dual_key_manager = DualKeyGovernanceManager(
        quarantine_store=quarantine_store,
        worm_ledger=worm_ledger,
        siem_forwarder=siem_forwarder,
        inference_gateway_url=cfg["server"]["inference_gateway_url"],
    )

    auth_manager = AuthManager(keys_dir=cfg["storage"]["keys_dir"])

    mock_cluster = MockReceiverCluster()
    _host_tpl = Path("/host_workspace/governance/templates")
    templates_dir = _host_tpl if _host_tpl.exists() else (Path(__file__).parent / "templates")
    templates = Jinja2Templates(directory=str(templates_dir))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        siem_forwarder.start_worker()
        logger.info("SIEM Forwarder daemon worker started.")
        mock_cluster.start()
        logger.info("Local Mock SIEM Receiver Cluster started.")

        # Seed initial demo quarantine & WORM items if empty
        if not quarantine_store.list_items():
            qid1 = quarantine_store.stage_quarantine(
                event_type="DOCKET_DENIAL",
                reason_code="UNATTESTED_DATA_OBJECT",
                payload_digest="7d8a9f24b6c31e05a8d9e2b104928e75c6129845ef1a34b9d0c2e3f4a5b6c7d8",
                raw_payload={"messages": [{"role": "user", "content": "Analyze corporate board strategy and projected Q4 earnings roadmap..."}]},
                locator_uri="file:///pc_demo_folder/07_purview_labeled_board_strategy.docx",
                claimed_tier="Confidential",
                triggered_rules=["UNATTESTED_DATA_OBJECT", "DOCKET_INGRESS_REJECT"],
                extracted_text="PROJECT TITAN ACQUISITION ROADMAP: Target Valuation $1.2B. Non-disclosure binding.",
                custom_id="Q-2026-BOARD-STRATEGY",
            )
            worm_ledger.append_event(
                event_type="DOCKET_DENIAL",
                actor_identity="boundary:docket-prevalidator",
                payload_digest="7d8a9f24b6c31e05a8d9e2b104928e75c6129845ef1a34b9d0c2e3f4a5b6c7d8",
                metadata={"quarantine_id": qid1, "reason_code": "UNATTESTED_DATA_OBJECT", "claimed_tier": "Confidential", "locator_uri": "file:///pc_demo_folder/07_purview_labeled_board_strategy.docx"},
                custom_entry_id="WORM-00000001-INIT",
            )

            qid2 = quarantine_store.stage_quarantine(
                event_type="DOCKET_DENIAL",
                reason_code="HASH_MISMATCH_TAMPERED",
                payload_digest="3f4b5c6d7e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
                raw_payload={"messages": [{"role": "user", "content": "Review payroll adjustments for executive team..."}]},
                locator_uri="file:///finance/2026_executive_payroll.xlsx",
                claimed_tier="Restricted",
                triggered_rules=["HASH_MISMATCH", "PREDICATE_TAMPERED"],
                extracted_text="EXECUTIVE PAYROLL LEDGER: Record altered in transit. Computed SHA does not match DSSE predicate.",
                custom_id="Q-2026-PAYROLL-TAMPERED",
            )
            worm_ledger.append_event(
                event_type="DOCKET_DENIAL",
                actor_identity="boundary:docket-prevalidator",
                payload_digest="3f4b5c6d7e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
                metadata={"quarantine_id": qid2, "reason_code": "HASH_MISMATCH_TAMPERED", "claimed_tier": "Restricted", "locator_uri": "file:///finance/2026_executive_payroll.xlsx"},
                custom_entry_id="WORM-00000002-INIT",
            )

        yield
        # Shutdown
        mock_cluster.stop()
        siem_forwarder.stop_worker()
        logger.info("SIEM Forwarder daemon worker stopped.")

    app = FastAPI(
        title="G1 Docket & Combine Governance Subsystem",
        version="4.0.0",
        lifespan=lifespan,
    )

    _host_static = Path("/host_workspace/governance/static")
    static_dir = _host_static if _host_static.exists() else (Path(__file__).parent / "static")
    if static_dir.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Attach subsystem singletons to app state
    app.state.worm_ledger = worm_ledger
    app.state.quarantine_store = quarantine_store
    app.state.siem_forwarder = siem_forwarder
    app.state.dual_key_manager = dual_key_manager
    app.state.auth_manager = auth_manager
    app.state.cfg = cfg

    # ---------------------------------------------------------
    # HTML Dashboard & Frontend Views
    # ---------------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    async def login_view(request: Request, error: Optional[str] = None):
        current_sess = get_current_user_session(request)
        if current_sess:
            return RedirectResponse(url="/", status_code=302)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "error": error,
                "current_user": None,
            },
        )

    @app.post("/login")
    async def login_submit(request: Request):
        content_type = request.headers.get("content-type", "")
        username = ""
        password = ""
        totp_code = ""
        if "application/json" in content_type:
            try:
                data = await request.json()
                username = data.get("username", "")
                password = data.get("password", "")
                totp_code = data.get("totp_code", "")
            except Exception:
                pass
        else:
            raw_body = (await request.body()).decode("utf-8", errors="ignore")
            from urllib.parse import parse_qs
            parsed = parse_qs(raw_body)
            username = parsed.get("username", [""])[0]
            password = parsed.get("password", [""])[0]
            totp_code = parsed.get("totp_code", [""])[0]

        client_ip = get_client_ip(request)
        auth_digest = hashlib.sha256(f"{username}:{client_ip}:{int(time.time())}".encode("utf-8")).hexdigest()
        try:
            target_user = auth_manager.users.get(username.strip().lower())
            is_mfa_candidate = bool(target_user and target_user.totp_secret)

            user = auth_manager.authenticate(username, password, client_ip, totp_code=totp_code)
            if not user:
                event_type = "OPERATOR_MFA_FAILURE" if (is_mfa_candidate and target_user and verify_password(password, target_user.password_hash)) else "OPERATOR_AUTH_FAILURE"
                reason_msg = "Invalid or missing authenticator code (2FA)." if event_type == "OPERATOR_MFA_FAILURE" else "Invalid operator ID or password."
                worm_ledger.append_event(
                    event_type=event_type,
                    actor_identity=f"operator:{username or 'unknown'}",
                    payload_digest=auth_digest,
                    metadata={"client_ip": client_ip, "reason": reason_msg},
                )
                if "application/json" in content_type:
                    return JSONResponse(status_code=401, content={"error": reason_msg})
                return templates.TemplateResponse(
                    request=request,
                    name="login.html",
                    context={
                        "request": request,
                        "error": reason_msg,
                        "current_user": None,
                    },
                    status_code=401,
                )

            success_event = "OPERATOR_MFA_SUCCESS" if user.totp_secret else "OPERATOR_AUTH_SUCCESS"
            worm_ledger.append_event(
                event_type=success_event,
                actor_identity=f"operator:{user.username}",
                payload_digest=auth_digest,
                metadata={"client_ip": client_ip, "role": user.role, "display_name": user.display_name, "mfa_enforced": bool(user.totp_secret)},
            )
            token = auth_manager.create_session_token(user)
            if "application/json" in content_type:
                resp = JSONResponse(
                    status_code=200,
                    content={
                        "status": "authenticated",
                        "operator": user.username,
                        "role": user.role,
                        "display_name": user.display_name,
                    },
                )
            else:
                resp = RedirectResponse(url="/", status_code=302)

            is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            resp.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=token,
                max_age=8 * 3600,
                httponly=True,
                samesite="lax",
                secure=is_secure,
            )
            return resp
        except ValueError as e:
            worm_ledger.append_event(
                event_type="OPERATOR_AUTH_LOCKOUT",
                actor_identity=f"operator:{username or 'unknown'}",
                payload_digest=auth_digest,
                metadata={"client_ip": client_ip, "reason": str(e)},
            )
            if "application/json" in content_type:
                return JSONResponse(status_code=429, content={"error": str(e)})
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "request": request,
                    "error": str(e),
                    "current_user": None,
                },
                status_code=429,
            )

    @app.get("/logout")
    async def logout_view(request: Request):
        sess = get_current_user_session(request)
        if sess and sess.get("sub"):
            client_ip = get_client_ip(request)
            logout_digest = hashlib.sha256(f"logout:{sess['sub']}:{client_ip}:{int(time.time())}".encode("utf-8")).hexdigest()
            worm_ledger.append_event(
                event_type="OPERATOR_LOGOUT",
                actor_identity=f"operator:{sess['sub']}",
                payload_digest=logout_digest,
                metadata={"client_ip": client_ip},
            )
        resp = RedirectResponse(url="/login", status_code=302)
        resp.delete_cookie(SESSION_COOKIE_NAME)
        return resp

    @app.get("/api/auth/session")
    @app.get("/api/auth/whoami")
    @app.get("/api/whoami")
    async def session_api(request: Request):
        sess = get_current_user_session(request)
        if not sess:
            return JSONResponse(status_code=401, content={"authenticated": False})
        return {
            "authenticated": True,
            "logged_in": True,
            "operator": sess.get("sub"),
            "role": sess.get("role"),
            "display_name": sess.get("display_name"),
            "email": sess.get("email"),
        }

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_view(request: Request):
        current_sess = get_current_user_session(request)
        current_user = current_sess["sub"] if current_sess else None

        require_auth = not is_demo_mode() or os.getenv("DOCKET_REQUIRE_AUTH", "").strip().lower() in ("1", "true", "yes")
        if require_auth and not current_user:
            return RedirectResponse(url="/login", status_code=302)

        q_items = quarantine_store.list_items(limit=25)
        w_events = worm_ledger.get_events(limit=25)
        q_counts = quarantine_store.count_by_status()
        _, tip_hash = worm_ledger.get_tip_hash()
        worm_count = worm_ledger.count_events()
        siem_dests = siem_forwarder.get_destination_status()
        cicd_status = fetch_cicd_status()
        secret_audit = fetch_secret_audit()

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "demo_mode": is_demo_mode(),
                "current_user": current_user,
                "current_role": current_sess.get("role") if current_sess else None,
                "quarantine_items": q_items,
                "worm_events": w_events,
                "cicd_status": cicd_status,
                "secret_audit": secret_audit,
                "stats": {
                    "quarantine_counts": q_counts,
                    "worm_count": worm_count,
                    "worm_tip": tip_hash,
                    "siem_destinations": siem_dests,
                },
            },
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    @app.get("/healthz")
    async def health_check():
        return {
            "status": "healthy",
            "service": "governance-triage",
            "environment": "demo" if is_demo_mode() else "production",
            "demo_mode": is_demo_mode(),
            "quarantine_pending": quarantine_store.count_by_status().get("QUARANTINED", 0),
            "worm_events": worm_ledger.count_events(),
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics():
        """Prometheus metrics exposition endpoint for WORM audit and quarantine telemetry."""
        w_count = worm_ledger.count_events()
        q_counts = quarantine_store.count_by_status()
        dests = siem_forwarder.get_destination_status()
        enabled_dests = sum(1 for d in dests if d.get("enabled", False))
        disabled_dests = len(dests) - enabled_dests

        lines = [
            "# HELP g1_docket_governance_worm_events_total Total verified events in the append-only WORM Merkle ledger.",
            "# TYPE g1_docket_governance_worm_events_total counter",
            f"g1_docket_governance_worm_events_total {w_count}",
            "",
            "# HELP g1_docket_governance_quarantine_items Quarantine incidents broken down by status.",
            "# TYPE g1_docket_governance_quarantine_items gauge",
        ]
        for st, count in sorted(q_counts.items()):
            lines.append(f'g1_docket_governance_quarantine_items{{status="{st}"}} {count}')
        lines.extend([
            "",
            "# HELP g1_docket_governance_siem_destinations Total SIEM forwarding destinations configured.",
            "# TYPE g1_docket_governance_siem_destinations gauge",
            f'g1_docket_governance_siem_destinations{{enabled="true"}} {enabled_dests}',
            f'g1_docket_governance_siem_destinations{{enabled="false"}} {disabled_dests}',
            "",
        ])
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")

    # ---------------------------------------------------------
    # REST APIs: Quarantine Management & Dual-Key Signoff
    # ---------------------------------------------------------
    @app.get("/api/quarantine")
    async def list_quarantine(request: Request, status: Optional[str] = None, limit: int = 50, offset: int = 0):
        require_session_and_role(request, QUARANTINE_READ_ROLES)
        return quarantine_store.list_items(status=status, limit=limit, offset=offset)

    @app.get("/api/quarantine/export")
    async def export_quarantine_items(request: Request, format: str = "json"):
        """Export all quarantined records as downloadable CSV or JSON for compliance audits."""
        require_session_and_role(request, QUARANTINE_READ_ROLES)
        import csv
        import io
        items = quarantine_store.list_items(limit=10000)
        if format.lower() == "csv":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["quarantine_id", "timestamp_utc", "event_type", "reason_code", "status", "locator_uri", "claimed_tier", "payload_digest"])
            for it in items:
                writer.writerow([
                    it.get("quarantine_id"),
                    it.get("timestamp_utc"),
                    it.get("event_type"),
                    it.get("reason_code"),
                    it.get("status"),
                    it.get("locator_uri"),
                    it.get("claimed_tier"),
                    it.get("payload_digest"),
                ])
            return Response(
                content=out.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=quarantine_export.csv"},
            )
        return Response(
            content=json.dumps({"total_items": len(items), "items": items}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=quarantine_export.json"},
        )

    @app.get("/api/quarantine/{quarantine_id}")
    async def get_quarantine_item(quarantine_id: str, request: Request):
        require_session_and_role(request, QUARANTINE_READ_ROLES)
        item = quarantine_store.get_item(quarantine_id)
        if not item:
            raise HTTPException(status_code=404, detail="Quarantine record not found.")
        return item

    @app.post("/api/quarantine/{quarantine_id}/stage-override")
    async def stage_override(quarantine_id: str, req: StageKey1Request, request: Request):
        try:
            if not is_demo_mode() and (req.requester_id or "").strip().lower().startswith("demo-"):
                raise HTTPException(status_code=403, detail="Demo requester identities are not permitted in production mode.")
            sess = get_current_user_session(request)
            if sess is None:
                if not is_demo_mode() or not (req.requester_id or "").strip():
                    raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED: Valid operator session required to stage overrides.")
                effective_requester = (req.requester_id or "").strip()
            else:
                require_session_and_role(request, QUARANTINE_STAGE_ROLES)
                auth_operator = sess.get("sub") or extract_authenticated_operator(request)
                effective_requester = (req.requester_id or auth_operator or "").strip()
                if not is_demo_mode():
                    if auth_operator and req.requester_id and req.requester_id.strip().lower() != auth_operator.strip().lower():
                        raise HTTPException(
                            status_code=403,
                            detail=f"Identity mismatch in production mode: Authenticated operator '{auth_operator}' does not match requester ID '{req.requester_id}'."
                        )
            if not effective_requester:
                raise HTTPException(status_code=400, detail="Requester identity required.")
            if not is_demo_mode() and effective_requester.lower().startswith("demo-"):
                raise HTTPException(status_code=403, detail="Demo requester identities are not permitted in production mode.")
            res = dual_key_manager.stage_override(
                quarantine_id=quarantine_id,
                requester_id=effective_requester,
                rationale=req.rationale,
            )
            await broadcast_event({
                "event_type": "HITL_OVERRIDE_REQUEST",
                "quarantine_id": quarantine_id,
                "operator": effective_requester,
                "rationale": req.rationale,
            })
            return res
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/quarantine/{quarantine_id}/approve-override")
    async def approve_override(quarantine_id: str, req: ApproveKey2Request, request: Request):
        try:
            sess = get_current_user_session(request)
            if sess is None:
                if not is_demo_mode() or not (req.approver_id or "").strip():
                    raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED: Valid operator session required for second-key approval.")
                effective_approver = (req.approver_id or "").strip()
            else:
                require_session_and_role(request, QUARANTINE_APPROVE_ROLES)
                auth_operator = sess.get("sub") or extract_authenticated_operator(request)
                effective_approver = (req.approver_id or auth_operator or "").strip()
                if not is_demo_mode():
                    if auth_operator and req.approver_id and req.approver_id.strip().lower() != auth_operator.strip().lower():
                        raise HTTPException(
                            status_code=403,
                            detail=f"Identity mismatch in production mode: Authenticated operator '{auth_operator}' does not match requested approver ID '{req.approver_id}'."
                        )
            if not effective_approver:
                raise HTTPException(status_code=400, detail="Approver identity required.")
            if not is_demo_mode() and effective_approver.lower().startswith("demo-"):
                raise HTTPException(status_code=403, detail="Demo approver identities are not permitted in production mode.")
            res = dual_key_manager.approve_and_release(
                quarantine_id=quarantine_id,
                approver_id=effective_approver,
                notes=req.notes or "",
                ttl_seconds=req.ttl_seconds or 7200,
            )
            await broadcast_event({
                "event_type": "HITL_DUAL_KEY_RELEASE",
                "quarantine_id": quarantine_id,
                "approver": effective_approver,
                "worm_hash": res["worm_hash"],
            })
            return res
        except FourEyesViolationError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/quarantine/{quarantine_id}/reject")
    async def reject_quarantine(quarantine_id: str, req: RejectRequest, request: Request):
        try:
            sess = get_current_user_session(request)
            if sess is None:
                if not is_demo_mode() or not (req.reviewer_id or "").strip():
                    raise HTTPException(status_code=401, detail="AUTHENTICATION_REQUIRED: Valid operator session required to reject incidents.")
                effective_reviewer = (req.reviewer_id or "").strip()
            else:
                require_session_and_role(request, QUARANTINE_STAGE_ROLES)
                auth_operator = sess.get("sub") or extract_authenticated_operator(request)
                effective_reviewer = (req.reviewer_id or auth_operator or "").strip()
            if not effective_reviewer:
                raise HTTPException(status_code=400, detail="Reviewer identity required.")
            dual_key_manager.reject(quarantine_id, effective_reviewer, req.reason)
            await broadcast_event({
                "event_type": "HITL_REJECTION",
                "quarantine_id": quarantine_id,
                "reviewer": effective_reviewer,
            })
            return {"status": "REJECTED", "quarantine_id": quarantine_id}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ---------------------------------------------------------
    # REST APIs: Cryptographic WORM Ledger
    # ---------------------------------------------------------
    @app.get("/api/worm/verify")
    async def audit_worm_chain():
        """Recalculate cryptographic hash-chain across entire JSONL WORM log and verify completeness against SQLite/checkpoint."""
        jsonl_path = cfg["storage"]["worm_jsonl_path"]
        db_path = cfg["storage"]["worm_sqlite_path"]
        return verify_ledger_integrity(jsonl_path, db_path=db_path)

    @app.get("/api/worm/events")
    async def get_worm_events(limit: int = 50, offset: int = 0, event_type: Optional[str] = None):
        return worm_ledger.get_events(limit=limit, offset=offset, event_type=event_type)

    @app.get("/api/worm/export")
    async def export_worm_ledger(format: str = "json"):
        """Export the cryptographic WORM audit ledger as downloadable CSV or JSON."""
        import csv
        import io
        events = worm_ledger.get_events(limit=10000)
        _, tip = worm_ledger.get_tip_hash()
        if format.lower() == "csv":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["entry_id", "timestamp_utc_iso8601", "event_type", "actor_identity", "payload_digest", "entry_hash", "prev_hash"])
            for e in events:
                writer.writerow([
                    e.get("entry_id"),
                    e.get("timestamp_utc_iso8601"),
                    e.get("event_type"),
                    e.get("actor_identity"),
                    e.get("payload_digest"),
                    e.get("entry_hash"),
                    e.get("previous_entry_hash") or e.get("prev_hash"),
                ])
            return Response(
                content=out.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=worm_ledger_export_{tip[:8]}.csv"},
            )
        return Response(
            content=json.dumps({"tip_hash": tip, "total_events": len(events), "events": events}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=worm_ledger_export_{tip[:8]}.json"},
        )

    # ---------------------------------------------------------
    # REST APIs: SIEM Destinations & Management
    # ---------------------------------------------------------
    @app.get("/api/siem/status")
    async def get_siem_status(request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        return siem_forwarder.get_destination_status()

    @app.post("/api/siem/{dest_id}/test")
    async def test_siem_destination(dest_id: str, request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        dest = siem_forwarder.destinations.get(dest_id)
        if not dest:
            raise HTTPException(status_code=404, detail=f"Destination '{dest_id}' not found.")

        # Create simulated probe event
        probe_event = {
            "entry_id": f"TEST-PING-{os.urandom(4).hex()}",
            "event_type": "SIEM_DISPATCH",
            "actor_identity": "admin:test-ping",
            "payload_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "metadata": {
                "reason_code": "PING_TEST",
                "clearance_tier": "Public",
                "destination_id": dest_id,
            },
        }

        try:
            sanitized = sanitize_for_siem(probe_event)
            siem_forwarder.dispatch_single_sync(dest, sanitized)
            return {"success": True, "message": f"Successfully delivered test probe to {dest.name}"}
        except Exception as e:
            # Enqueue into persistent buffer for retry
            siem_forwarder.enqueue_event(probe_event)
            return {"success": False, "error": str(e), "message": "Connection failed; probe enqueued to buffer for retry."}

    @app.get("/api/siem/mock-receivers")
    async def get_mock_receivers(request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        return mock_cluster.get_status()

    @app.post("/api/siem/mock-receivers/toggle")
    async def toggle_mock_receivers(request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        if mock_cluster._running:
            res = mock_cluster.stop()
        else:
            res = mock_cluster.start()
        return res

    @app.get("/api/siem/{dest_id}/config")
    async def get_siem_destination_config(dest_id: str, request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        dest = siem_forwarder.destinations.get(dest_id)
        if not dest:
            raise HTTPException(status_code=404, detail=f"Destination '{dest_id}' not found.")
        return _serialize_siem_destination_write_only(dest)

    @app.post("/api/siem/{dest_id}/config")
    async def update_siem_destination_config(dest_id: str, req: SIEMConfigUpdateRequest, request: Request):
        require_session_and_role(request, INTEGRATION_ADMIN_ROLES)
        dest = siem_forwarder.destinations.get(dest_id)
        if not dest:
            raise HTTPException(status_code=404, detail=f"Destination '{dest_id}' not found.")

        dest.enabled = req.enabled
        dest.endpoint_url = req.endpoint_url or ""
        if req.api_key is not None and req.api_key != "":
            dest.api_key = req.api_key
        if req.auth_header is not None and req.auth_header != "":
            dest.auth_header = req.auth_header
        dest.index_or_sourcetype = req.index_or_sourcetype or None
        dest.syslog_host = req.syslog_host or None
        dest.syslog_port = req.syslog_port or None
        dest.syslog_use_tls = req.syslog_use_tls
        dest.workspace_id = req.workspace_id or None
        dest.log_group_name = req.log_group_name or None
        if req.timeout_seconds:
            dest.timeout_seconds = req.timeout_seconds

        # Persist changes to config.yaml if present
        cfg_file_path = Path(config_path) if config_path else (Path(__file__).parent / "config.yaml")
        if cfg_file_path.exists():
            try:
                import yaml
                with open(cfg_file_path, "r", encoding="utf-8") as f:
                    file_cfg = yaml.safe_load(f) or {}
                for d in file_cfg.get("siem_destinations", []):
                    if d.get("id") == dest_id:
                        d["enabled"] = dest.enabled
                        d["endpoint_url"] = dest.endpoint_url
                        d["api_key"] = dest.api_key
                        d["auth_header"] = dest.auth_header
                        d["index_or_sourcetype"] = dest.index_or_sourcetype
                        d["syslog_host"] = dest.syslog_host
                        d["syslog_port"] = dest.syslog_port
                        d["syslog_use_tls"] = dest.syslog_use_tls
                        d["workspace_id"] = dest.workspace_id
                        d["log_group_name"] = dest.log_group_name
                        d["timeout_seconds"] = dest.timeout_seconds
                        break
                with open(cfg_file_path, "w", encoding="utf-8") as f:
                    yaml.dump(file_cfg, f, default_flow_style=False, sort_keys=False)
            except Exception as e:
                logger.warning(f"Could not persist SIEM config to YAML: {e}")

        return {"success": True, "destination": _serialize_siem_destination_write_only(dest)}

    # ---------------------------------------------------------
    # REST APIs: CI/CD Telemetry & Secret Security Posture
    # ---------------------------------------------------------
    @app.get("/api/governance/cicd-status")
    @app.get("/api/cicd/status")
    @app.post("/api/governance/cicd-status/refresh")
    async def get_governance_cicd_status(force: bool = False):
        """Retrieve real-time GitHub Actions test matrix telemetry and step diagnostics."""
        return fetch_cicd_status(force_refresh=True)

    @app.get("/api/governance/secret-audit")
    @app.get("/api/security/secret-audit")
    async def get_governance_secret_audit():
        """Retrieve continuous repository secret hygiene attestation metrics."""
        return fetch_secret_audit()

    @app.post("/api/governance/secret-audit/run")
    @app.post("/api/security/secret-audit/run")
    async def run_governance_secret_audit():
        """Re-run dynamic repository secret scan and broadcast verification to SSE stream."""
        audit_res = fetch_secret_audit()
        await broadcast_event({
            "event_type": "SECRET_AUDIT_COMPLETED",
            "verdict": audit_res.get("verdict", "CLEAN_PASS"),
            "active_keys": audit_res.get("tracked_files", {}).get("active_secrets_detected", 0),
            "timestamp": audit_res.get("timestamp_utc"),
        })
        return {"success": True, "audit": audit_res}

    # ---------------------------------------------------------
    # Boundary Ingress Interceptor (Called by Docket or Combine)
    # ---------------------------------------------------------
    @app.post("/api/intercept")
    async def intercept_boundary_event(req: BoundaryInterceptRequest):
        """
        Called when Docket (:18082) or Combine (:8000) evaluates a request (pass, fail, or redact).
        - If denial/block (DOCKET_DENIAL, COMBINE_THREAT_BLOCKED): stages in Quarantine queue.
        - For all events: appends to WORM Ledger, buffers to SIEM forwarders, and broadcasts to live SSE.
        """
        qid = None
        is_quarantine_candidate = (
            req.event_type in ("DOCKET_DENIAL", "COMBINE_THREAT_BLOCKED")
            or "DENIAL" in req.event_type.upper()
            or "BLOCK" in req.event_type.upper()
        )

        if is_quarantine_candidate:
            qid = quarantine_store.stage_quarantine(
                event_type=req.event_type,
                reason_code=req.reason_code,
                payload_digest=req.payload_digest,
                raw_payload=req.raw_payload or {},
                locator_uri=req.locator_uri or "urn:doc:unspecified",
                claimed_tier=req.claimed_tier or "Internal",
                triggered_rules=req.triggered_rules,
                extracted_text=req.extracted_text,
            )

        meta = {
            "reason_code": req.reason_code,
            "locator_uri": req.locator_uri,
            "claimed_tier": req.claimed_tier,
            "triggered_rules": req.triggered_rules,
        }
        if qid:
            meta["quarantine_id"] = qid
        if req.caller_clearance:
            meta["caller_clearance"] = req.caller_clearance
        if req.metadata:
            meta.update(req.metadata)

        worm_entry = worm_ledger.append_event(
            event_type=req.event_type,
            actor_identity=req.actor_identity or "boundary:prevalidator",
            payload_digest=req.payload_digest,
            metadata=meta,
        )

        siem_forwarder.enqueue_event(worm_entry)

        await broadcast_event({
            "event_type": req.event_type,
            "quarantine_id": qid,
            "reason_code": req.reason_code,
            "payload_digest": req.payload_digest,
            "locator_uri": req.locator_uri,
            "claimed_tier": req.claimed_tier,
            "timestamp": worm_entry.get("timestamp_utc_iso8601"),
            "entry_hash": worm_entry.get("entry_hash"),
        })

        status_str = "QUARANTINED" if qid else "LOGGED"
        return {"status": status_str, "quarantine_id": qid, "worm_entry_hash": worm_entry["entry_hash"]}

    # ---------------------------------------------------------
    # CI/CD Telemetry & Secret Hygiene Audit Endpoints
    # ---------------------------------------------------------
    @app.get("/api/cicd/status")
    async def get_cicd_status(request: Request):
        from governance.cicd_security import fetch_cicd_status
        return fetch_cicd_status()

    @app.get("/api/security/secret-audit")
    async def get_secret_audit(request: Request):
        from governance.cicd_security import fetch_secret_audit
        return fetch_secret_audit()

    # ---------------------------------------------------------
    # Server-Sent Events (SSE) Live Feed
    # ---------------------------------------------------------
    @app.get("/events/stream")
    async def sse_event_stream():
        async def event_generator() -> AsyncGenerator[str, None]:
            q: asyncio.Queue = asyncio.Queue()
            _sse_subscribers.append(q)
            try:
                # Initial handshake event
                yield f"data: {json.dumps({'event_type': 'CONNECTED', 'message': 'Subscribed to G1 Governance Event Stream'})}\n\n"
                while True:
                    msg = await q.get()
                    yield msg
            except asyncio.CancelledError:
                pass
            finally:
                if q in _sse_subscribers:
                    _sse_subscribers.remove(q)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app


app = create_governance_app()

if __name__ == "__main__":
    import uvicorn
    cfg = load_governance_config()
    uvicorn.run(
        app,
        host=cfg["server"]["host"],
        port=cfg["server"]["port"],
    )
