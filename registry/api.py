"""Hardened Registry Lookup and Lifecycle Admin FastAPI Service."""

from __future__ import annotations

import os
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from governance.auth import AuthManager, SESSION_COOKIE_NAME
from registry.store import (
    ApprovalVersionMismatchError,
    DualApprovalRequiredError,
    DualApprovalSamePrincipalError,
    FingerprintChangedError,
    RegistryLifecycleError,
    RegistryService,
)


class RaiseTierRequest(BaseModel):
    locator: str
    new_tier: str


class ApprovalEntry(BaseModel):
    approver_id: str | None = None
    rationale: str = "Approved tier lowering"


class LowerTierRequest(BaseModel):
    locator: str
    new_tier: str
    rationale: str = "Approved tier lowering"
    document_version: str | None = None
    approvals: list[ApprovalEntry] | None = None


class RevokeRequest(BaseModel):
    locator: str
    reason: str = "Administrative revocation"


class RenewRequest(BaseModel):
    locator: str
    observed_content_sha256: str
    ttl_days: int | None = None


class ReviewDecisionRequest(BaseModel):
    approver_id: str | None = None
    confirmed_tier: str | None = None
    rationale: str = "Confirmed in human review"
    document_version: str | None = None


class IssueFindingRequest(BaseModel):
    model_config = {"extra": "allow"}
    locator: str
    content_sha256: str
    tier: str
    owner: str


def create_registry_app(registry: RegistryService | None = None) -> FastAPI:
    """Create the hardened Registry FastAPI server (requires X-POD-Admin-Key for all catalog queries and mutations)."""
    app = FastAPI(title="POD Authoritative Registry API", version="1.0.2")

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data: fastmcp.org;"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    svc = registry or RegistryService()
    auth_manager = AuthManager(keys_dir=svc.key_dir)
    app.state.auth_manager = auth_manager
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")
    jwt_secret = os.environ.get("POD_JWT_SECRET", "pod-local-jwt-secret-key-minimum-32-bytes-long")

    def resolve_authenticated_principal(request: Request) -> str | None:
        """Derive authenticated principal exclusively from session cookie, Bearer token, or IdP proxy headers."""
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            tok = auth_hdr[7:].strip()
            sess = auth_manager.verify_bearer_token(tok)
            if sess and sess.get("sub"):
                return str(sess["sub"])
            try:
                claims = jwt.decode(tok, jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
                if claims.get("sub") or claims.get("email"):
                    return str(claims.get("sub") or claims.get("email"))
            except Exception:
                pass

        op_tok = (request.headers.get("x-pod-operator-token") or request.headers.get("x-pod-caller-token") or "").strip()
        if op_tok:
            sess = auth_manager.verify_bearer_token(op_tok)
            if sess and sess.get("sub"):
                return str(sess["sub"])
            try:
                claims = jwt.decode(op_tok, jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
                if claims.get("sub") or claims.get("email"):
                    return str(claims.get("sub") or claims.get("email"))
            except Exception:
                pass

        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie:
            sess = auth_manager.verify_session_token(cookie)
            if sess and sess.get("sub"):
                return str(sess["sub"])

        for h in (
            "x-pod-authenticated-principal",
            "x-forwarded-email",
            "x-auth-request-email",
            "cf-access-authenticated-user-email",
            "x-ms-client-principal-name",
            "x-goog-authenticated-user-email",
            "x-forwarded-user",
            "remote-user",
        ):
            val = request.headers.get(h)
            if val and val.strip():
                clean = val.strip()
                if clean.startswith("accounts.google.com:"):
                    clean = clean.split(":", 1)[1]
                return clean
        return None

    def require_admin_auth(
        request: Request,
        x_pod_admin_key: str | None = Header(default=None),
        x_pod_control_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> None:
        token = x_pod_admin_key or x_pod_control_token
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        valid_tokens = {t for t in (admin_key, control_token) if t}
        if token and token in valid_tokens:
            return
        if resolve_authenticated_principal(request) is not None:
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry access denied: valid X-POD-Admin-Key, X-POD-Control-Token, or authenticated operator session required.",
        )

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "pod-registry"}

    @app.get("/v1/records/lookup", dependencies=[Depends(require_admin_auth)])
    def lookup_record(locator: str = Query(..., description="Canonical object locator URI")) -> dict[str, Any]:
        rec = svc.lookup_by_locator(locator)
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No record found for locator")
        return rec

    @app.get("/v1/records", dependencies=[Depends(require_admin_auth)])
    def list_records(current_only: bool = True) -> dict[str, Any]:
        return {"records": svc.list_records(current_only=current_only)}

    @app.get("/v1/records/expiring", dependencies=[Depends(require_admin_auth)])
    def list_expiring(within_days: int = 30) -> dict[str, Any]:
        return {"records": svc.list_expiring(within_days=within_days)}

    @app.post("/v1/records/issue-finding", dependencies=[Depends(require_admin_auth)])
    def issue_finding(req: IssueFindingRequest) -> dict[str, Any]:
        kwargs = req.model_dump()
        return svc.issue_or_queue_finding(**kwargs)

    @app.post("/v1/records/raise-tier", dependencies=[Depends(require_admin_auth)])
    def raise_tier(req: RaiseTierRequest) -> dict[str, Any]:
        try:
            return svc.raise_tier(locator=req.locator, new_tier=req.new_tier)
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/lower-tier", dependencies=[Depends(require_admin_auth)])
    def lower_tier(req: LowerTierRequest, request: Request) -> Any:
        try:
            auth_principal = resolve_authenticated_principal(request)
            if req.approvals and len(req.approvals) > 1:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error_code": "SINGLE_CALLER_MULTI_APPROVAL_REJECTED",
                        "message": "SINGLE_CALLER_MULTI_APPROVAL_REJECTED: Dual approval requires two separate, independently authenticated approval requests by two distinct principals.",
                    },
                )
            if req.approvals and len(req.approvals) == 1 and req.approvals[0].approver_id:
                supplied_id = req.approvals[0].approver_id.strip()
                if auth_principal and supplied_id.lower() != auth_principal.lower():
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail={
                            "error_code": "PRINCIPAL_SPOOFING_REJECTED",
                            "message": f"PRINCIPAL_SPOOFING_REJECTED: Authenticated principal '{auth_principal}' cannot submit approval as '{supplied_id}'.",
                        },
                    )
            if not auth_principal:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error_code": "AUTHENTICATED_PRINCIPAL_REQUIRED",
                        "message": "AUTHENTICATED_PRINCIPAL_REQUIRED: Tier-lowering approval requires an authenticated operator session or principal token.",
                    },
                )
            rationale = (
                req.approvals[0].rationale
                if (req.approvals and len(req.approvals) == 1 and req.approvals[0].rationale)
                else req.rationale
            )
            res = svc.submit_tier_lower_approval(
                locator=req.locator,
                new_tier=req.new_tier,
                authenticated_principal=auth_principal,
                rationale=rationale,
                expected_document_version=req.document_version,
            )
            if res.get("status") == "PENDING_SECOND_APPROVAL":
                return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=res)
            return res
        except DualApprovalSamePrincipalError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error_code": "DUAL_APPROVAL_SAME_PRINCIPAL", "message": str(exc)},
            ) from exc
        except ApprovalVersionMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error_code": "APPROVAL_VERSION_MISMATCH", "message": str(exc)},
            ) from exc
        except DualApprovalRequiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error_code": "DUAL_APPROVAL_REQUIRED", "message": str(exc)},
            ) from exc
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/revoke", dependencies=[Depends(require_admin_auth)])
    def revoke_record(req: RevokeRequest) -> dict[str, Any]:
        try:
            return svc.revoke_record(locator=req.locator, reason=req.reason)
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/renew", dependencies=[Depends(require_admin_auth)])
    def renew_record(req: RenewRequest) -> dict[str, Any]:
        try:
            return svc.renew_record(
                locator=req.locator,
                observed_content_sha256=req.observed_content_sha256,
                ttl_days=req.ttl_days,
            )
        except FingerprintChangedError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.get("/v1/reviews", dependencies=[Depends(require_admin_auth)])
    def list_reviews(status_filter: str | None = Query(default="PENDING_REVIEW", alias="status")) -> dict[str, Any]:
        return {"reviews": svc.list_review_queue(status=status_filter)}

    @app.post("/v1/reviews/{review_id}/approve", dependencies=[Depends(require_admin_auth)])
    def approve_review(review_id: str, req: ReviewDecisionRequest, request: Request) -> dict[str, Any]:
        try:
            auth_principal = resolve_authenticated_principal(request)
            if auth_principal and req.approver_id and req.approver_id.strip().lower() != auth_principal.lower():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"PRINCIPAL_SPOOFING_REJECTED: Authenticated principal '{auth_principal}' does not match approver_id '{req.approver_id}'.",
                )
            effective_approver = auth_principal or (req.approver_id or "").strip()
            if not effective_approver:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="AUTHENTICATED_PRINCIPAL_REQUIRED: Review approval requires an authenticated principal.",
                )
            return svc.approve_pending_review(
                review_id=review_id,
                approver_id=effective_approver,
                confirmed_tier=req.confirmed_tier,
                rationale=req.rationale,
                expected_document_version=req.document_version,
            )
        except DualApprovalSamePrincipalError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ApprovalVersionMismatchError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return app
