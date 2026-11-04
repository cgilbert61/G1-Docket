"""FastAPI Prevalidator Proxy speaking standard OpenAI `/v1/chat/completions` and Anthropic `/v1/messages`, plus Directory Batch Prevalidation and Unified Operator Dashboard."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from engine.directory_bridge import (
    compute_bytes_sha256_hex,
    discover_selectable_drives_and_directories,
    iter_scannable_files,
    iter_scannable_files_unbounded,
    resolve_pc_directory_path,
)
from engine.storage_connectors import is_enterprise_store_uri
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from registry.signing import Keyring, compute_file_sha256


_governance_target_cache: str | None = None


async def _emit_governance_event_async(
    event_type: str,
    reason_code: str,
    payload_digest: str,
    raw_payload: dict[str, Any] | None,
    locator_uri: str,
    claimed_tier: str,
    triggered_rules: list[str],
    extracted_text: str | None = None,
    caller_clearance: str | None = None,
) -> None:
    """Non-blocking background emitter to G1 Governance, WORM ledger & SIEM hub (:18084)."""
    global _governance_target_cache
    candidate_urls: list[str] = []
    env_url = os.environ.get("POD_GOVERNANCE_URL")
    if env_url:
        candidate_urls.append(env_url.rstrip("/"))
    if _governance_target_cache:
        candidate_urls.append(_governance_target_cache)
    candidate_urls.extend(["http://host.docker.internal:18084", "http://127.0.0.1:18084", "http://localhost:18084"])

    seen = set()
    deduped = []
    for u in candidate_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    payload = {
        "event_type": event_type,
        "reason_code": reason_code,
        "payload_digest": payload_digest,
        "raw_payload": raw_payload or {},
        "locator_uri": locator_uri,
        "claimed_tier": claimed_tier,
        "triggered_rules": triggered_rules,
        "extracted_text": extracted_text,
        "actor_identity": "boundary:prevalidator",
        "caller_clearance": caller_clearance,
    }

    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            for base in deduped:
                try:
                    resp = await client.post(f"{base}/api/intercept", json=payload)
                    if resp.status_code in (200, 201):
                        _governance_target_cache = base
                        return
                except Exception:
                    continue
    except Exception:
        pass


def emit_governance_event_background(
    event_type: str,
    reason_code: str,
    payload_digest: str,
    raw_payload: dict[str, Any] | None,
    locator_uri: str,
    claimed_tier: str,
    triggered_rules: list[str],
    extracted_text: str | None = None,
    caller_clearance: str | None = None,
) -> None:
    """Fire-and-forget emitter that does not block the inference hot-path."""
    try:
        asyncio.create_task(
            _emit_governance_event_async(
                event_type=event_type,
                reason_code=reason_code,
                payload_digest=payload_digest,
                raw_payload=raw_payload,
                locator_uri=locator_uri,
                claimed_tier=claimed_tier,
                triggered_rules=triggered_rules,
                extracted_text=extracted_text,
                caller_clearance=caller_clearance,
            )
        )
    except Exception:
        pass


def _extract_last_user_text(payload: dict[str, Any]) -> str:
    messages = payload.get("messages", [])
    for msg in reversed(messages):
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


async def _mock_openai_sse_stream(model: str, text: str) -> AsyncIterator[bytes]:
    chunk_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    words = [f"[Gateway Ack ({model})]:", *text.split()[:25]]
    for word in words:
        data = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(data)}\n\n".encode("utf-8")
    done_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    yield f"data: {json.dumps(done_chunk)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


async def _mock_anthropic_sse_stream(model: str, text: str) -> AsyncIterator[bytes]:
    msg_id = f"msg_{uuid.uuid4().hex[:12]}"
    start_evt = {
        "type": "message_start",
        "message": {"id": msg_id, "type": "message", "role": "assistant", "model": model, "content": []},
    }
    yield f"event: message_start\ndata: {json.dumps(start_evt)}\n\n".encode("utf-8")
    delta_evt = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": f"[Anthropic Gateway Ack ({model})]: {text[:160]}"},
    }
    yield f"event: content_block_delta\ndata: {json.dumps(delta_evt)}\n\n".encode("utf-8")
    stop_evt = {"type": "message_stop"}
    yield f"event: message_stop\ndata: {json.dumps(stop_evt)}\n\n".encode("utf-8")


# Load modular HTML templates from prevalidator/templates/
_TEMPLATES_DIR = Path(__file__).parent / "templates"

def _load_template(filename: str) -> str:
    tpl_path = _TEMPLATES_DIR / filename
    if tpl_path.exists():
        return tpl_path.read_text(encoding="utf-8")
    return f"<!-- Template {filename} not found -->"

DASHBOARD_HTML = _load_template("dashboard.html")
DLP_CONNECTOR_HTML = _load_template("dlp_connector.html")



def create_prevalidator_app(
    enforcer: PrevalidatorEnforcer | None = None,
    upstream_gateway_url: str | None = None,
    snapshot_file: str | Path | None = None,
    engine_service_url: str | None = None,
) -> FastAPI:
    """Create the Prevalidator proxy application."""
    app = FastAPI(title="G1 Docket by G1163RT Security Labs — AI Gateway Prevalidator", version="0.1.0")

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

    logo_path = Path(__file__).resolve().parent / "g1_logo.png"

    if enforcer is None:
        pub_key_dir = Path(os.environ.get("POD_PUBLIC_KEY_DIR") or os.environ.get("POD_KEY_DIR", "./.pod_keys"))
        keyring = Keyring(public_key_dir=pub_key_dir, verification_only=True)
        store = InMemorySnapshotStore(keyring)
        snap_path = Path(snapshot_file or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json"))
        if snap_path.exists():
            try:
                store.load_from_file(snap_path)
            except Exception:
                # If a stale snapshot from an earlier boot exists on disk, start cleanly (fail-closed)
                # until SnapshotPublisher/Engine pushes a fresh signed snapshot.
                pass
        mode = os.environ.get("POD_PREVALIDATOR_MODE", "enforce")
        enforcer = PrevalidatorEnforcer(snapshot_store=store, mode=mode)

    upstream_url = (upstream_gateway_url or os.environ.get("POD_UPSTREAM_GATEWAY_URL", "mock://local")).rstrip("/")
    engine_url = (engine_service_url or os.environ.get("POD_ENGINE_SERVICE_URL", "http://engine:8083")).rstrip("/")
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")
    llm_config_file = Path(os.environ.get("POD_LLM_CONFIG_FILE", "./llm_provider_config.json"))

    llm_config: dict[str, Any] = {
        "provider_name": "Built-in G1 Gateway",
        "protocol": "openai",
        "base_url": upstream_url,
        "default_model": "local-model",
        "egress_class": "local_only",
        "api_key": os.environ.get("POD_UPSTREAM_API_KEY", ""),
    }
    if llm_config_file.exists():
        try:
            saved_cfg = json.loads(llm_config_file.read_text(encoding="utf-8"))
            if isinstance(saved_cfg, dict) and saved_cfg.get("base_url"):
                llm_config.update(saved_cfg)
                if llm_config.get("default_model") and llm_config.get("egress_class"):
                    enforcer.route_egress_map[llm_config["default_model"]] = llm_config["egress_class"]
        except Exception:
            pass

    def _public_llm_config() -> dict[str, Any]:
        raw_key = llm_config.get("api_key") or ""
        masked = f"{raw_key[:5]}...{raw_key[-4:]}" if len(raw_key) > 9 else ("****" if raw_key else "")
        return {
            "provider_name": llm_config["provider_name"],
            "protocol": llm_config["protocol"],
            "base_url": llm_config["base_url"],
            "default_model": llm_config["default_model"],
            "egress_class": llm_config["egress_class"],
            "has_api_key": bool(raw_key),
            "api_key_masked": masked,
            "route_egress_map": enforcer.route_egress_map,
        }

    @app.get("/", response_class=HTMLResponse)
    def root_console() -> HTMLResponse:
        return HTMLResponse(
            content=_load_template("dashboard.html"),
            media_type="text/html; charset=utf-8",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    @app.get("/dlp", response_class=HTMLResponse)
    def dlp_connector_console() -> HTMLResponse:
        return HTMLResponse(
            content=_load_template("dlp_connector.html"),
            media_type="text/html; charset=utf-8",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    @app.get("/v1/admin/dlp/config")
    async def proxy_dlp_get_config(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/dlp/config")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/config")
    async def proxy_dlp_save_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/config", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage1-inspect-labels")
    async def proxy_dlp_stage1_inspect(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage1-inspect-labels", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage1-stamp-sample")
    async def proxy_dlp_stage1_stamp(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage1-stamp-sample", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage2-pull-catalog")
    async def proxy_dlp_stage2_pull(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage2-pull-catalog", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage3-writeback")
    async def proxy_dlp_stage3_writeback(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage3-writeback", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/assets/g1-logo.png", include_in_schema=False)
    def serve_g1_logo() -> FileResponse:
        return FileResponse(logo_path, media_type="image/png")

    @app.get("/favicon.ico", include_in_schema=False)
    def serve_favicon() -> FileResponse:
        return FileResponse(logo_path, media_type="image/png")

    @app.get("/v1/admin/snapshot-view")
    def get_snapshot_view(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return {"snapshot": enforcer.snapshot_store.get_active_snapshot()}

    @app.get("/v1/admin/browse-dir")
    async def proxy_browse_dir(
        path: str = Query(default="D:\\attestation"),
        x_pod_admin_key: str | None = Header(default=None),
    ) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/browse-dir", params={"path": path})
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/pc-folders")
    async def proxy_pc_folders(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/pc-folders")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/datastores")
    async def proxy_get_datastores(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/datastores")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/datastores")
    async def proxy_register_datastore(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/datastores", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/events/storage")
    async def proxy_storage_event(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/events/storage", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/crawler/status")
    async def proxy_crawler_status(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/crawler/status")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/crawler/control")
    async def proxy_crawler_control(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/crawler/control", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/record-detail")
    async def proxy_record_detail(
        locator: str = Query(..., description="Canonical object locator URI"),
        x_pod_admin_key: str | None = Header(default=None),
    ) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        snap = enforcer.snapshot_store.get_active_snapshot()
        snap_entries = snap.get("entries", {}) if snap else {}
        snap_entry = snap_entries.get(locator)
        data: dict[str, Any] = {
            "found": False,
            "locator": locator,
            "in_active_snapshot": snap_entry is not None,
            "snapshot_id": snap.get("snapshot_id") if snap else None,
            "snapshot_sequence": snap.get("sequence_number") if snap else None,
            "snapshot_entry": snap_entry,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(f"{engine_url}/v1/record-detail", params={"locator": locator})
                if r.status_code == 200:
                    eng_data = r.json()
                    data.update(eng_data)
        except Exception as exc:
            data["engine_lookup_warning"] = str(exc)
        return JSONResponse(status_code=200, content=data)

    @app.post("/v1/admin/attest-directory")
    async def proxy_attest_directory(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                r = await client.post(f"{engine_url}/v1/attest-directory", json=body)
                try:
                    payload = r.json()
                except Exception:
                    payload = {"detail": r.text or f"Engine returned HTTP {r.status_code}"}
                return JSONResponse(status_code=r.status_code, content=payload)
        except Exception as exc:
            return JSONResponse(status_code=502, content={"detail": f"Attestation Engine request failed or timed out: {exc}"})

    @app.post("/v1/admin/add-unattested-file")
    async def proxy_add_unattested(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/demo-folder/add-unattested", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/prevalidate-directory")
    async def prevalidate_directory(request: Request) -> dict[str, Any]:
        """Scan every file in a directory (by PC path or browser folder picker upload) against the in-memory signed snapshot."""
        t_wall_start_ns = time.perf_counter_ns()
        body = await request.json()
        caller_key = body.get("caller_key", "pod-key-confidential")
        model = body.get("model", "local-model")
        uploaded_files = body.get("files")
        directory_path = body.get("directory_path")

        snap = enforcer.snapshot_store.get_active_snapshot()
        entries = snap.get("entries", {}) if snap else {}

        file_candidates: list[tuple[str, str, str]] = []  # (file_name, locator, observed_sha256)
        dir_label = directory_path or "picked-folder"
        if uploaded_files:
            folder_slug = "picked-folder"
            for item in uploaded_files:
                rel = item["relative_path"].replace("\\", "/").lstrip("/")
                parts = rel.split("/")
                if len(parts) > 1:
                    folder_slug = parts[0]
                    rel_inside = "/".join(parts[1:])
                else:
                    rel_inside = parts[0]
                raw_bytes = base64.b64decode(item["content_b64"])
                sha = compute_bytes_sha256_hex(raw_bytes)
                loc = f"file://pc-dir/{folder_slug}/{rel_inside}"
                file_candidates.append((rel_inside, loc, sha))
        elif directory_path and is_enterprise_store_uri(directory_path):
            async with httpx.AsyncClient(timeout=20.0) as client:
                r_objs = await client.get(f"{engine_url}/v1/datastores/objects", params={"uri": directory_path})
                if r_objs.status_code != 200:
                    raise HTTPException(status_code=r_objs.status_code, detail=r_objs.text)
                obj_data = r_objs.json()
                dir_label = obj_data.get("store_label") or directory_path
                for item in obj_data.get("objects", []):
                    file_candidates.append((item["file_name"], item["locator"], item["observed_sha256"]))
        elif directory_path:
            max_files = int(body.get("max_files", 120))
            include_code_dirs = bool(body.get("include_code_dirs", False))
            try:
                target_dir, locator_base = resolve_pc_directory_path(directory_path)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

            for p, rel_inside in iter_scannable_files_unbounded(target_dir, include_code_dirs=include_code_dirs):
                try:
                    sha = compute_file_sha256(p)
                    loc = f"{locator_base.rstrip('/')}/{rel_inside}"
                    file_candidates.append((rel_inside, loc, sha))
                    if max_files > 0 and len(file_candidates) >= max_files:
                        break
                except OSError:
                    continue
        else:
            raise HTTPException(status_code=400, detail="Provide either directory_path or files.")

        passed_count = 0
        allow_count = 0
        strip_count = 0
        failed_count = 0
        unattested_count = 0
        hash_drift_count = 0
        policy_denied_count = 0
        file_results: list[dict[str, Any]] = []
        in_memory_enforcer_ns = 0

        for file_name, loc, obs_sha in file_candidates:
            snap_entry = entries.get(loc)
            sim_payload = {
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": f'<pod:object locator="{loc}" sha256="{obs_sha}">File content check</pod:object>',
                    }
                ],
            }
            t_eval_ns = time.perf_counter_ns()
            try:
                outcome = enforcer.evaluate_request(
                    payload=sim_payload,
                    headers={"X-POD-Caller-Key": caller_key},
                    verify_inline_text=False,
                )
            finally:
                in_memory_enforcer_ns += max(100, time.perf_counter_ns() - t_eval_ns)
            reasons = outcome.audit_entry.reason_codes
            is_clean_pass = len(reasons) == 0 and outcome.allowed_to_forward
            is_observe_mode = enforcer.mode == "observe"
            is_pass = is_clean_pass or (is_observe_mode and outcome.allowed_to_forward)

            if not snap_entry:
                att_state = "UNATTESTED"
                tier = "NONE"
                unattested_count += 1
                if is_observe_mode:
                    reason_detail = "OBSERVE MODE (FORWARDED + LOGGED) — Unattested file (would block in Enforce Mode)"
                else:
                    reason_detail = "UNATTESTED — No signed record in snapshot"
            elif snap_entry["content_sha256"].lower() != obs_sha.lower():
                att_state = "HASH_DRIFT"
                tier = snap_entry["tier"]
                unattested_count += 1
                hash_drift_count += 1
                if is_observe_mode:
                    reason_detail = "OBSERVE MODE (FORWARDED + LOGGED) — File SHA-256 modified (would block in Enforce Mode)"
                else:
                    reason_detail = "UNATTESTED — File content SHA-256 modified since attestation"
            else:
                att_state = f"ATTESTED ({snap_entry['status'].upper()})"
                tier = snap_entry["tier"]
                if is_clean_pass:
                    if outcome.audit_entry.decision == "strip":
                        strip_count += 1
                        reason_detail = "PASSED (STRIP) — Confidential content stripped per policy"
                    else:
                        allow_count += 1
                        reason_detail = "PASSED (ALLOW) — Hash & policy verified"
                else:
                    policy_denied_count += 1
                    if is_observe_mode:
                        reason_detail = f"OBSERVE MODE (FORWARDED + LOGGED) — Would block in Enforce Mode: {', '.join(reasons)}"
                    else:
                        reason_detail = f"BLOCKED — {', '.join(reasons)}"

            if is_clean_pass:
                passed_count += 1
                verdict = "PASS (STRIP)" if outcome.audit_entry.decision == "strip" else "PASS (ALLOW)"
            elif is_observe_mode and outcome.allowed_to_forward:
                passed_count += 1
                verdict = "OBSERVED (WOULD BLOCK)"
            else:
                failed_count += 1
                verdict = "FAILED / BLOCKED"

            file_results.append(
                {
                    "file_name": file_name,
                    "locator": loc,
                    "observed_sha256": obs_sha,
                    "attestation_state": att_state,
                    "tier": tier,
                    "passed": is_pass,
                    "verdict": verdict,
                    "reason_codes": reasons,
                    "reason_detail": reason_detail,
                }
            )

        total_count = len(file_candidates)
        total_wall_ms = round((time.perf_counter_ns() - t_wall_start_ns) / 1_000_000.0, 2)
        enforcer_ms = round(in_memory_enforcer_ns / 1_000_000.0, 3)
        avg_file_us = round((in_memory_enforcer_ns / 1_000.0) / max(1, total_count), 1)
        files_per_sec = round((total_count / max(0.0001, in_memory_enforcer_ns / 1_000_000_000.0)), 1)
        enforcer.last_directory_scan_metrics = {
            "total_files": total_count,
            "total_wall_ms": total_wall_ms,
            "in_memory_enforcer_ms": enforcer_ms,
            "avg_per_file_us": avg_file_us,
            "files_per_sec": files_per_sec,
        }

        pure_unattested = unattested_count - hash_drift_count
        mode_tag = "OBSERVE MODE (Audit-Only — Violations Forwarded & Logged)" if enforcer.mode == "observe" else "ENFORCE MODE (Active Blocking)"
        english_summary = (
            f"[{mode_tag}] Prevalidator scanned {total_count} total file(s) in '{dir_label}' in {enforcer_ms} ms in-memory ({avg_file_us} µs/file; {total_wall_ms} ms incl. disk SHA-256): "
            f"{passed_count} of {total_count} file(s) PASSED/FORWARDED ({allow_count} Clean Allowed, {strip_count} Stripped) and "
            f"{failed_count} of {total_count} file(s) BLOCKED "
            f"({pure_unattested} Unattested file(s) with no signed record, "
            f"{hash_drift_count} Modified/Hash-drift file(s), "
            f"{policy_denied_count} Policy/Clearance violation(s))."
        )

        return {
            "mode": enforcer.mode,
            "directory": dir_label,
            "total_files": total_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "unattested_count": unattested_count,
            "english_summary": english_summary,
            "caller_key": caller_key,
            "model": model,
            "latency": enforcer.get_latency_telemetry(),
            "files": file_results,
        }

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        snap = enforcer.snapshot_store.get_active_snapshot()
        return {
            "status": "ok" if snap is not None else "stale_or_missing_snapshot",
            "mode": enforcer.mode,
            "snapshot_sequence": snap["sequence_number"] if snap else None,
            "latency": enforcer.get_latency_telemetry(),
        }

    @app.post("/v1/admin/latency-benchmark")
    async def run_latency_benchmark_endpoint(
        request: Request,
        x_pod_admin_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        iterations = min(500, max(10, int(body.get("iterations", 100))))
        prompts = [
            (
                "gpt-4o",
                "pod-key-public",
                'Summarize doc:\n<pod:object locator="file://estate/fileshare/product_overview_public.md">Open Source AI Architecture Overview</pod:object>',
            ),
            (
                "local-model",
                "pod-key-confidential",
                'HR policy guidance:\n<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">diana.prince@example.org | salary: $145,000</pod:object>',
            ),
            (
                "gpt-4o",
                "pod-key-restricted",
                'Analyze intake:\n<pod:object locator="file://estate/fileshare/clinical_intake_restricted.txt">Patient SSN: 412-58-9021, MRN-8839201</pod:object>',
            ),
            (
                "gpt-4o",
                "pod-key-public",
                '<pod:object locator="file://estate/fileshare/unverified_notes_ambiguous.txt">AMBIGUOUS_REF_9042</pod:object>',
            ),
        ]
        t0_ns = time.perf_counter_ns()
        for idx in range(iterations):
            model_id, caller_k, content = prompts[idx % len(prompts)]
            enforcer.evaluate_request(
                payload={"model": model_id, "messages": [{"role": "user", "content": content}]},
                headers={"X-POD-Caller-Key": caller_k},
            )
        wall_ms = round((time.perf_counter_ns() - t0_ns) / 1_000_000.0, 3)
        avg_us = round(((time.perf_counter_ns() - t0_ns) / 1_000.0) / iterations, 2)
        return {
            "iterations": iterations,
            "benchmark_wall_ms": wall_ms,
            "avg_eval_us": avg_us,
            "latency": enforcer.get_latency_telemetry(),
        }

    @app.get("/v1/admin/llm-config")
    def get_llm_config(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return _public_llm_config()

    @app.post("/v1/admin/llm-config")
    async def update_llm_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        provider_name = (body.get("provider_name") or "Custom LLM Provider").strip()
        protocol = (body.get("protocol") or "openai").strip().lower()
        base_url = (body.get("base_url") or "").strip().rstrip("/")
        default_model = (body.get("default_model") or "local-model").strip()
        egress_class = (body.get("egress_class") or "local_only").strip()
        new_api_key = body.get("api_key")

        if not base_url:
            raise HTTPException(status_code=400, detail="base_url is required")
        if egress_class not in ("local_only", "private_cloud", "public_api"):
            raise HTTPException(status_code=400, detail="egress_class must be local_only, private_cloud, or public_api")

        llm_config["provider_name"] = provider_name
        llm_config["protocol"] = protocol
        llm_config["base_url"] = base_url
        llm_config["default_model"] = default_model
        llm_config["egress_class"] = egress_class
        if new_api_key is not None and str(new_api_key).strip() != "":
            llm_config["api_key"] = str(new_api_key).strip()

        enforcer.route_egress_map[default_model] = egress_class
        try:
            llm_config_file.parent.mkdir(parents=True, exist_ok=True)
            llm_config_file.write_text(json.dumps(llm_config, indent=2), encoding="utf-8")
        except Exception:
            pass

        return _public_llm_config()

    @app.post("/v1/admin/llm-config/test")
    async def test_llm_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        base_url = (body.get("base_url") or llm_config["base_url"]).strip().rstrip("/")
        egress_class = (body.get("egress_class") or llm_config["egress_class"]).strip()
        api_key = (body.get("api_key") or llm_config.get("api_key") or "").strip()

        if base_url.startswith("mock://"):
            return {
                "reachable": True,
                "base_url": base_url,
                "status_code": 200,
                "latency_ms": 0.2,
                "discovered_models": ["local-model", "vpc-model", "gpt-4o"],
            }

        req_headers: dict[str, str] = {}
        if api_key:
            req_headers["Authorization"] = f"Bearer {api_key}"
            req_headers["x-api-key"] = api_key
            req_headers["anthropic-version"] = "2023-06-01"

        t0 = time.perf_counter()
        discovered_models: list[str] = []
        status_code = 0
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                # Probe /v1/models first, then /api/tags (Ollama), then /healthz
                for probe_path in ("/v1/models", "/models", "/api/tags", "/healthz"):
                    try:
                        r = await client.get(f"{base_url}{probe_path}", headers=req_headers)
                        status_code = r.status_code
                        if r.status_code < 500:
                            try:
                                j = r.json()
                                if isinstance(j, dict):
                                    if isinstance(j.get("data"), list):
                                        discovered_models = [str(m.get("id")) for m in j["data"] if isinstance(m, dict) and m.get("id")]
                                    elif isinstance(j.get("models"), list):
                                        discovered_models = [str(m.get("name") or m.get("id")) for m in j["models"] if isinstance(m, dict)]
                            except Exception:
                                pass
                            break
                    except Exception:
                        continue
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if status_code == 0:
                return {"reachable": False, "base_url": base_url, "error": f"Could not connect to {base_url}"}
            for m_id in discovered_models:
                if egress_class in ("local_only", "private_cloud", "public_api"):
                    enforcer.route_egress_map[m_id] = egress_class
            return {
                "reachable": True,
                "base_url": base_url,
                "status_code": status_code,
                "latency_ms": latency_ms,
                "discovered_models": discovered_models,
            }
        except Exception as exc:
            return {"reachable": False, "base_url": base_url, "error": str(exc)}

    _shared_upstream_client: httpx.AsyncClient | None = None

    def get_shared_upstream_client() -> httpx.AsyncClient:
        nonlocal _shared_upstream_client
        if _shared_upstream_client is None or _shared_upstream_client.is_closed:
            _shared_upstream_client = httpx.AsyncClient(
                timeout=60.0,
                limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)
            )
        return _shared_upstream_client

    @app.post("/v1/chat/completions")
    async def openai_chat_completions(request: Request) -> Any:
        payload = await request.json()
        headers = dict(request.headers)
        outcome = enforcer.evaluate_request(payload=payload, headers=headers)

        user_text = _extract_last_user_text(payload)
        p_digest = compute_bytes_sha256_hex(user_text.encode("utf-8")) if user_text else compute_bytes_sha256_hex(json.dumps(payload, sort_keys=True).encode("utf-8"))
        loc_uri = outcome.audit_entry.locators_evaluated[0] if (outcome.audit_entry and outcome.audit_entry.locators_evaluated) else "urn:prompt:openai"
        cl_tier = outcome.audit_entry.caller_clearance if outcome.audit_entry else "Public"
        reasons = outcome.audit_entry.reason_codes if outcome.audit_entry else []

        if not outcome.allowed_to_forward:
            emit_governance_event_background(
                event_type="DOCKET_DENIAL",
                reason_code=reasons[0] if reasons else "POLICY_DENIED",
                payload_digest=p_digest,
                raw_payload=payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )
            denial_headers = {
                "X-Blocked-By": "G1-Docket-Prevalidator",
                "X-POD-Attestation-Verdict": "BLOCKED",
                "X-POD-Reason-Codes": ",".join(reasons) if reasons else "policy_denied",
            }
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=outcome.client_denial_body, headers=denial_headers)

        if outcome.audit_entry and (outcome.audit_entry.decision == "strip" or outcome.audit_entry.stripped_locators):
            emit_governance_event_background(
                event_type="COMBINE_PII_REDACTED",
                reason_code="CONFIDENTIAL_BLOCK_STRIPPED",
                payload_digest=p_digest,
                raw_payload=outcome.transformed_payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )
        else:
            emit_governance_event_background(
                event_type="DOCKET_ADMISSION",
                reason_code="POLICY_ALLOWED",
                payload_digest=p_digest,
                raw_payload=outcome.transformed_payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )

        clean_payload = outcome.transformed_payload
        model = clean_payload.get("model", llm_config.get("default_model", "gpt-4o"))
        is_stream = bool(clean_payload.get("stream", False))
        active_base_url = llm_config["base_url"]

        if active_base_url.startswith("mock://"):
            user_text = _extract_last_user_text(clean_payload)
            if is_stream:
                return StreamingResponse(_mock_openai_sse_stream(model, user_text), media_type="text/event-stream")
            return {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"[Gateway Ack ({model})]: {user_text}",
                        },
                        "finish_reason": "stop",
                    }
                ],
            }

        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "x-pod-locators", "x-pod-caller-key", "x-pod-caller-token")
        }
        if outcome.audit_entry and outcome.audit_entry.locators_evaluated:
            forward_headers["X-Docket-Attestation-Verdict"] = outcome.audit_entry.decision.upper()
            forward_headers["X-Docket-Clearance-Tier"] = outcome.audit_entry.caller_clearance.upper()
            forward_headers["X-Docket-Attested-Locators"] = ",".join(outcome.audit_entry.locators_evaluated)
            forward_headers["X-Docket-Attestation-Timestamp"] = outcome.audit_entry.timestamp
        else:
            forward_headers["X-Docket-Attestation-Verdict"] = "PASSTHROUGH_UNATTESTED"
            forward_headers["X-Docket-Clearance-Tier"] = "PUBLIC"
            forward_headers["X-Docket-Attested-Locators"] = ""

        if llm_config.get("api_key") and "authorization" not in {k.lower() for k in forward_headers}:
            forward_headers["Authorization"] = f"Bearer {llm_config['api_key']}"

        target_endpoint = f"{active_base_url}/chat/completions" if active_base_url.endswith("/v1") or active_base_url.endswith("/openai") else f"{active_base_url}/v1/chat/completions"
        if is_stream:
            client = httpx.AsyncClient(timeout=60.0)
            req = client.build_request("POST", target_endpoint, json=clean_payload, headers=forward_headers)
            resp = await client.send(req, stream=True)

            async def stream_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for chunk in resp.aiter_raw():
                        yield chunk
                finally:
                    await resp.aclose()
                    await client.aclose()

            return StreamingResponse(stream_passthrough(), status_code=resp.status_code, media_type="text/event-stream")

        client = get_shared_upstream_client()
        resp = await client.post(target_endpoint, json=clean_payload, headers=forward_headers)
        return JSONResponse(status_code=resp.status_code, content=resp.json())

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Any:
        payload = await request.json()
        headers = dict(request.headers)
        outcome = enforcer.evaluate_request(payload=payload, headers=headers)

        user_text = _extract_last_user_text(payload)
        p_digest = compute_bytes_sha256_hex(user_text.encode("utf-8")) if user_text else compute_bytes_sha256_hex(json.dumps(payload, sort_keys=True).encode("utf-8"))
        loc_uri = outcome.audit_entry.locators_evaluated[0] if (outcome.audit_entry and outcome.audit_entry.locators_evaluated) else "urn:prompt:anthropic"
        cl_tier = outcome.audit_entry.caller_clearance if outcome.audit_entry else "Public"
        reasons = outcome.audit_entry.reason_codes if outcome.audit_entry else []

        if not outcome.allowed_to_forward:
            emit_governance_event_background(
                event_type="DOCKET_DENIAL",
                reason_code=reasons[0] if reasons else "POLICY_DENIED",
                payload_digest=p_digest,
                raw_payload=payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )
            denial_headers = {
                "X-Blocked-By": "G1-Docket-Prevalidator",
                "X-POD-Attestation-Verdict": "BLOCKED",
                "X-POD-Reason-Codes": ",".join(reasons) if reasons else "policy_denied",
            }
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=outcome.client_denial_body, headers=denial_headers)

        if outcome.audit_entry and (outcome.audit_entry.decision == "strip" or outcome.audit_entry.stripped_locators):
            emit_governance_event_background(
                event_type="COMBINE_PII_REDACTED",
                reason_code="CONFIDENTIAL_BLOCK_STRIPPED",
                payload_digest=p_digest,
                raw_payload=outcome.transformed_payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )
        else:
            emit_governance_event_background(
                event_type="DOCKET_ADMISSION",
                reason_code="POLICY_ALLOWED",
                payload_digest=p_digest,
                raw_payload=outcome.transformed_payload,
                locator_uri=loc_uri,
                claimed_tier=cl_tier,
                triggered_rules=reasons,
                extracted_text=user_text,
                caller_clearance=cl_tier,
            )

        clean_payload = outcome.transformed_payload
        model = clean_payload.get("model", llm_config.get("default_model", "claude-3-5-sonnet"))
        is_stream = bool(clean_payload.get("stream", False))
        active_base_url = llm_config["base_url"]

        if active_base_url.startswith("mock://"):
            user_text = _extract_last_user_text(clean_payload)
            if is_stream:
                return StreamingResponse(_mock_anthropic_sse_stream(model, user_text), media_type="text/event-stream")
            return {
                "id": f"msg_{uuid.uuid4().hex[:12]}",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [
                    {
                        "type": "text",
                        "text": f"[Anthropic Gateway Ack ({model})]: {user_text}",
                    }
                ],
                "stop_reason": "end_turn",
            }

        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "x-pod-locators", "x-pod-caller-key", "x-pod-caller-token")
        }
        if llm_config.get("api_key"):
            lower_keys = {k.lower() for k in forward_headers}
            if "x-api-key" not in lower_keys:
                forward_headers["x-api-key"] = llm_config["api_key"]
            if "anthropic-version" not in lower_keys:
                forward_headers["anthropic-version"] = "2023-06-01"

        target_endpoint = f"{active_base_url}/messages" if active_base_url.endswith("/v1") else f"{active_base_url}/v1/messages"
        if is_stream:
            client = httpx.AsyncClient(timeout=60.0)
            req = client.build_request("POST", target_endpoint, json=clean_payload, headers=forward_headers)
            resp = await client.send(req, stream=True)

            async def stream_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for chunk in resp.aiter_raw():
                        yield chunk
                finally:
                    await resp.aclose()
                    await client.aclose()

            return StreamingResponse(stream_passthrough(), status_code=resp.status_code, media_type="text/event-stream")

        client = get_shared_upstream_client()
        resp = await client.post(target_endpoint, json=clean_payload, headers=forward_headers)
        return JSONResponse(status_code=resp.status_code, content=resp.json())

    @app.get("/v1/admin/audit-log")
    def get_audit_log(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return {"entries": [e.to_dict() for e in enforcer.audit_log]}

    @app.post("/v1/admin/mode")
    async def set_mode(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, str]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        new_mode = body.get("mode")
        if new_mode not in ("enforce", "observe"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="mode must be 'enforce' or 'observe'")
        enforcer.mode = new_mode
        return {"mode": enforcer.mode}

    @app.post("/v1/admin/reload-snapshot")
    async def reload_snapshot(
        request: Request,
        x_pod_admin_key: str | None = Header(default=None),
        x_pod_control_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        bearer = None
        if authorization and authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()
        valid_tokens = {t for t in (admin_key, control_token) if t}
        if not (
            (x_pod_admin_key and x_pod_admin_key in valid_tokens)
            or (x_pod_control_token and x_pod_control_token in valid_tokens)
            or (bearer and bearer in valid_tokens)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized control-plane request: valid X-POD-Control-Token or Bearer token required.",
            )
        body = await request.json()
        if "envelope" in body:
            pred = enforcer.snapshot_store.load_from_envelope(body["envelope"])
        else:
            path = body.get("path") or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json")
            pred = enforcer.snapshot_store.load_from_file(path)
        return {"loaded": True, "snapshot_id": pred["snapshot_id"], "sequence_number": pred["sequence_number"]}

    return app
