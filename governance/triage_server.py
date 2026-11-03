"""
FastAPI Human-in-the-Loop (HITL) Governance, Audit, and Triage Server.
Runs on port 18083 (administratively segregated from inference port 18082).
Serves the institutional HTMX/Tailwind dashboard, REST triage APIs,
and real-time Server-Sent Events (SSE) telemetry feed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

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


class StageKey1Request(BaseModel):
    requester_id: str
    rationale: str


class ApproveKey2Request(BaseModel):
    approver_id: str
    notes: Optional[str] = ""
    ttl_seconds: Optional[int] = 7200


class RejectRequest(BaseModel):
    reviewer_id: str
    reason: str


class BoundaryInterceptRequest(BaseModel):
    event_type: str = "DOCKET_DENIAL"
    reason_code: str
    payload_digest: str
    raw_payload: Dict[str, Any]
    locator_uri: Optional[str] = "urn:doc:unspecified"
    claimed_tier: Optional[str] = "Internal"
    triggered_rules: Optional[List[str]] = None
    extracted_text: Optional[str] = None


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

    mock_cluster = MockReceiverCluster()
    templates_dir = Path(__file__).parent / "templates"
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

    # Attach subsystem singletons to app state
    app.state.worm_ledger = worm_ledger
    app.state.quarantine_store = quarantine_store
    app.state.siem_forwarder = siem_forwarder
    app.state.dual_key_manager = dual_key_manager
    app.state.cfg = cfg

    # ---------------------------------------------------------
    # HTML Dashboard & Frontend Views
    # ---------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_view(request: Request):
        q_items = quarantine_store.list_items(limit=25)
        w_events = worm_ledger.get_events(limit=25)
        q_counts = quarantine_store.count_by_status()
        _, tip_hash = worm_ledger.get_tip_hash()
        worm_count = worm_ledger.count_events()
        siem_dests = siem_forwarder.get_destination_status()

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "quarantine_items": q_items,
                "worm_events": w_events,
                "stats": {
                    "quarantine_counts": q_counts,
                    "worm_count": worm_count,
                    "worm_tip": tip_hash,
                    "siem_destinations": siem_dests,
                },
            },
        )

    # ---------------------------------------------------------
    # REST APIs: Quarantine Management & Dual-Key Signoff
    # ---------------------------------------------------------
    @app.get("/api/quarantine")
    async def list_quarantine(status: Optional[str] = None, limit: int = 50, offset: int = 0):
        return quarantine_store.list_items(status=status, limit=limit, offset=offset)

    @app.get("/api/quarantine/{quarantine_id}")
    async def get_quarantine_item(quarantine_id: str):
        item = quarantine_store.get_item(quarantine_id)
        if not item:
            raise HTTPException(status_code=404, detail="Quarantine record not found.")
        return item

    @app.post("/api/quarantine/{quarantine_id}/stage-override")
    async def stage_override(quarantine_id: str, req: StageKey1Request):
        try:
            res = dual_key_manager.stage_override(
                quarantine_id=quarantine_id,
                requester_id=req.requester_id,
                rationale=req.rationale,
            )
            await broadcast_event({
                "event_type": "HITL_OVERRIDE_REQUEST",
                "quarantine_id": quarantine_id,
                "operator": req.requester_id,
                "rationale": req.rationale,
            })
            return res
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/quarantine/{quarantine_id}/approve-override")
    async def approve_override(quarantine_id: str, req: ApproveKey2Request):
        try:
            res = dual_key_manager.approve_and_release(
                quarantine_id=quarantine_id,
                approver_id=req.approver_id,
                notes=req.notes or "",
                ttl_seconds=req.ttl_seconds or 7200,
            )
            await broadcast_event({
                "event_type": "HITL_DUAL_KEY_RELEASE",
                "quarantine_id": quarantine_id,
                "approver": req.approver_id,
                "worm_hash": res["worm_hash"],
            })
            return res
        except FourEyesViolationError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/quarantine/{quarantine_id}/reject")
    async def reject_quarantine(quarantine_id: str, req: RejectRequest):
        try:
            dual_key_manager.reject(quarantine_id, req.reviewer_id, req.reason)
            await broadcast_event({
                "event_type": "HITL_REJECTION",
                "quarantine_id": quarantine_id,
                "reviewer": req.reviewer_id,
            })
            return {"status": "REJECTED", "quarantine_id": quarantine_id}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ---------------------------------------------------------
    # REST APIs: Cryptographic WORM Ledger
    # ---------------------------------------------------------
    @app.get("/api/worm/verify")
    async def audit_worm_chain():
        """Recalculate cryptographic hash-chain across entire JSONL WORM log."""
        jsonl_path = cfg["storage"]["worm_jsonl_path"]
        return verify_ledger_integrity(jsonl_path)

    @app.get("/api/worm/events")
    async def get_worm_events(limit: int = 50, offset: int = 0, event_type: Optional[str] = None):
        return worm_ledger.get_events(limit=limit, offset=offset, event_type=event_type)

    # ---------------------------------------------------------
    # REST APIs: SIEM Destinations & Management
    # ---------------------------------------------------------
    @app.get("/api/siem/status")
    async def get_siem_status():
        return siem_forwarder.get_destination_status()

    @app.post("/api/siem/{dest_id}/test")
    async def test_siem_destination(dest_id: str):
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
    async def get_mock_receivers():
        return mock_cluster.get_status()

    @app.post("/api/siem/mock-receivers/toggle")
    async def toggle_mock_receivers():
        if mock_cluster._running:
            res = mock_cluster.stop()
        else:
            res = mock_cluster.start()
        return res

    @app.get("/api/siem/{dest_id}/config")
    async def get_siem_destination_config(dest_id: str):
        dest = siem_forwarder.destinations.get(dest_id)
        if not dest:
            raise HTTPException(status_code=404, detail=f"Destination '{dest_id}' not found.")
        return {
            "id": dest.id,
            "name": dest.name,
            "type": dest.type,
            "enabled": dest.enabled,
            "endpoint_url": dest.endpoint_url or "",
            "api_key": dest.api_key or "",
            "auth_header": dest.auth_header or "",
            "index_or_sourcetype": dest.index_or_sourcetype or "",
            "syslog_host": dest.syslog_host or "",
            "syslog_port": dest.syslog_port or 514,
            "syslog_use_tls": dest.syslog_use_tls,
            "workspace_id": dest.workspace_id or "",
            "log_group_name": dest.log_group_name or "",
            "timeout_seconds": dest.timeout_seconds,
        }

    @app.post("/api/siem/{dest_id}/config")
    async def update_siem_destination_config(dest_id: str, req: SIEMConfigUpdateRequest):
        dest = siem_forwarder.destinations.get(dest_id)
        if not dest:
            raise HTTPException(status_code=404, detail=f"Destination '{dest_id}' not found.")

        dest.enabled = req.enabled
        dest.endpoint_url = req.endpoint_url or ""
        dest.api_key = req.api_key or None
        dest.auth_header = req.auth_header or None
        dest.index_or_sourcetype = req.index_or_sourcetype or None
        dest.syslog_host = req.syslog_host or None
        dest.syslog_port = req.syslog_port or None
        dest.syslog_use_tls = req.syslog_use_tls
        dest.workspace_id = req.workspace_id or None
        dest.log_group_name = req.log_group_name or None
        if req.timeout_seconds:
            dest.timeout_seconds = req.timeout_seconds

        # Persist changes to config.yaml if present
        cfg_file_path = Path(__file__).parent / "config.yaml"
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

        return {"success": True, "destination": dest}

    # ---------------------------------------------------------
    # Boundary Ingress Interceptor (Called by Docket or Combine)
    # ---------------------------------------------------------
    @app.post("/api/intercept")
    async def intercept_boundary_event(req: BoundaryInterceptRequest):
        """
        Called when Docket (:18082) or Combine (:8000) blocks an un-papered data object,
        tampered DSSE ticket, or cognitive threat.
        Atomically stages in Quarantine, logs to WORM Ledger, and buffers to SIEM.
        """
        qid = quarantine_store.stage_quarantine(
            event_type=req.event_type,
            reason_code=req.reason_code,
            payload_digest=req.payload_digest,
            raw_payload=req.raw_payload,
            locator_uri=req.locator_uri,
            claimed_tier=req.claimed_tier,
            triggered_rules=req.triggered_rules,
            extracted_text=req.extracted_text,
        )

        worm_entry = worm_ledger.append_event(
            event_type=req.event_type,
            actor_identity="boundary:interceptor",
            payload_digest=req.payload_digest,
            metadata={
                "quarantine_id": qid,
                "reason_code": req.reason_code,
                "locator_uri": req.locator_uri,
                "claimed_tier": req.claimed_tier,
                "triggered_rules": req.triggered_rules,
            },
        )

        siem_forwarder.enqueue_event(worm_entry)

        await broadcast_event({
            "event_type": req.event_type,
            "quarantine_id": qid,
            "reason_code": req.reason_code,
            "payload_digest": req.payload_digest,
        })

        return {"status": "QUARANTINED", "quarantine_id": qid, "worm_entry_hash": worm_entry["entry_hash"]}

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
