"""
Human-in-the-Loop (HITL) Dual-Key Governance Engine.
Enforces the Four-Eyes Principle for emergency admission of quarantined context,
mints authentic Ed25519 DSSE admission tickets, automates pipeline replay,
and logs all actions to WORM ledger and SIEM pipelines.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from governance.quarantine import QuarantineStore
from governance.siem_forwarder import SIEMForwarder
from governance.worm_ledger import WORMAuditLedger
from registry.signing import (
    Keyring,
    build_attestation_statement,
    compute_bytes_sha256,
    normalize_canonical_text,
    sign_statement,
)

logger = logging.getLogger("g1.governance.dual_key")


class FourEyesViolationError(ValueError):
    """Raised when the same operator attempts to sign both Key 1 and Key 2."""


class DualKeyGovernanceManager:
    """Orchestrates four-eyes signoff, DSSE emergency ticket issuance, and replay."""

    def __init__(
        self,
        quarantine_store: QuarantineStore,
        worm_ledger: WORMAuditLedger,
        siem_forwarder: SIEMForwarder,
        keyring: Optional[Keyring] = None,
        inference_gateway_url: str = "http://localhost:18082",
    ):
        self.quarantine_store = quarantine_store
        self.worm_ledger = worm_ledger
        self.siem_forwarder = siem_forwarder
        self.inference_gateway_url = inference_gateway_url.rstrip("/")

        if keyring is None:
            # Default to local pod keys directory
            key_dir = Path(os.environ.get("POD_KEY_DIR", ".pod_keys"))
            self.keyring = Keyring(public_key_dir=key_dir, private_key_dir=key_dir)
        else:
            self.keyring = keyring

    def stage_override(self, quarantine_id: str, requester_id: str, rationale: str) -> Dict[str, Any]:
        """Stage Key 1: Record emergency override request and rationale."""
        req_clean = requester_id.strip()
        if not req_clean:
            raise ValueError("Requester identity cannot be blank.")
        if not rationale.strip():
            raise ValueError("Override rationale is mandatory.")

        first_key = self.quarantine_store.stage_first_key(quarantine_id, req_clean, rationale)
        item = self.quarantine_store.get_item(quarantine_id)
        if not item:
            raise ValueError(f"Quarantine item {quarantine_id} not found.")

        # Log to WORM Ledger
        worm_entry = self.worm_ledger.append_event(
            event_type="HITL_OVERRIDE_REQUEST",
            actor_identity=req_clean,
            payload_digest=item["payload_digest"],
            metadata={
                "quarantine_id": quarantine_id,
                "reason_code": item["reason_code"],
                "claimed_tier": item["claimed_tier"],
                "rationale": rationale,
            },
        )

        # Buffer to SIEM
        self.siem_forwarder.enqueue_event(worm_entry)

        return {
            "status": "AWAITING_SECOND_KEY",
            "quarantine_id": quarantine_id,
            "first_key": first_key,
        }

    def mint_emergency_ticket(
        self,
        quarantine_id: str,
        locator_uri: str,
        raw_text: str,
        tier: str,
        requester_id: str,
        approver_id: str,
        ttl_seconds: int = 7200,
    ) -> Dict[str, Any]:
        """
        Mint a schema-valid in-toto v1 Attestation statement & Ed25519 DSSE envelope
        for the quarantined document with emergency clearance.
        """
        normalized_bytes = normalize_canonical_text(raw_text)
        content_sha256 = compute_bytes_sha256(normalized_bytes)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        statement = build_attestation_statement(
            locator=locator_uri,
            content_sha256=content_sha256,
            tier=tier,
            owner=requester_id,
            attested_by=f"hitl:dual-key:{approver_id}",
            display_name=f"Emergency Exemption for {quarantine_id}",
            environment="production",
            status="issued",
            issued_at=now,
            expires_at=expires_at,
        )

        envelope = sign_statement(statement, self.keyring)
        envelope_json = json.dumps(envelope)
        envelope_b64 = base64.b64encode(envelope_json.encode("utf-8")).decode("ascii")

        # Construct <pod:object> admission tag
        pod_tag = (
            f'<pod:object locator="{locator_uri}" sha256="{content_sha256}" '
            f'tier="{tier}" dsse="{envelope_b64}">\n'
            f'{raw_text}\n'
            f'</pod:object>'
        )

        return {
            "locator_uri": locator_uri,
            "content_sha256": content_sha256,
            "tier": tier,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "dsse_envelope": envelope,
            "pod_xml_tag": pod_tag,
        }

    def replay_to_pipeline(
        self,
        raw_payload: Dict[str, Any],
        emergency_tag: str,
    ) -> Dict[str, Any]:
        """
        Replay authorized payload wrapped with emergency admission ticket
        through the Docket Prevalidator Gateway (:18082).
        """
        replay_payload = json.loads(json.dumps(raw_payload))  # deep copy
        messages = replay_payload.get("messages", [])

        # Inject emergency ticket into first user message
        injected = False
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    msg["content"] = f"{emergency_tag}\n\n{content}"
                    injected = True
                    break

        if not injected:
            messages.append({"role": "user", "content": emergency_tag})
            replay_payload["messages"] = messages

        headers = {
            "Content-Type": "application/json",
            "X-POD-Caller-Clearance": "TopSecret",
            "X-POD-Target-Egress": "Internal",
            "X-POD-Require-Attested-Context": "false",
        }

        url = f"{self.inference_gateway_url}/v1/chat/completions"
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, json=replay_payload, headers=headers)
                return {
                    "status_code": resp.status_code,
                    "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:500],
                }
        except Exception as e:
            logger.warning(f"Replay to pipeline gateway {url} failed: {e}")
            return {
                "status_code": 0,
                "error": str(e),
                "message": "Gateway replay connection failed, but emergency ticket was successfully minted.",
            }

    def approve_and_release(
        self,
        quarantine_id: str,
        approver_id: str,
        notes: str,
        ttl_seconds: int = 7200,
        perform_replay: bool = True,
    ) -> Dict[str, Any]:
        """
        Stage Key 2: Verify four-eyes compliance, mint DSSE admission ticket,
        replay to inference pipeline, and log release to WORM and SIEM.
        """
        app_clean = approver_id.strip()
        if not app_clean:
            raise ValueError("Approver identity cannot be blank.")

        item = self.quarantine_store.get_item(quarantine_id)
        if not item:
            raise ValueError(f"Quarantine item {quarantine_id} not found.")

        first_key = item.get("first_key")
        if not first_key:
            raise ValueError(f"Item {quarantine_id} has not completed Key 1 stage.")

        requester_id = first_key.get("operator", "")
        if app_clean.lower() == requester_id.lower():
            raise FourEyesViolationError(
                f"Four-Eyes Violation: Self-approval prohibited! Approver '{app_clean}' cannot be the same "
                f"as Requester '{requester_id}'."
            )

        # Mint emergency ticket
        extracted_text = item.get("extracted_text") or "Emergency authorized context object"
        raw_loc = item.get("locator_uri") or f"emergency://quarantine/{quarantine_id}"
        if "://" not in raw_loc:
            safe_locator = f"emergency://override/{quarantine_id}"
        else:
            safe_locator = raw_loc

        ticket = self.mint_emergency_ticket(
            quarantine_id=quarantine_id,
            locator_uri=safe_locator,
            raw_text=extracted_text,
            tier=item.get("claimed_tier") or "Internal",
            requester_id=requester_id,
            approver_id=app_clean,
            ttl_seconds=ttl_seconds,
        )

        replay_result = None
        if perform_replay:
            replay_result = self.replay_to_pipeline(item["raw_payload"], ticket["pod_xml_tag"])

        second_key = self.quarantine_store.approve_second_key(
            quarantine_id=quarantine_id,
            operator=app_clean,
            notes=notes,
            emergency_ticket=ticket,
            replay_response=replay_result,
        )

        # Log release to WORM Ledger
        worm_entry = self.worm_ledger.append_event(
            event_type="HITL_DUAL_KEY_RELEASE",
            actor_identity=f"{requester_id}+{app_clean}",
            payload_digest=item["payload_digest"],
            metadata={
                "quarantine_id": quarantine_id,
                "requester": requester_id,
                "approver": app_clean,
                "ticket_locator": ticket["locator_uri"],
                "expires_at": ticket["expires_at"],
                "replay_status": item.get("replay_status", "COMPLETED"),
            },
        )

        # Buffer to SIEM
        self.siem_forwarder.enqueue_event(worm_entry)

        return {
            "status": "RELEASED",
            "quarantine_id": quarantine_id,
            "requester": requester_id,
            "approver": app_clean,
            "emergency_ticket": ticket,
            "replay_result": replay_result,
            "worm_hash": worm_entry["entry_hash"],
        }

    def reject(self, quarantine_id: str, reviewer_id: str, reason: str) -> None:
        """Permanently reject a quarantined item."""
        rev_clean = reviewer_id.strip()
        item = self.quarantine_store.get_item(quarantine_id)
        if not item:
            raise ValueError(f"Quarantine item {quarantine_id} not found.")

        self.quarantine_store.reject_item(quarantine_id, rev_clean, reason)

        worm_entry = self.worm_ledger.append_event(
            event_type="HITL_REJECTION",
            actor_identity=rev_clean,
            payload_digest=item["payload_digest"],
            metadata={
                "quarantine_id": quarantine_id,
                "reviewer": rev_clean,
                "reason": reason,
            },
        )
        self.siem_forwarder.enqueue_event(worm_entry)
