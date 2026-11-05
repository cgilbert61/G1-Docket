"""G1 Docket Python SDK Client implementation.

Provides `DocketClient` (synchronous) and `AsyncDocketClient` (asynchronous)
for communicating with G1 Docket services over HTTP/HTTPS.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

import httpx


class DocketError(Exception):
    """Base exception for all G1 Docket SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, response_body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class PolicyDenialError(DocketError):
    """Raised when an AI gateway request is blocked by data attestation policy (HTTP 403)."""


def compute_file_sha256(path: str | Path) -> str:
    """Compute the hexadecimal SHA-256 digest of a local file."""
    p = Path(path)
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def wrap_object_tag(locator: str, content: str, sha256: str | None = None, chunk_proof: str | None = None) -> str:
    """Wrap content in an inline `<pod:object>` tag for AI Gateway evaluation."""
    attrs = [f'locator="{locator}"']
    if sha256:
        attrs.append(f'sha256="{sha256}"')
    if chunk_proof:
        attrs.append(f'chunk_proof="{chunk_proof}"')
    return f'<pod:object {" ".join(attrs)}>{content}</pod:object>'


class DocketClient:
    """Synchronous client for G1 Docket Prevalidator, Registry, and Snapshot services."""

    def __init__(
        self,
        base_url: str = "http://localhost:18082",
        registry_url: str = "http://localhost:18080",
        snapshot_url: str = "http://localhost:18081",
        governance_url: str = "http://localhost:18084",
        admin_key: str = "pod-dev-admin-key",
        default_caller_key: str = "pod-key-public",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        app: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.registry_url = registry_url.rstrip("/")
        self.snapshot_url = snapshot_url.rstrip("/")
        self.governance_url = governance_url.rstrip("/")
        self.admin_key = admin_key
        self.default_caller_key = default_caller_key
        self.timeout = timeout
        if app is not None and transport is None:
            try:
                from starlette.testclient import TestClient

                self._client = TestClient(app, base_url=self.base_url)
                return
            except Exception:
                transport = httpx.ASGITransport(app=app)
        elif transport is None:
            transport = httpx.HTTPTransport(retries=2)
        self._client = httpx.Client(timeout=timeout, transport=transport, base_url=self.base_url if app is not None else "")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> DocketClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _admin_headers(self) -> dict[str, str]:
        return {
            "X-POD-Admin-Key": self.admin_key,
            "Content-Type": "application/json",
        }

    def _caller_headers(
        self,
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        headers = {
            "X-POD-Caller-Key": caller_key or self.default_caller_key,
            "Content-Type": "application/json",
        }
        if caller_dept:
            headers["X-POD-Caller-Dept"] = caller_dept
        if target_region:
            headers["X-POD-Target-Region"] = target_region
        if caller_id:
            headers["X-POD-Caller-Id"] = caller_id
        if jwt_token:
            headers["X-POD-Caller-Token"] = jwt_token
        if permit_masked:
            headers["X-POD-Permit-Masked"] = "true"
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 403:
            try:
                body = response.json()
            except Exception:
                body = response.text
            raise PolicyDenialError("Request denied by G1 Docket data attestation policy.", status_code=403, response_body=body)
        if response.is_error:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise DocketError(f"G1 Docket API Error ({response.status_code}): {detail}", status_code=response.status_code, response_body=detail)
        try:
            return response.json()
        except Exception:
            return {"raw_text": response.text}

    # -------------------------------------------------------------------------
    # Prevalidator & Gateway Enforcement
    # -------------------------------------------------------------------------

    def get_health(self) -> dict[str, Any]:
        """Check Prevalidator health status and active snapshot sequence."""
        res = self._client.get(f"{self.base_url}/healthz")
        return self._handle_response(res)

    def wait_for_sync(
        self,
        min_sequence: int = 1,
        timeout_sec: float = 60.0,
        interval_sec: float = 2.0,
    ) -> bool:
        """Poll the Prevalidator until it loads at least `min_sequence` snapshot in memory."""
        import time

        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            try:
                health = self.get_health()
                seq = health.get("snapshot_sequence", 0)
                if health.get("status") == "ok" and seq >= min_sequence:
                    return True
            except DocketError:
                pass
            time.sleep(interval_sec)
        raise TimeoutError(f"Prevalidator failed to reach snapshot sequence {min_sequence} within {timeout_sec}s")

    def chat_completions(
        self,
        messages: Sequence[Mapping[str, Any]],
        model: str = "gpt-4o",
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        headers: dict[str, str] | None = None,
        stream: bool = False,
        **extra_kwargs: Any,
    ) -> dict[str, Any]:
        """Submit an OpenAI-compatible chat completion through the Prevalidator.

        Raises `PolicyDenialError` if referenced data violates attestation policies.
        """
        payload: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "stream": stream,
            **extra_kwargs,
        }
        res = self._client.post(
            f"{self.base_url}/v1/chat/completions",
            headers=self._caller_headers(
                caller_key=caller_key,
                caller_dept=caller_dept,
                target_region=target_region,
                caller_id=caller_id,
                jwt_token=jwt_token,
                permit_masked=permit_masked,
                extra_headers=headers,
            ),
            json=payload,
        )
        return self._handle_response(res)

    def messages(
        self,
        messages: Sequence[Mapping[str, Any]],
        model: str = "claude-3-5-sonnet",
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        headers: dict[str, str] | None = None,
        max_tokens: int = 1024,
        **extra_kwargs: Any,
    ) -> dict[str, Any]:
        """Submit an Anthropic-compatible message request through the Prevalidator.

        Raises `PolicyDenialError` if referenced data violates attestation policies.
        """
        payload: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "max_tokens": max_tokens,
            **extra_kwargs,
        }
        res = self._client.post(
            f"{self.base_url}/v1/messages",
            headers=self._caller_headers(
                caller_key=caller_key,
                caller_dept=caller_dept,
                target_region=target_region,
                caller_id=caller_id,
                jwt_token=jwt_token,
                permit_masked=permit_masked,
                extra_headers=headers,
            ),
            json=payload,
        )
        return self._handle_response(res)

    def prevalidate_directory(
        self,
        directory_path: str | Path,
        caller_key: str | None = None,
        model: str = "local-model",
    ) -> dict[str, Any]:
        """Prevalidate all scannable files in a directory before ingestion or fine-tuning."""
        payload = {
            "directory_path": str(directory_path),
            "caller_key": caller_key or self.default_caller_key,
            "model": model,
        }
        res = self._client.post(f"{self.base_url}/v1/prevalidate-directory", json=payload)
        return self._handle_response(res)

    def attest_directory(self, directory_path: str | Path) -> dict[str, Any]:
        """Trigger the Attestation Engine to discover, classify, and attest a local directory."""
        payload = {"directory_path": str(directory_path)}
        res = self._client.post(
            f"{self.base_url}/v1/admin/attest-directory",
            headers=self._admin_headers(),
            json=payload,
            timeout=max(self.timeout, 120.0),
        )
        return self._handle_response(res)

    def get_audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent Prevalidator enforcement audit log entries."""
        res = self._client.get(f"{self.base_url}/v1/admin/audit-log", headers=self._admin_headers())
        data = self._handle_response(res)
        entries = data.get("entries", [])
        return entries[:limit]

    def set_enforcement_mode(self, mode: str) -> dict[str, Any]:
        """Set Prevalidator mode ('enforce' or 'observe')."""
        if mode not in ("enforce", "observe"):
            raise ValueError("mode must be 'enforce' or 'observe'")
        res = self._client.post(
            f"{self.base_url}/v1/admin/mode",
            headers=self._admin_headers(),
            json={"mode": mode},
        )
        return self._handle_response(res)

    def reload_snapshot(self) -> dict[str, Any]:
        """Force the Prevalidator to reload the latest signed snapshot into memory."""
        res = self._client.post(f"{self.base_url}/v1/admin/reload-snapshot", headers=self._admin_headers())
        return self._handle_response(res)

    def list_policy_hooks(self) -> dict[str, Any]:
        """List active ABAC policy hooks and sovereign boundaries on the Prevalidator."""
        res = self._client.get(f"{self.base_url}/v1/admin/policies/hooks", headers=self._admin_headers())
        return self._handle_response(res)

    def configure_policy_hook(
        self,
        hook_type: str,
        action: str = "enable",
        allowed_regions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Dynamically enable, disable, or configure an ABAC policy hook (e.g. data_residency, departmental_isolation)."""
        payload: dict[str, Any] = {"hook_type": hook_type, "action": action}
        if allowed_regions is not None:
            payload["allowed_regions"] = allowed_regions
        res = self._client.post(
            f"{self.base_url}/v1/admin/policies/hooks",
            headers=self._admin_headers(),
            json=payload,
        )
        return self._handle_response(res)

    def get_snapshot_view(self) -> dict[str, Any]:
        """Inspect the active in-memory snapshot state on the Prevalidator."""
        res = self._client.get(f"{self.base_url}/v1/admin/snapshot-view", headers=self._admin_headers())
        return self._handle_response(res)

    def run_latency_benchmark(self, samples: int = 20) -> dict[str, Any]:
        """Benchmark Prevalidator policy decision latency."""
        res = self._client.post(
            f"{self.base_url}/v1/admin/latency-benchmark",
            headers=self._admin_headers(),
            json={"samples": samples},
        )
        return self._handle_response(res)

    # -------------------------------------------------------------------------
    # Governance, WORM Audit & Quarantine
    # -------------------------------------------------------------------------

    def verify_worm_chain(self) -> dict[str, Any]:
        """Recalculate and verify the cryptographic WORM hash-chain on the Governance service."""
        res = self._client.get(f"{self.governance_url}/api/worm/verify")
        return self._handle_response(res)

    def export_worm_ledger(self, format: str = "json") -> str | dict[str, Any]:
        """Export the cryptographic WORM audit ledger as JSON or CSV string."""
        res = self._client.get(f"{self.governance_url}/api/worm/export", params={"format": format})
        if format.lower() == "csv":
            return res.text
        return self._handle_response(res)

    def export_quarantine(self, format: str = "json") -> str | dict[str, Any]:
        """Export quarantined security items as JSON or CSV string."""
        res = self._client.get(f"{self.governance_url}/api/quarantine/export", params={"format": format})
        if format.lower() == "csv":
            return res.text
        return self._handle_response(res)

    # -------------------------------------------------------------------------
    # Registry Catalog & Governance
    # -------------------------------------------------------------------------

    def lookup_record(self, locator: str) -> dict[str, Any]:
        """Look up an attestation record in the Authoritative Registry by canonical locator."""
        res = self._client.get(
            f"{self.registry_url}/v1/records/lookup",
            headers=self._admin_headers(),
            params={"locator": locator},
        )
        return self._handle_response(res)

    def list_records(self, current_only: bool = True) -> list[dict[str, Any]]:
        """List active attestation records from the Authoritative Registry."""
        res = self._client.get(
            f"{self.registry_url}/v1/records",
            headers=self._admin_headers(),
            params={"current_only": current_only},
        )
        data = self._handle_response(res)
        return data.get("records", [])

    def list_expiring_records(self, within_days: int = 30) -> list[dict[str, Any]]:
        """List records reaching expiry within the given number of days."""
        res = self._client.get(
            f"{self.registry_url}/v1/records/expiring",
            headers=self._admin_headers(),
            params={"within_days": within_days},
        )
        data = self._handle_response(res)
        return data.get("records", [])

    def raise_tier(self, locator: str, new_tier: str) -> dict[str, Any]:
        """Immediately raise an object's classification tier (e.g. to Confidential or Restricted)."""
        res = self._client.post(
            f"{self.registry_url}/v1/records/raise-tier",
            headers=self._admin_headers(),
            json={"locator": locator, "new_tier": new_tier},
        )
        return self._handle_response(res)

    def lower_tier(
        self,
        locator: str,
        new_tier: str,
        approvals: Sequence[Mapping[str, str]],
    ) -> dict[str, Any]:
        """Lower an object's classification tier (requires dual approvers)."""
        res = self._client.post(
            f"{self.registry_url}/v1/records/lower-tier",
            headers=self._admin_headers(),
            json={"locator": locator, "new_tier": new_tier, "approvals": list(approvals)},
        )
        return self._handle_response(res)

    def renew_record(
        self,
        locator: str,
        observed_content_sha256: str,
        ttl_days: int | None = None,
    ) -> dict[str, Any]:
        """Renew a record whose cryptographic fingerprint is unchanged."""
        res = self._client.post(
            f"{self.registry_url}/v1/records/renew",
            headers=self._admin_headers(),
            json={
                "locator": locator,
                "observed_content_sha256": observed_content_sha256,
                "ttl_days": ttl_days,
            },
        )
        return self._handle_response(res)

    def revoke_record(self, locator: str, reason: str = "Administrative revocation") -> dict[str, Any]:
        """Immediately revoke an attestation record."""
        res = self._client.post(
            f"{self.registry_url}/v1/records/revoke",
            headers=self._admin_headers(),
            json={"locator": locator, "reason": reason},
        )
        return self._handle_response(res)

    def list_reviews(self, status: str = "PENDING_REVIEW") -> list[dict[str, Any]]:
        """List governance review queue items."""
        res = self._client.get(
            f"{self.registry_url}/v1/reviews",
            headers=self._admin_headers(),
            params={"status": status},
        )
        data = self._handle_response(res)
        return data.get("reviews", [])

    def approve_review(
        self,
        review_id: str,
        approver_id: str,
        confirmed_tier: str | None = None,
        rationale: str = "Confirmed in human review",
    ) -> dict[str, Any]:
        """Approve an item in the governance review queue."""
        res = self._client.post(
            f"{self.registry_url}/v1/reviews/{review_id}/approve",
            headers=self._admin_headers(),
            json={
                "approver_id": approver_id,
                "confirmed_tier": confirmed_tier,
                "rationale": rationale,
            },
        )
        return self._handle_response(res)

    # -------------------------------------------------------------------------
    # Snapshot Publisher
    # -------------------------------------------------------------------------

    def get_latest_snapshot(self) -> dict[str, Any]:
        """Retrieve the latest DSSE-signed snapshot envelope from the publisher."""
        res = self._client.get(f"{self.snapshot_url}/v1/snapshot/latest")
        return self._handle_response(res)

    # -------------------------------------------------------------------------
    # Utility Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def wrap_object(locator: str, content: str, sha256: str | None = None, chunk_proof: str | None = None) -> str:
        """Wrap text in a `<pod:object>` XML block."""
        return wrap_object_tag(locator, content, sha256, chunk_proof)

    @staticmethod
    def hash_file(path: str | Path) -> str:
        """Calculate SHA-256 for a local file."""
        return compute_file_sha256(path)

    @staticmethod
    def extract_watermark(text: str, secret_key: bytes | None = None) -> dict[str, Any] | None:
        """Extract and verify an invisible cryptographic provenance watermark from text."""
        from docket.watermark import DEFAULT_WATERMARK_SECRET, extract_invisible_watermark
        key = secret_key or DEFAULT_WATERMARK_SECRET
        payload = extract_invisible_watermark(text, secret_key=key)
        return payload.to_dict() if payload else None

    @staticmethod
    def embed_watermark(
        text: str,
        snapshot_sequence: int,
        caller_key: str,
        secret_key: bytes | None = None,
    ) -> str:
        """Embed an invisible cryptographic provenance watermark into text."""
        from docket.watermark import DEFAULT_WATERMARK_SECRET, embed_invisible_watermark
        key = secret_key or DEFAULT_WATERMARK_SECRET
        return embed_invisible_watermark(text, snapshot_sequence=snapshot_sequence, caller_key=caller_key, secret_key=key)


class AsyncDocketClient:
    """Asynchronous client for G1 Docket Prevalidator, Registry, and Snapshot services."""

    def __init__(
        self,
        base_url: str = "http://localhost:18082",
        registry_url: str = "http://localhost:18080",
        snapshot_url: str = "http://localhost:18081",
        governance_url: str = "http://localhost:18084",
        admin_key: str = "pod-dev-admin-key",
        default_caller_key: str = "pod-key-public",
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        app: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.registry_url = registry_url.rstrip("/")
        self.snapshot_url = snapshot_url.rstrip("/")
        self.governance_url = governance_url.rstrip("/")
        self.admin_key = admin_key
        self.default_caller_key = default_caller_key
        self.timeout = timeout
        if app is not None and transport is None:
            transport = httpx.ASGITransport(app=app)
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport, base_url=self.base_url if transport else "")

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncDocketClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def _admin_headers(self) -> dict[str, str]:
        return {
            "X-POD-Admin-Key": self.admin_key,
            "Content-Type": "application/json",
        }

    def _caller_headers(
        self,
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        headers = {
            "X-POD-Caller-Key": caller_key or self.default_caller_key,
            "Content-Type": "application/json",
        }
        if caller_dept:
            headers["X-POD-Caller-Dept"] = caller_dept
        if target_region:
            headers["X-POD-Target-Region"] = target_region
        if caller_id:
            headers["X-POD-Caller-Id"] = caller_id
        if jwt_token:
            headers["X-POD-Caller-Token"] = jwt_token
        if permit_masked:
            headers["X-POD-Permit-Masked"] = "true"
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 403:
            try:
                body = response.json()
            except Exception:
                body = response.text
            raise PolicyDenialError("Request denied by G1 Docket data attestation policy.", status_code=403, response_body=body)
        if response.is_error:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise DocketError(f"G1 Docket API Error ({response.status_code}): {detail}", status_code=response.status_code, response_body=detail)
        try:
            return response.json()
        except Exception:
            return {"raw_text": response.text}

    async def get_health(self) -> dict[str, Any]:
        """Check Prevalidator health status and active snapshot sequence."""
        res = await self._client.get(f"{self.base_url}/healthz")
        return self._handle_response(res)

    async def wait_for_sync(
        self,
        min_sequence: int = 1,
        timeout_sec: float = 60.0,
        interval_sec: float = 2.0,
    ) -> bool:
        """Poll the Prevalidator until it loads at least `min_sequence` snapshot in memory asynchronously."""
        import asyncio
        import time

        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            try:
                health = await self.get_health()
                seq = health.get("snapshot_sequence", 0)
                if health.get("status") == "ok" and seq >= min_sequence:
                    return True
            except DocketError:
                pass
            await asyncio.sleep(interval_sec)
        raise TimeoutError(f"Prevalidator failed to reach snapshot sequence {min_sequence} within {timeout_sec}s")

    async def chat_completions(
        self,
        messages: Sequence[Mapping[str, Any]],
        model: str = "gpt-4o",
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        headers: dict[str, str] | None = None,
        stream: bool = False,
        **extra_kwargs: Any,
    ) -> dict[str, Any]:
        """Submit an OpenAI-compatible chat completion through the Prevalidator asynchronously."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "stream": stream,
            **extra_kwargs,
        }
        res = await self._client.post(
            f"{self.base_url}/v1/chat/completions",
            headers=self._caller_headers(
                caller_key=caller_key,
                caller_dept=caller_dept,
                target_region=target_region,
                caller_id=caller_id,
                jwt_token=jwt_token,
                permit_masked=permit_masked,
                extra_headers=headers,
            ),
            json=payload,
        )
        return self._handle_response(res)

    async def messages(
        self,
        messages: Sequence[Mapping[str, Any]],
        model: str = "claude-3-5-sonnet",
        caller_key: str | None = None,
        caller_dept: str | None = None,
        target_region: str | None = None,
        caller_id: str | None = None,
        jwt_token: str | None = None,
        permit_masked: bool = False,
        headers: dict[str, str] | None = None,
        max_tokens: int = 1024,
        **extra_kwargs: Any,
    ) -> dict[str, Any]:
        """Submit an Anthropic-compatible message request through the Prevalidator asynchronously."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "max_tokens": max_tokens,
            **extra_kwargs,
        }
        res = await self._client.post(
            f"{self.base_url}/v1/messages",
            headers=self._caller_headers(
                caller_key=caller_key,
                caller_dept=caller_dept,
                target_region=target_region,
                caller_id=caller_id,
                jwt_token=jwt_token,
                permit_masked=permit_masked,
                extra_headers=headers,
            ),
            json=payload,
        )
        return self._handle_response(res)

    async def prevalidate_directory(
        self,
        directory_path: str | Path,
        caller_key: str | None = None,
        model: str = "local-model",
    ) -> dict[str, Any]:
        """Prevalidate all scannable files in a directory asynchronously."""
        payload = {
            "directory_path": str(directory_path),
            "caller_key": caller_key or self.default_caller_key,
            "model": model,
        }
        res = await self._client.post(f"{self.base_url}/v1/prevalidate-directory", json=payload)
        return self._handle_response(res)

    async def attest_directory(self, directory_path: str | Path) -> dict[str, Any]:
        """Trigger the Attestation Engine to discover, classify, and attest a local directory asynchronously."""
        payload = {"directory_path": str(directory_path)}
        res = await self._client.post(
            f"{self.base_url}/v1/admin/attest-directory",
            headers=self._admin_headers(),
            json=payload,
            timeout=max(self.timeout, 120.0),
        )
        return self._handle_response(res)

    async def get_latest_snapshot(self) -> dict[str, Any]:
        """Retrieve the latest DSSE-signed snapshot envelope from the publisher asynchronously."""
        res = await self._client.get(f"{self.snapshot_url}/v1/snapshot/latest")
        return self._handle_response(res)

    async def lookup_record(self, locator: str) -> dict[str, Any]:
        """Look up an attestation record in the Authoritative Registry by canonical locator asynchronously."""
        res = await self._client.get(
            f"{self.registry_url}/v1/records/lookup",
            headers=self._admin_headers(),
            params={"locator": locator},
        )
        return self._handle_response(res)

    async def verify_worm_chain(self) -> dict[str, Any]:
        """Recalculate and verify the cryptographic WORM hash-chain on the Governance service asynchronously."""
        res = await self._client.get(f"{self.governance_url}/api/worm/verify")
        return self._handle_response(res)

    async def export_worm_ledger(self, format: str = "json") -> str | dict[str, Any]:
        """Export the cryptographic WORM audit ledger as JSON or CSV string asynchronously."""
        res = await self._client.get(f"{self.governance_url}/api/worm/export", params={"format": format})
        if format.lower() == "csv":
            return res.text
        return self._handle_response(res)

    async def export_quarantine(self, format: str = "json") -> str | dict[str, Any]:
        """Export quarantined security items as JSON or CSV string asynchronously."""
        res = await self._client.get(f"{self.governance_url}/api/quarantine/export", params={"format": format})
        if format.lower() == "csv":
            return res.text
        return self._handle_response(res)

    async def list_policy_hooks(self) -> dict[str, Any]:
        """List active ABAC policy hooks and sovereign boundaries on the Prevalidator asynchronously."""
        res = await self._client.get(f"{self.base_url}/v1/admin/policies/hooks", headers=self._admin_headers())
        return self._handle_response(res)

    async def configure_policy_hook(
        self,
        hook_type: str,
        action: str = "enable",
        allowed_regions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Dynamically enable, disable, or configure an ABAC policy hook asynchronously."""
        payload: dict[str, Any] = {"hook_type": hook_type, "action": action}
        if allowed_regions is not None:
            payload["allowed_regions"] = allowed_regions
        res = await self._client.post(
            f"{self.base_url}/v1/admin/policies/hooks",
            headers=self._admin_headers(),
            json=payload,
        )
        return self._handle_response(res)
