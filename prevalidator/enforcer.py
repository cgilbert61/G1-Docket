"""In-memory Snapshot Enforcer and `<pod:object>` tag parser/stripper for the Prevalidator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt

from engine.classifier import RESTRICTED_CATEGORIES, PresidioClassifier
from registry.schema_validator import (
    CLEARANCE_ORDER,
    EGRESS_ORDER,
    SNAPSHOT_PREDICATE_TYPE,
    format_iso8601,
    parse_iso8601,
)
from registry.signing import Keyring, normalize_canonical_text, verify_dsse_envelope
from docket.chunking import ChunkProof, MerkleChunkTree

# Uniform denial message mandated by Phase 2 Consumer Conformance Suite (never leaks which rule fired)
UNIFORM_DENIAL_MESSAGE = "Request denied by data attestation policy."
UNIFORM_DENIAL_CODE = "policy_denied"

# Security reason codes
REASON_HASH_MISMATCH = "REASON_HASH_MISMATCH"
REASON_UNVERIFIED_INLINE_CONTENT = "REASON_UNVERIFIED_INLINE_CONTENT"
REASON_MALFORMED_POD_TAG = "REASON_MALFORMED_POD_TAG"
REASON_UNATTESTED_CONTEXT_OVERFLOW = "REASON_UNATTESTED_CONTEXT_OVERFLOW"
REASON_DATA_RESIDENCY_VIOLATION = "DATA_RESIDENCY_VIOLATION"
REASON_DEPARTMENTAL_ISOLATION_VIOLATION = "DEPARTMENTAL_ISOLATION_VIOLATION"
REASON_CLEARANCE_ESCALATION_BLOCKED = "CLEARANCE_ESCALATION_BLOCKED"
REASON_DELEGATION_VIOLATION = "DELEGATION_VIOLATION"

# Strict regexes for <pod:object> structural validation
POD_OPEN_TAG_STRICT_RE = re.compile(
    r'^<pod:object\s+locator="([^"<>]+)"(?:\s+(?:(?:sha256="([a-fA-F0-9]{64})"\s+chunk_proof="([A-Za-z0-9_-]+={0,2})")|(?:chunk_proof="([A-Za-z0-9_-]+={0,2})"\s+sha256="([a-fA-F0-9]{64})")|(?:sha256="([a-fA-F0-9]{64})")|(?:chunk_proof="([A-Za-z0-9_-]+={0,2})")))?\s*>$'
)
POD_CLOSE_TAG_STRICT_RE = re.compile(r"^</pod:object>$")
POD_ANY_TAG_TOKEN_RE = re.compile(r"<\s*/?\s*pod:object\b[^>]*>?|<\s*/?\s*pod:object", re.IGNORECASE)

# Regex matching balanced inline <pod:object locator="..." [sha256="..."]>...</pod:object> blocks
POD_OBJECT_TAG_RE = re.compile(
    r'<pod:object\s+locator="([^"<>]+)"(?:\s+(?:(?:sha256="([a-fA-F0-9]{64})"\s+chunk_proof="([A-Za-z0-9_-]+={0,2})")|(?:chunk_proof="([A-Za-z0-9_-]+={0,2})"\s+sha256="([a-fA-F0-9]{64})")|(?:sha256="([a-fA-F0-9]{64})")|(?:chunk_proof="([A-Za-z0-9_-]+={0,2})")))?\s*>(.*?)</pod:object>',
    re.DOTALL,
)

# Regex matching balanced inline <pod:delegate ...>...</pod:delegate> blocks for multi-agent swarm handoffs
POD_DELEGATE_TAG_RE = re.compile(
    r'<pod:delegate\s+([^>]+)>(.*?)</pod:delegate>',
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class AuditLogEntry:
    """Operator audit log entry recording exact reason codes (never exposed in client error responses)."""

    timestamp: str
    mode: str  # "enforce" | "observe"
    decision: str  # "allow" | "strip" | "deny" | "observe_would_deny"
    reason_codes: list[str]
    locators_evaluated: list[str]
    caller_clearance: str
    target_egress: str
    stripped_locators: list[str] = field(default_factory=list)
    masked_locators: list[str] = field(default_factory=list)
    decision_latency_ms: float = 0.0
    decision_latency_us: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "mode": self.mode,
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "locators_evaluated": self.locators_evaluated,
            "caller_clearance": self.caller_clearance,
            "target_egress": self.target_egress,
            "stripped_locators": self.stripped_locators,
            "masked_locators": self.masked_locators,
            "decision_latency_ms": self.decision_latency_ms,
            "decision_latency_us": self.decision_latency_us,
        }


@dataclass
class EnforcementOutcome:
    """Result of evaluating an incoming LLM request against the in-memory snapshot."""

    allowed_to_forward: bool
    transformed_payload: dict[str, Any]
    client_denial_body: dict[str, Any] | None
    audit_entry: AuditLogEntry
    masked_locators: list[str] = field(default_factory=list)
    decision_latency_ms: float = 0.0
    decision_latency_us: float = 0.0


class InMemorySnapshotStore:
    """Holds the latest verified DSSE snapshot in memory, enforcing monotonic sequence numbers and TTL fail-closed."""

    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring
        self._snapshot_predicate: dict[str, Any] | None = None
        self._highest_sequence: int = 0

    def load_from_envelope(self, envelope: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        """Verify DSSE signature and sequence number before atomically updating the in-memory snapshot."""
        ver = self.keyring.verify_dsse(
            envelope=envelope,
            expected_predicate_type=SNAPSHOT_PREDICATE_TYPE,
            check_expiry=True,
            now=now,
        )
        pred = ver.statement["predicate"]
        seq = int(pred["sequence_number"])
        if seq < self._highest_sequence:
            raise ValueError(
                f"Snapshot rollback rejected: incoming sequence_number ({seq}) < current ({self._highest_sequence})."
            )
        self._highest_sequence = seq
        self._snapshot_predicate = pred
        return pred

    def load_from_file(self, path: str | Path, now: datetime | None = None) -> dict[str, Any]:
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.load_from_envelope(envelope, now=now)

    def get_active_snapshot(self, now: datetime | None = None) -> dict[str, Any] | None:
        """Return the in-memory snapshot predicate ONLY if loaded and not past `expires_at` (fail-closed)."""
        if self._snapshot_predicate is None:
            return None
        current_time = now or datetime.now(timezone.utc)
        expires_at = parse_iso8601(self._snapshot_predicate["expires_at"])
        if current_time >= expires_at:
            return None
        return self._snapshot_predicate


class PrevalidatorEnforcer:
    """Evaluates OpenAI and Anthropic request payloads against the in-memory signed snapshot."""

    def __init__(
        self,
        snapshot_store: InMemorySnapshotStore,
        mode: str = "enforce",  # "enforce" | "observe"
        route_egress_map: dict[str, str] | None = None,
        default_egress_class: str = "public_api",
        caller_key_clearance_map: dict[str, str] | None = None,
        jwt_secret: str | None = None,
        enable_presidio_fallback: bool | None = None,
        allow_header_only_objects: bool | None = None,
        strict_inline_hash: bool | None = None,
        max_untagged_chars: int | None = None,
    ) -> None:
        if mode not in ("enforce", "observe"):
            raise ValueError("mode must be 'enforce' or 'observe'")
        self.snapshot_store = snapshot_store
        self.mode = mode
        self.route_egress_map = route_egress_map or {
            "local-model": "local_only",
            "ollama": "local_only",
            "vpc-model": "private_cloud",
            "gpt-4": "private_cloud",
            "combine-gateway": "private_cloud",
            "gpt-4o": "public_api",
            "claude-3-5-sonnet": "public_api",
        }
        self.default_egress_class = default_egress_class
        self.caller_key_clearance_map = caller_key_clearance_map or {
            "pod-key-public": "Public",
            "pod-key-internal": "Internal",
            "pod-key-confidential": "Confidential",
            "pod-key-restricted": "Restricted",
        }
        self.jwt_secret = jwt_secret or "pod-local-jwt-secret-key-minimum-32-bytes-long"
        self.enable_presidio_fallback = (
            enable_presidio_fallback
            if enable_presidio_fallback is not None
            else os.environ.get("POD_ENABLE_PRESIDIO_FALLBACK", "false").lower() in ("1", "true", "yes")
        )
        self.allow_header_only_objects = (
            allow_header_only_objects
            if allow_header_only_objects is not None
            else os.environ.get("POD_ALLOW_HEADER_ONLY_OBJECTS", "false").lower() in ("1", "true", "yes")
        )
        self.strict_inline_hash = (
            strict_inline_hash
            if strict_inline_hash is not None
            else os.environ.get("POD_STRICT_INLINE_HASH", "true").lower() in ("1", "true", "yes")
        )
        self.max_untagged_chars = (
            max_untagged_chars
            if max_untagged_chars is not None
            else int(os.environ.get("POD_MAX_UNTAGGED_CHARS", "2000"))
        )
        self.classifier = PresidioClassifier()
        self.custom_policy_hooks: list[Any] = []
        if os.environ.get("POD_ENABLE_ABAC_DATA_RESIDENCY", "false").lower() in ("1", "true", "yes"):
            self.register_policy_hook(create_data_residency_hook())
        if os.environ.get("POD_ENABLE_ABAC_DEPARTMENTAL_ISOLATION", "false").lower() in ("1", "true", "yes"):
            self.register_policy_hook(create_departmental_isolation_hook())
        self.audit_log: list[AuditLogEntry] = []
        self.latency_samples_ms: list[float] = []
        self.total_evaluations: int = 0
        self.last_directory_scan_metrics: dict[str, Any] = {
            "total_files": 0,
            "total_wall_ms": 0.0,
            "in_memory_enforcer_ms": 0.0,
            "avg_per_file_us": 0.0,
            "files_per_sec": 0.0,
        }

    def _record_latency_ns(self, elapsed_ns: int) -> tuple[float, float]:
        ms = round(max(elapsed_ns, 100) / 1_000_000.0, 4)
        us = round(max(elapsed_ns, 100) / 1_000.0, 2)
        self.total_evaluations += 1
        self.latency_samples_ms.append(ms)
        if len(self.latency_samples_ms) > 500:
            self.latency_samples_ms = self.latency_samples_ms[-500:]
        return ms, us

    def get_latency_telemetry(self) -> dict[str, Any]:
        """Return real-time sub-millisecond latency clock metrics for the Prevalidator."""
        samples = list(self.latency_samples_ms)
        if not samples:
            return {
                "last_decision_ms": 0.0,
                "last_decision_us": 0.0,
                "avg_ms": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "total_evaluations": self.total_evaluations,
                "sla_budget_ms": 5.0,
                "sla_compliant_pct": 100.0,
                "recent_samples_ms": [],
                "last_directory_scan": self.last_directory_scan_metrics,
            }
        sorted_s = sorted(samples)
        n = len(sorted_s)

        def _pct(p: float) -> float:
            idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
            return round(sorted_s[idx], 4)

        last_ms = samples[-1]
        compliant = sum(1 for x in samples if x <= 5.0)
        return {
            "last_decision_ms": round(last_ms, 4),
            "last_decision_us": round(last_ms * 1000.0, 2),
            "avg_ms": round(sum(samples) / n, 4),
            "p50_ms": _pct(50.0),
            "p95_ms": _pct(95.0),
            "p99_ms": _pct(99.0),
            "min_ms": round(sorted_s[0], 4),
            "max_ms": round(sorted_s[-1], 4),
            "total_evaluations": self.total_evaluations,
            "sla_budget_ms": 5.0,
            "sla_compliant_pct": round((compliant / n) * 100.0, 2),
            "recent_samples_ms": [round(x, 4) for x in samples[-24:]],
            "last_directory_scan": self.last_directory_scan_metrics,
        }

    def generate_prometheus_metrics(self) -> str:
        """Render standard Prometheus exposition format text for monitoring & telemetry."""
        lines: list[str] = [
            "# HELP g1_docket_mode Gateway posture mode (1 for enforce, 0 for observe).",
            "# TYPE g1_docket_mode gauge",
            f'g1_docket_mode{{mode="{self.mode}"}} 1',
            "",
            "# HELP g1_docket_evaluations_total Total admission evaluations performed.",
            "# TYPE g1_docket_evaluations_total counter",
            f'g1_docket_evaluations_total{{mode="{self.mode}"}} {self.total_evaluations}',
            "",
        ]

        decisions: dict[str, int] = {"allow": 0, "deny": 0, "strip": 0, "mask": 0}
        reasons: dict[str, int] = {}
        for entry in self.audit_log:
            dec = entry.decision.lower()
            decisions[dec] = decisions.get(dec, 0) + 1
            for r in entry.reason_codes:
                reasons[r] = reasons.get(r, 0) + 1

        lines.extend([
            "# HELP g1_docket_evaluations_by_decision_total Evaluations broken down by decision.",
            "# TYPE g1_docket_evaluations_by_decision_total counter",
        ])
        for dec, count in sorted(decisions.items()):
            lines.append(f'g1_docket_evaluations_by_decision_total{{decision="{dec}"}} {count}')
        lines.append("")

        if reasons:
            lines.extend([
                "# HELP g1_docket_policy_denials_by_reason_total Total policy denials by specific reason code.",
                "# TYPE g1_docket_policy_denials_by_reason_total counter",
            ])
            for r, count in sorted(reasons.items()):
                lines.append(f'g1_docket_policy_denials_by_reason_total{{reason="{r}"}} {count}')
            lines.append("")

        telemetry = self.get_latency_telemetry()
        samples = list(self.latency_samples_ms)
        lines.extend([
            "# HELP g1_docket_evaluation_duration_seconds Evaluation latency summary in seconds.",
            "# TYPE g1_docket_evaluation_duration_seconds summary",
            f'g1_docket_evaluation_duration_seconds{{quantile="0.5"}} {round(telemetry["p50_ms"] / 1000.0, 6)}',
            f'g1_docket_evaluation_duration_seconds{{quantile="0.95"}} {round(telemetry["p95_ms"] / 1000.0, 6)}',
            f'g1_docket_evaluation_duration_seconds{{quantile="0.99"}} {round(telemetry["p99_ms"] / 1000.0, 6)}',
            f'g1_docket_evaluation_duration_seconds_sum {round(sum(samples) / 1000.0, 6)}',
            f'g1_docket_evaluation_duration_seconds_count {len(samples)}',
            "",
        ])

        snap = self.snapshot_store.get_active_snapshot()
        seq = snap["sequence_number"] if snap else 0
        entries_count = len(snap.get("entries", {})) if snap else 0
        lines.extend([
            "# HELP g1_docket_active_snapshot_sequence Current active DSSE signed snapshot sequence number.",
            "# TYPE g1_docket_active_snapshot_sequence gauge",
            f"g1_docket_active_snapshot_sequence {seq}",
            "",
            "# HELP g1_docket_active_snapshot_entries Number of active attested entries in the active snapshot.",
            "# TYPE g1_docket_active_snapshot_entries gauge",
            f"g1_docket_active_snapshot_entries {entries_count}",
            "",
        ])

        return "\n".join(lines) + "\n"

    def resolve_caller_clearance(self, headers: dict[str, str]) -> str:
        """Resolve caller clearance from verified JWT or configured caller API key (defaults to 'Public')."""
        norm_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Check signed JWT in X-POD-Caller-Token
        jwt_token = norm_headers.get("x-pod-caller-token")
        if jwt_token:
            try:
                decoded = jwt.decode(jwt_token, self.jwt_secret, algorithms=["HS256"])
                clearance = decoded.get("clearance", "Public")
                if clearance in CLEARANCE_ORDER:
                    return clearance
            except Exception:
                return "Public"

        # 2. Check configured caller key map in X-POD-Caller-Key
        caller_key = norm_headers.get("x-pod-caller-key")
        if caller_key and caller_key in self.caller_key_clearance_map:
            return self.caller_key_clearance_map[caller_key]

        return "Public"

    def resolve_target_egress(self, model_name: str | None, route_override: str | None = None) -> str:
        """Resolve destination egress class from configured route/model map."""
        if route_override and route_override in EGRESS_ORDER:
            return route_override
        if model_name:
            if model_name in self.route_egress_map:
                return self.route_egress_map[model_name]
            for prefix, egress in sorted(self.route_egress_map.items(), key=lambda kv: len(kv[0]), reverse=True):
                if model_name.startswith(prefix):
                    return egress
        return self.default_egress_class

    def register_policy_hook(self, hook: Any) -> None:
        """Register a custom policy hook with signature `hook(entry: dict, context: dict) -> tuple[str, list[str]]`.
        
        The hook receives the attested entry metadata and resolved caller context, returning
        `('allow' | 'strip' | 'deny', [reason_codes])`.
        """
        self.custom_policy_hooks.append(hook)

    def resolve_caller_context(
        self,
        headers: dict[str, str],
        payload: dict[str, Any],
        caller_clearance: str,
        target_egress: str,
    ) -> dict[str, Any]:
        """Resolve enriched caller context (claims, department, jurisdiction, tenant) for ABAC evaluation."""
        norm_headers = {k.lower(): v for k, v in headers.items()}
        ctx: dict[str, Any] = {
            "caller_clearance": caller_clearance,
            "target_egress": target_egress,
            "model": payload.get("model", ""),
            "caller_id": norm_headers.get("x-pod-caller-id", norm_headers.get("x-pod-caller-key", "anonymous")),
            "department": norm_headers.get("x-pod-caller-dept", ""),
            "jurisdiction": norm_headers.get("x-pod-caller-region", norm_headers.get("x-pod-caller-jurisdiction", "")),
            "target_region": norm_headers.get("x-pod-target-region", ""),
            "tenant_id": norm_headers.get("x-pod-tenant-id", ""),
            "permit_masked": (
                norm_headers.get("x-pod-permit-masked", "").lower() in ("true", "1", "yes")
                or norm_headers.get("x-pod-transform", "").lower() in ("mask", "redact")
            ),
        }

        # Enrich from verified JWT claims if present
        jwt_token = norm_headers.get("x-pod-caller-token")
        if jwt_token:
            try:
                decoded = jwt.decode(jwt_token, self.jwt_secret, algorithms=["HS256"])
                if "sub" in decoded and not ctx["caller_id"]:
                    ctx["caller_id"] = decoded["sub"]
                if "dept" in decoded and not ctx["department"]:
                    ctx["department"] = decoded["dept"]
                if "tenant_id" in decoded and not ctx["tenant_id"]:
                    ctx["tenant_id"] = decoded["tenant_id"]
                if "jurisdiction" in decoded and not ctx["jurisdiction"]:
                    ctx["jurisdiction"] = decoded["jurisdiction"]
            except Exception:
                pass

        return ctx

    @staticmethod
    def _validate_pod_tag_structure(text: str) -> tuple[bool, list[tuple[int, int, str, str | None, str, str | None]]]:
        """Strictly validate `<pod:object>` tag balance, syntax, and absence of nesting or early-close smuggling.

        Returns `(is_valid, parsed_blocks)` where each block is `(start, end, locator, sha256, inner_text, chunk_proof)`.
        """
        tokens = list(POD_ANY_TAG_TOKEN_RE.finditer(text))
        if not tokens:
            return True, []

        blocks: list[tuple[int, int, str, str | None, str, str | None]] = []
        open_token: tuple[int, int, str, str | None, str | None] | None = None

        for tok in tokens:
            raw_tok = tok.group(0)
            if raw_tok.lower().startswith("</") or re.match(r"^<\s*/", raw_tok):
                # Closing tag
                if not POD_CLOSE_TAG_STRICT_RE.match(raw_tok):
                    return False, []
                if open_token is None:
                    # Early or orphan closing tag
                    return False, []
                o_start, o_end, loc, sha, proof = open_token
                inner_text = text[o_end : tok.start()]
                # Ensure no nested or partial pod:object markers inside inner_text
                if "pod:object" in inner_text.lower():
                    return False, []
                blocks.append((o_start, tok.end(), loc, sha, inner_text, proof))
                open_token = None
            else:
                # Opening tag
                if open_token is not None:
                    # Nested or unclosed previous opening tag
                    return False, []
                m = POD_OPEN_TAG_STRICT_RE.match(raw_tok)
                if not m:
                    return False, []
                loc = m.group(1)
                sha = m.group(2) or m.group(5) or m.group(6)
                proof = m.group(3) or m.group(4) or m.group(7)
                open_token = (tok.start(), tok.end(), loc, sha, proof)

        if open_token is not None:
            # Unclosed opening tag at end of text
            return False, []

        return True, blocks

    @staticmethod
    def _verify_inner_text_cryptographically(
        inner_text: str,
        inline_sha256: str | None,
        entry: dict[str, Any],
        chunk_proof: str | None = None,
    ) -> bool:
        """Verify live SHA-256 of `inner_text` against `content_sha256`, `extracted_text_sha256`, `chunk_hashes`, or Merkle `chunk_tree` proof."""
        raw_inner_sha256 = hashlib.sha256(inner_text.encode("utf-8")).hexdigest()
        norm_inner_sha256 = hashlib.sha256(normalize_canonical_text(inner_text)).hexdigest()

        att_content_sha = (entry.get("content_sha256") or "").lower()
        att_text_sha = (entry.get("extracted_text_sha256") or "").lower()
        att_chunks = {h.lower() for h in (entry.get("chunk_hashes") or [])}

        tree_root = (
            entry.get("chunk_tree_root")
            or entry.get("tree_root")
            or (entry.get("chunk_tree") or {}).get("tree_root")
            or ((entry.get("integrity") or {}).get("chunk_tree") or {}).get("tree_root")
            or (entry.get("integrity") or {}).get("chunk_tree_root")
        )

        # 0. Merkle Chunk Tree (MCT) cryptographic inclusion verification (RFC-009)
        if chunk_proof and tree_root:
            try:
                proof_obj = ChunkProof.from_base64(chunk_proof)
                if (
                    proof_obj.verify(norm_inner_sha256, tree_root)
                    or proof_obj.verify(raw_inner_sha256, tree_root)
                    or proof_obj.verify(normalize_canonical_text(inner_text), tree_root)
                    or proof_obj.verify(inner_text.encode("utf-8"), tree_root)
                ):
                    return True
            except Exception:
                pass

        # Never trust a caller-supplied sha256 attribute that contradicts the attested object or live inner digest
        if inline_sha256 is not None:
            supplied = inline_sha256.lower()
            valid_attested = {att_content_sha} | att_chunks
            if att_text_sha:
                valid_attested.add(att_text_sha)
            valid_attested.discard("")
            if supplied not in valid_attested:
                is_tree_verified = False
                if chunk_proof and tree_root:
                    try:
                        p = ChunkProof.from_base64(chunk_proof)
                        is_tree_verified = p.verify(supplied, tree_root)
                    except Exception:
                        pass
                if not is_tree_verified:
                    return False
            if supplied not in (att_content_sha, att_text_sha) and supplied not in (raw_inner_sha256, norm_inner_sha256):
                return False

        # 1. Whole-object content_sha256 match
        if raw_inner_sha256 == att_content_sha or norm_inner_sha256 == att_content_sha:
            return True

        # 2. Full normalized extracted_text_sha256 match
        if att_text_sha and (norm_inner_sha256 == att_text_sha or raw_inner_sha256 == att_text_sha):
            return True

        # 3. Deterministic chunk_hashes match
        if norm_inner_sha256 in att_chunks or raw_inner_sha256 in att_chunks:
            return True

        # 4. Multi-paragraph / multi-line composition strictly from attested chunk_hashes
        if att_chunks and "\n" in inner_text:
            sub_lines = [ln.strip() for ln in inner_text.splitlines() if ln.strip()]
            if sub_lines and all(
                hashlib.sha256(normalize_canonical_text(ln)).hexdigest() in att_chunks
                for ln in sub_lines
            ):
                return True

        # 5. Exact File Inspector reference token when accompanied by verified whole-object content_sha256
        if inline_sha256 is not None and inline_sha256.lower() == att_content_sha and att_content_sha:
            loc = entry.get("locator") or ""
            fname = loc.rsplit("/", 1)[-1] if loc else ""
            if inner_text.strip() in (f"Inspecting {loc}", f"Inspecting {fname}"):
                return True

        return False

    def _evaluate_single_locator(
        self,
        locator: str,
        inline_sha256: str | None,
        entries: dict[str, Any],
        caller_clearance: str,
        target_egress: str,
        now_dt: datetime,
        inner_text: str | None = None,
        verify_inline_text: bool | None = None,
        caller_context: dict[str, Any] | None = None,
        chunk_proof: str | None = None,
    ) -> tuple[str, list[str]]:
        """Return `(action, reason_codes)` where action is `'allow' | 'strip' | 'deny'`."""
        entry = entries.get(locator)
        if not entry:
            return "deny", ["UNATTESTED"]

        status = entry.get("status", "active")
        if status == "revoked":
            return "deny", ["REVOKED"]

        rec_exp = parse_iso8601(entry["record_expires_at"])
        if status == "expired" or now_dt >= rec_exp:
            return "deny", ["EXPIRED"]

        # Live cryptographic verification of inline <pod:object> content
        effective_strict_inline = self.strict_inline_hash if verify_inline_text is None else verify_inline_text
        if inner_text is not None and effective_strict_inline:
            if not self._verify_inner_text_cryptographically(inner_text, inline_sha256, entry, chunk_proof=chunk_proof):
                return "deny", [REASON_HASH_MISMATCH, "HASH_DRIFT"]
        elif inline_sha256 and inline_sha256.lower() != entry["content_sha256"].lower():
            return "deny", [REASON_HASH_MISMATCH, "HASH_DRIFT"]

        # Check caller clearance against record minimum_clearance
        req_clearance = entry["minimum_clearance"]
        if CLEARANCE_ORDER[caller_clearance] < CLEARANCE_ORDER[req_clearance]:
            if entry.get("ai_eligibility") in ("mask", "redact") or (caller_context and caller_context.get("permit_masked")):
                return "mask", []
            return "deny", ["INSUFFICIENT_CLEARANCE"]

        # Check destination egress class against record egress_class
        allowed_egress = entry["egress_class"]
        if EGRESS_ORDER[target_egress] > EGRESS_ORDER[allowed_egress]:
            if entry.get("ai_eligibility") in ("mask", "redact") or (caller_context and caller_context.get("permit_masked")):
                return "mask", []
            return "deny", ["EGRESS_DENIED"]

        # Check AI eligibility ('allow' | 'strip' | 'mask' | 'deny')
        ai_elig = entry["ai_eligibility"]
        if ai_elig == "deny":
            return "deny", ["EGRESS_DENIED"]

        # Check registered Custom ABAC Policy Hooks (Data Residency, Departmental Isolation, Project boundaries)
        if self.custom_policy_hooks:
            ctx = caller_context or {
                "caller_clearance": caller_clearance,
                "target_egress": target_egress,
            }
            for hook in self.custom_policy_hooks:
                hook_action, hook_reasons = hook(entry, ctx)
                if hook_action == "deny":
                    return "deny", hook_reasons or ["CUSTOM_POLICY_DENIAL"]
                elif hook_action == "strip" and ai_elig != "deny":
                    ai_elig = "strip"
                elif hook_action in ("mask", "redact") and ai_elig != "deny":
                    ai_elig = "mask"

        if ai_elig in ("mask", "redact"):
            return "mask", []
        if ai_elig == "strip":
            return "strip", []
        return "allow", []

    @staticmethod
    def _uniform_denial_response() -> dict[str, Any]:
        return {
            "error": {
                "message": UNIFORM_DENIAL_MESSAGE,
                "type": "pod_policy_denial",
                "code": UNIFORM_DENIAL_CODE,
            }
        }

    def evaluate_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        now: datetime | None = None,
        verify_inline_text: bool | None = None,
    ) -> EnforcementOutcome:
        """Evaluate an OpenAI `/v1/chat/completions` or Anthropic `/v1/messages` request payload."""
        t0_ns = time.perf_counter_ns()
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)
        hdrs = headers or {}
        norm_hdrs = {k.lower(): v for k, v in hdrs.items()}
        effective_strict_inline = self.strict_inline_hash if verify_inline_text is None else verify_inline_text

        caller_clearance = self.resolve_caller_clearance(hdrs)
        target_egress = self.resolve_target_egress(payload.get("model"))
        caller_context = self.resolve_caller_context(hdrs, payload, caller_clearance, target_egress)

        snapshot = self.snapshot_store.get_active_snapshot(now=now_dt)
        if snapshot is None:
            # Staleness or missing snapshot MUST fail closed
            lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
            audit = AuditLogEntry(
                timestamp=now_str,
                mode=self.mode,
                decision="deny",
                reason_codes=["EXPIRED"],
                locators_evaluated=[],
                caller_clearance=caller_clearance,
                target_egress=target_egress,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )

        entries = snapshot.get("entries", {})
        reason_codes: list[str] = []
        locators_seen: list[str] = []
        inline_verified_locators: set[str] = set()
        stripped_locators: list[str] = []
        masked_locators: list[str] = []
        total_untagged_chars = 0
        has_inline_pod_tags = False

        # 1. Evaluate and transform message texts (strict `<pod:object>` parser + live inner-text SHA-256 + fallback Presidio)
        new_payload = json.loads(json.dumps(payload))

        def process_delegates(text_val: str) -> str:
            nonlocal reason_codes
            if "pod:delegate" not in text_val.lower():
                return text_val

            def replace_delegate(m: re.Match[str]) -> str:
                attrs_str = m.group(1)
                inner_body = m.group(2)
                tier_match = re.search(r'parent_tier=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
                parent_tier = tier_match.group(1).capitalize() if tier_match else "Restricted"

                req_level = CLEARANCE_ORDER.get(parent_tier, 2)
                caller_level = CLEARANCE_ORDER.get(caller_clearance, 0)
                if caller_level < req_level:
                    reason_codes.append(REASON_CLEARANCE_ESCALATION_BLOCKED)
                    reason_codes.append(REASON_DELEGATION_VIOLATION)
                    return inner_body if self.mode == "observe" else "[POD:DELEGATE_BLOCKED]"

                allowed_egress = "allow_external" if parent_tier == "Public" else "internal_only"
                if EGRESS_ORDER.get(target_egress, 0) > EGRESS_ORDER.get(allowed_egress, 0):
                    reason_codes.append(REASON_CLEARANCE_ESCALATION_BLOCKED)
                    reason_codes.append("EGRESS_DENIED")
                    return inner_body if self.mode == "observe" else "[POD:DELEGATE_BLOCKED]"

                return inner_body

            return POD_DELEGATE_TAG_RE.sub(replace_delegate, text_val)

        def process_text(text: str) -> str:
            nonlocal reason_codes, locators_seen, stripped_locators, masked_locators, total_untagged_chars, has_inline_pod_tags

            text = process_delegates(text)

            is_valid_structure, parsed_blocks = self._validate_pod_tag_structure(text)
            if not is_valid_structure:
                reason_codes.append(REASON_MALFORMED_POD_TAG)
                return text

            if parsed_blocks:
                has_inline_pod_tags = True

            untagged_parts: list[str] = []
            last_end = 0
            out_segments: list[str] = []

            for start_idx, end_idx, loc, sha, inner_content, proof in parsed_blocks:
                untagged_seg = text[last_end:start_idx]
                untagged_parts.append(untagged_seg)
                last_end = end_idx

                locators_seen.append(loc)
                inline_verified_locators.add(loc)

                action, r_codes = self._evaluate_single_locator(
                    locator=loc,
                    inline_sha256=sha,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                    inner_text=inner_content,
                    verify_inline_text=effective_strict_inline,
                    caller_context=caller_context,
                    chunk_proof=proof,
                )
                if action == "deny":
                    reason_codes.extend(r_codes)
                    if self.mode == "observe":
                        out_segments.append(inner_content)
                elif action == "strip":
                    stripped_locators.append(loc)
                    if self.mode == "observe":
                        out_segments.append(inner_content)
                    else:
                        out_segments.append("[POD:STRIPPED]")
                elif action in ("mask", "redact"):
                    masked_locators.append(loc)
                    if self.mode == "observe":
                        out_segments.append(inner_content)
                    else:
                        masked_content, _ = self.classifier.mask_text_spans(inner_content)
                        out_segments.append(masked_content)
                else:
                    # Allowed -> unwrap <pod:object> tags and forward clean content
                    out_segments.append(inner_content)

            tail_seg = text[last_end:]
            untagged_parts.append(tail_seg)
            for p in untagged_parts:
                total_untagged_chars += len(p.strip())
            untagged_joined = " ".join(p for p in untagged_parts if p.strip())

            # Fallback content inspection (Presidio) ONLY on untagged free text carrying no object identity
            if self.enable_presidio_fallback and untagged_joined:
                findings = self.classifier.scan_text_segment(untagged_joined)
                restricted_hits = [f for f in findings if f.category in RESTRICTED_CATEGORIES]
                if restricted_hits:
                    reason_codes.append("UNATTESTED")

            # Reconstruct full text with transformed inline blocks
            if parsed_blocks:
                rebuilt: list[str] = []
                idx = 0
                seg_idx = 0
                for block in parsed_blocks:
                    start_idx, end_idx = block[0], block[1]
                    rebuilt.append(text[idx:start_idx])
                    if seg_idx < len(out_segments):
                        rebuilt.append(out_segments[seg_idx])
                        seg_idx += 1
                    idx = end_idx
                rebuilt.append(text[idx:])
                return "".join(rebuilt).strip()
            return text

        # Transform top-level Anthropic `system` prompt if present
        if isinstance(new_payload.get("system"), str):
            new_payload["system"] = process_text(new_payload["system"])
        elif isinstance(new_payload.get("system"), list):
            for block in new_payload["system"]:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    block["text"] = process_text(block["text"])

        # Transform `messages` array (OpenAI & Anthropic formats)
        for msg in new_payload.get("messages", []):
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = process_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = process_text(part["text"])

        # 2. Enforce Untagged Context Quota when <pod:object> tags or X-POD-Require-Attested-Context: true are present
        require_attested_ctx = norm_hdrs.get("x-pod-require-attested-context", "").lower() in ("1", "true", "yes")
        if require_attested_ctx and not has_inline_pod_tags:
            reason_codes.append("UNATTESTED_DATA_OBJECT")
        elif (has_inline_pod_tags or require_attested_ctx) and total_untagged_chars > self.max_untagged_chars:
            reason_codes.append(REASON_UNATTESTED_CONTEXT_OVERFLOW)

        # 3. Evaluate request-level header locators (`X-POD-Locators` or `X-POD-Objects`)
        header_loc_str = ",".join(
            s for s in (norm_hdrs.get("x-pod-locators", "").strip(), norm_hdrs.get("x-pod-objects", "").strip()) if s
        )
        if header_loc_str:
            for raw_loc in [x.strip() for x in header_loc_str.split(",") if x.strip()]:
                if raw_loc not in locators_seen:
                    locators_seen.append(raw_loc)
                if effective_strict_inline and not self.allow_header_only_objects and raw_loc not in inline_verified_locators:
                    reason_codes.append(REASON_UNVERIFIED_INLINE_CONTENT)
                    continue
                action, r_codes = self._evaluate_single_locator(
                    locator=raw_loc,
                    inline_sha256=None,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                    inner_text=None,
                    verify_inline_text=effective_strict_inline,
                    caller_context=caller_context,
                )
                if action == "deny":
                    reason_codes.extend(r_codes)
                elif action == "strip":
                    # Header-level locator has no inline block boundary to strip -> must deny whole request
                    reason_codes.append("EGRESS_DENIED")

        # Deduplicate reason codes preserving discovery order
        unique_reasons = list(dict.fromkeys(reason_codes))

        if unique_reasons:
            lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
            if self.mode == "observe":
                audit = AuditLogEntry(
                    timestamp=now_str,
                    mode="observe",
                    decision="observe_would_deny",
                    reason_codes=unique_reasons,
                    locators_evaluated=locators_seen,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    stripped_locators=stripped_locators,
                    decision_latency_ms=lat_ms,
                    decision_latency_us=lat_us,
                )
                self.audit_log.append(audit)
                return EnforcementOutcome(
                    allowed_to_forward=True,
                    transformed_payload=new_payload,
                    client_denial_body=None,
                    audit_entry=audit,
                    decision_latency_ms=lat_ms,
                    decision_latency_us=lat_us,
                )

            audit = AuditLogEntry(
                timestamp=now_str,
                mode="enforce",
                decision="deny",
                reason_codes=unique_reasons,
                locators_evaluated=locators_seen,
                caller_clearance=caller_clearance,
                target_egress=target_egress,
                stripped_locators=stripped_locators,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=new_payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )

        lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
        decision_str = "strip" if stripped_locators else ("mask" if masked_locators else "allow")
        audit = AuditLogEntry(
            timestamp=now_str,
            mode=self.mode,
            decision=decision_str,
            reason_codes=[],
            locators_evaluated=locators_seen,
            caller_clearance=caller_clearance,
            target_egress=target_egress,
            stripped_locators=stripped_locators,
            masked_locators=masked_locators,
            decision_latency_ms=lat_ms,
            decision_latency_us=lat_us,
        )
        self.audit_log.append(audit)
        return EnforcementOutcome(
            allowed_to_forward=True,
            transformed_payload=new_payload,
            client_denial_body=None,
            audit_entry=audit,
            masked_locators=masked_locators,
            decision_latency_ms=lat_ms,
            decision_latency_us=lat_us,
        )


def create_data_residency_hook(default_allowed_regions: list[str] | None = None):
    """Enforce sovereign data boundaries (e.g. GDPR).
    
    If an object's jurisdiction is 'EU' / 'EEA' / 'GDPR', blocks egress to non-EU model regions.
    """
    allowed = set(r.lower() for r in (default_allowed_regions or ["eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1"]))

    def _residency_hook(entry: dict[str, Any], ctx: dict[str, Any]) -> tuple[str, list[str]]:
        obj_jurisdiction = str(
            entry.get("jurisdiction")
            or entry.get("metadata", {}).get("jurisdiction")
            or entry.get("organizational_unit", {}).get("jurisdiction", "")
        ).upper()

        if obj_jurisdiction in ("EU", "EEA", "GDPR"):
            target_reg = str(ctx.get("target_region") or "").lower()
            if target_reg and target_reg not in allowed:
                return "deny", [REASON_DATA_RESIDENCY_VIOLATION]
            # If targeting an unpartitioned public model with no sovereign region guarantee
            if ctx.get("target_egress") == "public_api" and not target_reg:
                return "deny", [REASON_DATA_RESIDENCY_VIOLATION]
        return "allow", []

    _residency_hook.__name__ = "data_residency"
    _residency_hook.__doc__ = "Enforces GDPR and sovereign region boundaries"
    return _residency_hook


def create_departmental_isolation_hook():
    """Enforce strict departmental compartmentalization (e.g. HR / Finance data isolated to authorized teams)."""
    def _dept_hook(entry: dict[str, Any], ctx: dict[str, Any]) -> tuple[str, list[str]]:
        owner_dept = str(
            entry.get("owner_department")
            or entry.get("metadata", {}).get("department")
            or ""
        ).lower()

        if owner_dept:
            caller_dept = str(ctx.get("department") or "").lower()
            if caller_dept and caller_dept != owner_dept and caller_dept != "security-audit":
                return "deny", [REASON_DEPARTMENTAL_ISOLATION_VIOLATION]
        return "allow", []

    _dept_hook.__name__ = "departmental_isolation"
    _dept_hook.__doc__ = "Enforces departmental isolation and prevent cross-team data access"
    return _dept_hook

