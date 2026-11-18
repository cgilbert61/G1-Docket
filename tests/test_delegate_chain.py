"""Unit and integration tests for Multi-Agent Signed & Chained Delegation Envelopes (<pod:delegate>).

Covers:
1. Signed single-hop (Restricted content, Restricted caller, internal model) -> allowed, tags unwrapped;
   audit delegate_chain_root, verified_root_owner, delegate_chain_hops == 1 correct.
2. Production + legacy unsigned envelope -> deny, DELEGATION_SIGNATURE_INVALID in reason codes.
3. Production + inner body altered after signing -> deny, DELEGATION_SIGNATURE_INVALID.
4. Production + parent_tier attribute raised after signing -> deny, DELEGATION_CHAIN_BROKEN.
5. Two hops: A wraps at Restricted, B re-wraps narrowing to Confidential; Confidential caller, internal model -> allowed;
   audit root == A, hops == 2.
6. Two hops widening (A at Confidential, B claims Restricted) -> deny,
   DELEGATION_CHAIN_BROKEN + CLEARANCE_ESCALATION_BLOCKED.
7. Chain tamper: root entry removed, remaining signatures untouched -> deny.
8. Production + enforcer built with NO verify key + validly signed envelope -> deny (fail closed on missing key material).
9. Root entry with empty owner in production -> deny, DELEGATION_CHAIN_BROKEN. Same for a non-empty owner on a non-root entry.
10. Latency: build a 4-hop chained envelope; run evaluate_request 100 times; compare enforcer's recorded decision-latency p95
    against the same request carrying a legacy envelope. Acceptance bar: added p95 < 0.5 ms per request.
11. Change 2: production + delegate block + surrounding untagged text over max_untagged_chars -> deny with
    REASON_UNATTESTED_CONTEXT_OVERFLOW. Guard case: production + plain chat request (no delegate blocks, no pod tags, no locators)
    -> NOT denied for unattested context.
12. Change 4: with caplog, a fresh enforcer constructed under DOCKET_ENVIRONMENT=production emits the warning exactly once
    at initialization; subsequent evaluate_request calls do not re-fire it; a second fresh instance warns again;
    an enforcer constructed in demo mode emits nothing.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from prevalidator.enforcer import (
    InMemorySnapshotStore,
    PrevalidatorEnforcer,
    REASON_CLEARANCE_ESCALATION_BLOCKED,
    REASON_DELEGATION_CHAIN_BROKEN,
    REASON_DELEGATION_SIGNATURE_INVALID,
    REASON_DELEGATION_VIOLATION,
    REASON_UNATTESTED_CONTEXT_OVERFLOW,
)
from registry.signing import Keyring
from docket.integrations import (
    compute_delegate_canonical_string,
    wrap_delegated_context,
)


@pytest.fixture
def keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def _create_test_enforcer(
    verify_key: Any = None,
    mode: str = "enforce",
    max_untagged_chars: int | None = None,
) -> PrevalidatorEnforcer:
    keyring = Keyring()
    store = InMemorySnapshotStore(keyring)
    store._snapshot_predicate = {
        "sequence_number": 1,
        "expires_at": "2099-01-01T00:00:00Z",
        "entries": {},
    }
    return PrevalidatorEnforcer(
        snapshot_store=store,
        mode=mode,
        delegate_verify_key=verify_key,
        max_untagged_chars=max_untagged_chars,
    )


def test_signed_single_hop_allowed_and_enriches_audit(keypair, monkeypatch):
    """Test 1: Signed single-hop (Restricted content, Restricted caller, internal model) -> allowed, tags unwrapped."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    summary = "Projected Q3 M&A target acquisition valuation: $4.2B"
    delegated_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        origin_locator="s3://corp-lake/finance/merger_q3.pdf",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review valuation: {delegated_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is True
    assert outcome.audit_entry is not None
    assert outcome.audit_entry.decision == "allow"
    assert "<pod:delegate" not in outcome.transformed_payload["messages"][0]["content"]
    assert summary in outcome.transformed_payload["messages"][0]["content"]
    assert outcome.audit_entry.delegate_chain_root == "worker-agent-01"
    assert outcome.audit_entry.verified_root_owner == "c.w.gilbert"
    assert outcome.audit_entry.delegate_chain_hops == 1


def test_production_legacy_unsigned_envelope_denied(keypair, monkeypatch):
    """Test 2: Production + legacy unsigned envelope -> deny, DELEGATION_SIGNATURE_INVALID in reason codes."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    _, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    summary = "Legacy unsigned summary content"
    # wrap without signing_key emits legacy envelope
    legacy_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Restricted",
        agent_id="worker-agent-01",
    )
    assert "chain=" not in legacy_payload

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {legacy_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert outcome.audit_entry.decision == "deny"
    assert REASON_DELEGATION_SIGNATURE_INVALID in outcome.audit_entry.reason_codes
    assert REASON_DELEGATION_VIOLATION in outcome.audit_entry.reason_codes


def test_production_inner_body_altered_denied(keypair, monkeypatch):
    """Test 3: Production + inner body altered after signing -> deny, DELEGATION_SIGNATURE_INVALID."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    delegated_payload = wrap_delegated_context(
        content="Authentic analysis report data",
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    # Tamper with the inner body
    tampered_payload = delegated_payload.replace("Authentic analysis report data", "Malicious altered payload")

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {tampered_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert REASON_DELEGATION_SIGNATURE_INVALID in outcome.audit_entry.reason_codes


def test_production_parent_tier_attribute_raised_denied(keypair, monkeypatch):
    """Test 4: Production + parent_tier attribute raised after signing -> deny, DELEGATION_CHAIN_BROKEN."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    delegated_payload = wrap_delegated_context(
        content="Internal financial notes",
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Internal",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    # Tamper with outer parent_tier attribute from Internal to Restricted
    tampered_payload = delegated_payload.replace('parent_tier="Internal"', 'parent_tier="Restricted"')

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {tampered_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert REASON_DELEGATION_CHAIN_BROKEN in outcome.audit_entry.reason_codes


def test_two_hops_narrowing_allowed(keypair, monkeypatch):
    """Test 5: Two hops: A wraps at Restricted, B re-wraps narrowing to Confidential; Confidential caller -> allowed."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    summary = "Restricted research finding"
    origin_sha = "8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4"

    # Hop 1: Agent A wraps at Restricted
    env_hop1 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    # Hop 2: Agent B re-wraps narrowing to Confidential
    env_hop2 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_hop1,
        parent_tier="Confidential",
        agent_id="synth-agent-02",
        signing_key=priv,
    )

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {env_hop2}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-confidential"},
    )

    assert outcome.allowed_to_forward is True
    assert outcome.audit_entry is not None
    assert outcome.audit_entry.decision == "allow"
    assert outcome.audit_entry.delegate_chain_root == "worker-agent-01"
    assert outcome.audit_entry.verified_root_owner == "c.w.gilbert"
    assert outcome.audit_entry.delegate_chain_hops == 2


def test_two_hops_widening_denied(keypair, monkeypatch):
    """Test 6: Two hops widening (A at Confidential, B claims Restricted) -> deny DELEGATION_CHAIN_BROKEN + CLEARANCE_ESCALATION_BLOCKED."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    summary = "Confidential corporate memo"
    origin_sha = "8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4"

    # Hop 1: Agent A wraps at Confidential
    env_hop1 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_tier="Confidential",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    # Hop 2: Agent B attempts to widen ceiling to Restricted
    env_hop2 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_hop1,
        parent_tier="Restricted",
        agent_id="synth-agent-02",
        signing_key=priv,
    )

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {env_hop2}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert REASON_DELEGATION_CHAIN_BROKEN in outcome.audit_entry.reason_codes
    assert REASON_CLEARANCE_ESCALATION_BLOCKED in outcome.audit_entry.reason_codes


def test_chain_tamper_root_entry_removed_denied(keypair, monkeypatch):
    """Test 7: Chain tamper: root entry removed, remaining signatures untouched -> deny."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)

    summary = "Confidential memo"
    origin_sha = "8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4"

    env_hop1 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )
    env_hop2 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_hop1,
        parent_tier="Confidential",
        agent_id="synth-agent-02",
        signing_key=priv,
    )

    # Extract chain attribute and remove the root entry (index 0)
    m = re.search(r'chain="([^"]+)"', env_hop2)
    assert m is not None
    padded = m.group(1) + "=" * ((4 - len(m.group(1)) % 4) % 4)
    entries = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    assert len(entries) == 2

    # Remove root entry, leaving only entry 1
    tampered_entries = entries[1:]
    tampered_chain_b64 = base64.urlsafe_b64encode(
        json.dumps(tampered_entries, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    tampered_envelope = env_hop2.replace(m.group(1), tampered_chain_b64)

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {tampered_envelope}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-confidential"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert any(
        r in outcome.audit_entry.reason_codes
        for r in (REASON_DELEGATION_SIGNATURE_INVALID, REASON_DELEGATION_CHAIN_BROKEN)
    )


def test_production_enforcer_no_verify_key_fails_closed(keypair, monkeypatch):
    """Test 8: Production + enforcer built with NO verify key + validly signed envelope -> deny."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    monkeypatch.delenv("POD_DELEGATE_VERIFY_KEY", raising=False)
    priv, _ = keypair
    # Enforcer has NO verify key
    enforcer = _create_test_enforcer(verify_key=None)

    delegated_payload = wrap_delegated_context(
        content="Classified data",
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {delegated_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert REASON_DELEGATION_SIGNATURE_INVALID in outcome.audit_entry.reason_codes
    assert REASON_DELEGATION_VIOLATION in outcome.audit_entry.reason_codes


def test_production_root_entry_empty_owner_and_non_root_non_empty_owner_denied(keypair, monkeypatch):
    """Test 9: Root entry with empty owner in production -> deny, DELEGATION_CHAIN_BROKEN. Same for non-empty owner on non-root."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)
    origin_sha = "8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4"

    # 9a: Root entry with empty owner
    empty_owner_payload = wrap_delegated_context(
        content="Unattributed secret",
        origin_sha256=origin_sha,
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="",  # Empty owner on root
    )
    req1 = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {empty_owner_payload}"}],
    }
    outcome1 = enforcer.evaluate_request(req1, headers={"x-pod-caller-key": "pod-key-restricted"})
    assert outcome1.allowed_to_forward is False
    assert REASON_DELEGATION_CHAIN_BROKEN in outcome1.audit_entry.reason_codes

    # 9b: Non-root entry with non-empty owner
    env1 = wrap_delegated_context(
        content="Legitimate root secret",
        origin_sha256=origin_sha,
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )
    # Manually forge a second hop with a non-empty owner and valid signature over it
    m = re.search(r'chain="([^"]+)"', env1)
    padded = m.group(1) + "=" * ((4 - len(m.group(1)) % 4) % 4)
    entries1 = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    prev_sig = entries1[-1]["sig"]

    bad_owner_canonical = compute_delegate_canonical_string(
        origin_sha256=origin_sha,
        origin_locator="",
        agent="synth-agent-02",
        tier="Restricted",
        owner="impostor-owner",
        inner_body="Legitimate root secret",
        prev_sig=prev_sig,
    )
    bad_sig = base64.urlsafe_b64encode(priv.sign(bad_owner_canonical.encode("utf-8"))).decode("ascii").rstrip("=")
    entries_tampered = list(entries1) + [
        {"agent": "synth-agent-02", "tier": "Restricted", "owner": "impostor-owner", "sig": bad_sig}
    ]
    tampered_chain_b64 = base64.urlsafe_b64encode(
        json.dumps(entries_tampered, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")

    bad_hop_envelope = (
        f'<pod:delegate origin_sha256="{origin_sha}" parent_tier="Restricted" agent_id="synth-agent-02" '
        f'chain="{tampered_chain_b64}" sig="{bad_sig}">Legitimate root secret</pod:delegate>'
    )

    req2 = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review: {bad_hop_envelope}"}],
    }
    outcome2 = enforcer.evaluate_request(req2, headers={"x-pod-caller-key": "pod-key-restricted"})
    assert outcome2.allowed_to_forward is False
    assert REASON_DELEGATION_CHAIN_BROKEN in outcome2.audit_entry.reason_codes


def test_latency_delta_4_hop_vs_legacy(keypair, monkeypatch):
    """Test 10: Latency: build 4-hop chained envelope; run 100 times; compare decision-latency p95 against legacy. Added p95 < 0.5 ms."""
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    enforcer = _create_test_enforcer(verify_key=pub)
    summary = "High frequency transaction ledger audit record 0x88F1"
    origin_sha = "8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4"

    # Build 4-hop chained envelope
    env_h1 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_tier="Restricted",
        agent_id="agent-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )
    env_h2 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_h1,
        parent_tier="Restricted",
        agent_id="agent-02",
        signing_key=priv,
    )
    env_h3 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_h2,
        parent_tier="Confidential",
        agent_id="agent-03",
        signing_key=priv,
    )
    env_h4 = wrap_delegated_context(
        content=summary,
        origin_sha256=origin_sha,
        parent_envelope=env_h3,
        parent_tier="Internal",
        agent_id="agent-04",
        signing_key=priv,
    )

    # Legacy envelope with same content
    legacy_env = f'<pod:delegate origin_sha256="{origin_sha}" parent_tier="Internal" agent_id="agent-04">{summary}</pod:delegate>'

    headers = {"x-pod-caller-key": "pod-key-internal"}
    req_chained = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Check: {env_h4}"}],
    }
    req_legacy = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Check: {legacy_env}"}],
    }

    # Warmup
    for _ in range(5):
        enforcer.evaluate_request(req_chained, headers=headers)

    chained_latencies_ms: list[float] = []
    for _ in range(100):
        out = enforcer.evaluate_request(req_chained, headers=headers)
        assert out.allowed_to_forward is True
        chained_latencies_ms.append(out.decision_latency_ms)

    # Run legacy in demo mode to isolate legacy baseline without chain verification
    monkeypatch.delenv("DOCKET_ENVIRONMENT", raising=False)
    monkeypatch.delenv("DOCKET_REQUIRE_AUTH", raising=False)
    enforcer_legacy = _create_test_enforcer(verify_key=None)

    for _ in range(5):
        enforcer_legacy.evaluate_request(req_legacy, headers=headers)

    legacy_latencies_ms: list[float] = []
    for _ in range(100):
        out = enforcer_legacy.evaluate_request(req_legacy, headers=headers)
        assert out.allowed_to_forward is True
        legacy_latencies_ms.append(out.decision_latency_ms)

    chained_p95 = sorted(chained_latencies_ms)[int(len(chained_latencies_ms) * 0.95)]
    legacy_p95 = sorted(legacy_latencies_ms)[int(len(legacy_latencies_ms) * 0.95)]
    delta_p95 = chained_p95 - legacy_p95

    print(f"\n[LATENCY BENCHMARK] Chained 4-hop p95: {chained_p95:.4f} ms, Legacy p95: {legacy_p95:.4f} ms, Added p95 delta: {delta_p95:.4f} ms")
    assert delta_p95 < 0.5, f"Added p95 latency {delta_p95:.4f} ms exceeded 0.5 ms threshold"


def test_change2_untagged_context_quota_covers_delegates(keypair, monkeypatch):
    """Test 11: Change 2: production + delegate block + surrounding untagged text over max_untagged_chars -> deny REASON_UNATTESTED_CONTEXT_OVERFLOW.
    Guard case: production + plain chat request (no delegate blocks, no pod tags, no locators) -> NOT denied for unattested context.
    """
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    priv, pub = keypair
    max_untagged = 500
    enforcer = _create_test_enforcer(verify_key=pub, max_untagged_chars=max_untagged)

    summary = "Verified delegated summary payload"
    delegated_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Internal",
        agent_id="worker-01",
        signing_key=priv,
        owner="c.w.gilbert",
    )

    # 11a: Delegate block + surrounding untagged text over max_untagged_chars (600 chars > 500)
    surrounding_text = "Prompt context: " + ("X" * 600) + " please process: "
    req_overflow = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"{surrounding_text}{delegated_payload}"}],
    }
    out_overflow = enforcer.evaluate_request(
        req_overflow,
        headers={"x-pod-caller-key": "pod-key-internal"},
    )
    assert out_overflow.allowed_to_forward is False
    assert out_overflow.audit_entry is not None
    assert REASON_UNATTESTED_CONTEXT_OVERFLOW in out_overflow.audit_entry.reason_codes

    # 11b: Guard case: Plain chat request with surrounding text > 500 chars, NO delegate blocks, NO pod tags, NO locators
    plain_chat_text = "General user instruction: " + ("Y" * 600) + " what is the capital of France?"
    req_plain = {
        "model": "local-model",
        "messages": [{"role": "user", "content": plain_chat_text}],
    }
    out_plain = enforcer.evaluate_request(
        req_plain,
        headers={"x-pod-caller-key": "pod-key-internal"},
    )
    assert REASON_UNATTESTED_CONTEXT_OVERFLOW not in out_plain.audit_entry.reason_codes
    assert out_plain.allowed_to_forward is True


def test_change4_startup_warning_for_header_asserted_identity(keypair, caplog, monkeypatch):
    """Test 12: Change 4: fresh enforcer in auth-enforced mode emits warning exactly once at initialization;
    subsequent evaluate_request does not re-fire; second fresh instance warns again; demo mode emits nothing.
    """
    _, pub = keypair
    warning_phrase = "Auth-enforced mode: callers authenticating by API key"

    # 1. Production mode: fresh instance warns once
    monkeypatch.setenv("DOCKET_ENVIRONMENT", "production")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        enforcer1 = _create_test_enforcer(verify_key=pub)
        matching1 = [r for r in caplog.records if warning_phrase in r.message]
        assert len(matching1) == 1

        # Subsequent evaluate_request calls do not re-fire the warning
        req = {
            "model": "local-model",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        enforcer1.evaluate_request(req, headers={"x-pod-caller-key": "pod-key-public"})
        matching_after_eval = [r for r in caplog.records if warning_phrase in r.message]
        assert len(matching_after_eval) == 1

        # A second fresh instance warns again (no cross-instance suppression)
        enforcer2 = _create_test_enforcer(verify_key=pub)
        matching2 = [r for r in caplog.records if warning_phrase in r.message]
        assert len(matching2) == 2

    # 2. Demo mode: enforcer constructed in demo mode emits nothing
    monkeypatch.delenv("DOCKET_ENVIRONMENT", raising=False)
    monkeypatch.delenv("DOCKET_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("DOCKET_DEMO_MODE", raising=False)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        enforcer_demo = _create_test_enforcer()
        matching_demo = [r for r in caplog.records if warning_phrase in r.message]
        assert len(matching_demo) == 0
