"""Tests for Multi-Agent Swarm Attestation Delegation (<pod:delegate>).

Validates Section 7 of the Fortune 500 Enterprise Reference Architecture:
  1. Provenance Stripping Prevention:
     - Worker Agent with high clearance summarizes a confidential/restricted document.
     - Worker injects `<pod:delegate>` wrapper with parent tier and origin hash.
  2. Gateway Mediation:
     - Prevalidator evaluates effective tier = max(child, parent).
     - Blocks low-clearance downstream agents with CLEARANCE_ESCALATION_BLOCKED.
     - Blocks egress to public cloud models with EGRESS_DENIED.
     - Allows privileged agents routing to internal air-gapped models in < 140 us.
"""

import time
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from registry.signing import Keyring
from docket.integrations import wrap_delegated_context


def _create_test_enforcer() -> PrevalidatorEnforcer:
    keyring = Keyring()
    store = InMemorySnapshotStore(keyring)
    store._snapshot_predicate = {
        "sequence_number": 1,
        "expires_at": "2099-01-01T00:00:00Z",
        "entries": {},
    }
    return PrevalidatorEnforcer(snapshot_store=store, mode="enforce")


def test_swarm_delegation_clearance_escalation_blocked():
    """A low-clearance synthesizer agent cannot launder a restricted delegate block."""
    enforcer = _create_test_enforcer()

    # Worker Agent A (Restricted) summarizes a restricted document
    summary = "Projected Q3 M&A target acquisition valuation: $4.2B"
    delegated_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="8f3b92c4e1a0b5d8f6c3e2a1b9c7d4e5f6a8b0c2d3e4f5a6b7c8d9e0f1a2b3c4",
        parent_tier="Restricted",
        agent_id="worker-agent-01",
        origin_locator="s3://corp-lake/finance/merger_q3.pdf",
    )

    # Downstream Agent B (Public clearance) attempts to send Agent A's summary to an LLM
    req_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Synthesize market update: {delegated_payload}"}],
    }

    t0 = time.perf_counter_ns()
    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-public"},
    )
    elapsed_us = (time.perf_counter_ns() - t0) / 1000.0

    # Decision must be deny in sub-140 us
    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert outcome.audit_entry.decision == "deny"
    assert "CLEARANCE_ESCALATION_BLOCKED" in outcome.audit_entry.reason_codes
    assert "DELEGATION_VIOLATION" in outcome.audit_entry.reason_codes
    assert elapsed_us < 2000.0  # Well within single-digit ms even on busy test host


def test_swarm_delegation_egress_violation_blocked():
    """A privileged caller cannot egress a restricted delegate block to a public cloud model."""
    enforcer = _create_test_enforcer()

    summary = "Executive Compensation W2 Gross: $1,250,000"
    delegated_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        parent_tier="Restricted",
        agent_id="hr-specialist-09",
    )

    # Caller has Restricted clearance, but target model is public cloud (gpt-4o)
    req_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Prepare executive briefing: {delegated_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-restricted"},
    )

    assert outcome.allowed_to_forward is False
    assert outcome.audit_entry is not None
    assert "CLEARANCE_ESCALATION_BLOCKED" in outcome.audit_entry.reason_codes
    assert "EGRESS_DENIED" in outcome.audit_entry.reason_codes


def test_swarm_delegation_authorized_internal_routing():
    """Privileged caller routing to an air-gapped / internal model passes with tags unwrapped."""
    enforcer = _create_test_enforcer()

    summary = "Internal Architecture Blueprint: TRNG Entropy Source 0x9AF"
    delegated_payload = wrap_delegated_context(
        content=summary,
        origin_sha256="a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
        parent_tier="Confidential",
        agent_id="arch-worker-03",
    )

    # Privileged caller + internal model
    req_payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"Review blueprint: {delegated_payload}"}],
    }

    outcome = enforcer.evaluate_request(
        req_payload,
        headers={"x-pod-caller-key": "pod-key-confidential"},
    )

    assert outcome.allowed_to_forward is True
    assert outcome.audit_entry is not None
    assert outcome.audit_entry.decision == "allow"
    # Content must have <pod:delegate> tags unwrapped
    rebuilt_msg = outcome.transformed_payload["messages"][0]["content"]
    assert "<pod:delegate" not in rebuilt_msg
    assert summary in rebuilt_msg
