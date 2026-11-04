"""Unit tests for Prevalidator ABAC (Attribute-Based Access Control) & Data Residency policy hooks."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from engine.pipeline import AttestationEngine
from prevalidator.enforcer import (
    InMemorySnapshotStore,
    PrevalidatorEnforcer,
    REASON_DATA_RESIDENCY_VIOLATION,
    REASON_DEPARTMENTAL_ISOLATION_VIOLATION,
    create_data_residency_hook,
    create_departmental_isolation_hook,
)
from prevalidator.proxy import create_prevalidator_app
from registry.signing import Keyring
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


@pytest.fixture
def abac_env(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'abac_test.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    engine = AttestationEngine(registry=registry)

    # 1. Attest an EU GDPR sovereign document
    eu_file = tmp_path / "gdpr_eu_user_registry.csv"
    eu_content = "user_id,eu_vat_id,country\nEU-001,DE999123,Germany\n"
    eu_file.write_bytes(eu_content.encode("utf-8"))
    eu_loc = "file://corp-lake/eu/gdpr_eu_user_registry.csv"
    engine.attest_file(
        eu_file,
        owner="compliance@example.de",
        locator_override=eu_loc,
        jurisdiction="EU",
        org_unit="Compliance",
    )

    # 2. Attest a Finance-restricted ledger
    fin_file = tmp_path / "q4_payroll_allocations.csv"
    fin_content = "dept,payroll_q4\nEngineering,$4200000\nFinance,$980000\n"
    fin_file.write_bytes(fin_content.encode("utf-8"))
    fin_loc = "file://corp-lake/finance/q4_payroll_allocations.csv"
    engine.attest_file(
        fin_file,
        owner="cfo@example.org",
        locator_override=fin_loc,
        jurisdiction="US",
        org_unit="Finance",
    )

    # Publish snapshot
    snap_path = tmp_path / "abac_snap.dsse.json"
    pub = SnapshotPublisher(registry=registry, snapshot_output_path=snap_path)
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)

    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    yield {
        "enforcer": enforcer,
        "client": client,
        "eu_loc": eu_loc,
        "eu_sha": hashlib.sha256(eu_content.encode("utf-8")).hexdigest(),
        "eu_content": eu_content,
        "fin_loc": fin_loc,
        "fin_sha": hashlib.sha256(fin_content.encode("utf-8")).hexdigest(),
        "fin_content": fin_content,
    }

    registry.close()


def test_abac_data_residency_blocks_cross_border_egress(abac_env):
    """Verify GDPR / EU sovereign data is blocked from non-EU model endpoints."""
    enforcer = abac_env["enforcer"]
    client = abac_env["client"]
    eu_loc = abac_env["eu_loc"]
    eu_content = abac_env["eu_content"]

    # Register Data Residency Hook
    enforcer.register_policy_hook(create_data_residency_hook(default_allowed_regions=["eu-central-1", "eu-west-1"]))

    # Attempt egress to default / US model without EU region claim
    resp_us = client.post(
        "/v1/chat/completions",
        headers={"X-Pod-Caller-Key": "pod-key-public", "X-Pod-Target-Region": "us-east-1"},
        json={
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": f'Examine user registry:\n<pod:object locator="{eu_loc}">{eu_content}</pod:object>'}
            ],
        },
    )
    assert resp_us.status_code == 403
    assert resp_us.json()["error"]["code"] == "policy_denied"
    assert REASON_DATA_RESIDENCY_VIOLATION in enforcer.audit_log[-1].reason_codes


def test_abac_data_residency_allows_sovereign_eu_region(abac_env):
    """Verify GDPR / EU sovereign data is permitted when target region is an approved EU sovereign enclave."""
    enforcer = abac_env["enforcer"]
    client = abac_env["client"]
    eu_loc = abac_env["eu_loc"]
    eu_content = abac_env["eu_content"]

    enforcer.register_policy_hook(create_data_residency_hook(default_allowed_regions=["eu-central-1", "eu-west-1"]))

    resp_eu = client.post(
        "/v1/chat/completions",
        headers={"X-Pod-Caller-Key": "pod-key-public", "X-Pod-Target-Region": "eu-central-1"},
        json={
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": f'Examine user registry:\n<pod:object locator="{eu_loc}">{eu_content}</pod:object>'}
            ],
        },
    )
    assert resp_eu.status_code == 200
    assert enforcer.audit_log[-1].decision == "allow"


def test_abac_departmental_isolation_blocks_cross_department_access(abac_env):
    """Verify callers outside the authorized department are blocked from accessing department data."""
    enforcer = abac_env["enforcer"]
    client = abac_env["client"]
    fin_loc = abac_env["fin_loc"]
    fin_content = abac_env["fin_content"]

    enforcer.register_policy_hook(create_departmental_isolation_hook())

    # Caller with Confidential clearance but wrong department (Marketing)
    resp_marketing = client.post(
        "/v1/chat/completions",
        headers={
            "X-Pod-Caller-Key": "pod-key-confidential",
            "X-Pod-Caller-Dept": "Marketing",
        },
        json={
            "model": "local-model",
            "messages": [
                {"role": "user", "content": f'Review payroll data:\n<pod:object locator="{fin_loc}">{fin_content}</pod:object>'}
            ],
        },
    )
    assert resp_marketing.status_code == 403
    assert resp_marketing.json()["error"]["code"] == "policy_denied"
    assert REASON_DEPARTMENTAL_ISOLATION_VIOLATION in enforcer.audit_log[-1].reason_codes


def test_abac_departmental_isolation_allows_matching_department(abac_env):
    """Verify callers within the matching department pass policy evaluation."""
    enforcer = abac_env["enforcer"]
    client = abac_env["client"]
    fin_loc = abac_env["fin_loc"]
    fin_content = abac_env["fin_content"]

    enforcer.register_policy_hook(create_departmental_isolation_hook())

    resp_finance = client.post(
        "/v1/chat/completions",
        headers={
            "X-Pod-Caller-Key": "pod-key-confidential",
            "X-Pod-Caller-Dept": "Finance",
        },
        json={
            "model": "local-model",
            "messages": [
                {"role": "user", "content": f'Review payroll data:\n<pod:object locator="{fin_loc}">{fin_content}</pod:object>'}
            ],
        },
    )
    assert resp_finance.status_code == 200
    assert enforcer.audit_log[-1].decision == "allow"


def test_abac_custom_callable_hook(abac_env):
    """Verify arbitrary enterprise Python policy callables can be dynamically registered and enforced."""
    enforcer = abac_env["enforcer"]
    client = abac_env["client"]
    eu_loc = abac_env["eu_loc"]
    eu_content = abac_env["eu_content"]

    # Custom rule: Require caller to present a specific client project tag
    def require_project_apollo(entry, ctx):
        caller_id = ctx.get("caller_id", "")
        if not caller_id.startswith("apollo-"):
            return "deny", ["PROJECT_APOLLO_CREDENTIAL_REQUIRED"]
        return "allow", []

    enforcer.register_policy_hook(require_project_apollo)

    # 1. Deny when caller lacks apollo- prefix
    r_deny = client.post(
        "/v1/chat/completions",
        headers={"X-Pod-Caller-Key": "pod-key-public", "X-Pod-Caller-Id": "agent-standard"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f'<pod:object locator="{eu_loc}">{eu_content}</pod:object>'}],
        },
    )
    assert r_deny.status_code == 403
    assert "PROJECT_APOLLO_CREDENTIAL_REQUIRED" in enforcer.audit_log[-1].reason_codes

    # 2. Allow when caller presents valid apollo- prefix
    r_allow = client.post(
        "/v1/chat/completions",
        headers={"X-Pod-Caller-Key": "pod-key-public", "X-Pod-Caller-Id": "apollo-agent-07"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f'<pod:object locator="{eu_loc}">{eu_content}</pod:object>'}],
        },
    )
    assert r_allow.status_code == 200
    assert enforcer.audit_log[-1].decision == "allow"
