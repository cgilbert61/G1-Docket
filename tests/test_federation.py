"""Unit tests for G1 Docket Multi-Region Active-Active Federation & Split-Brain Resiliency.

Tests Section 6 of the Enterprise Reference Architecture:
  - 3-Region edge distribution (us-east-1, eu-west-1, ap-southeast-1)
  - Monotonic sequence enforcement & split-brain rejection
  - Edge autonomy during WAN partition
  - Partition recovery, snapshot fast-forward & audit buffer drain
"""

import hashlib
import pytest
from docket.federation import CentralGovernanceHub, RegionalPrevalidatorNode


def make_test_entry(locator: str, content: str = "", tier: str = "Public", ai: str = "allow", egress: str = "public_api"):
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return {
        "locator": locator,
        "tier": tier,
        "minimum_clearance": "Public",
        "egress_class": egress,
        "ai_eligibility": ai,
        "content_sha256": sha,
        "record_expires_at": "2099-01-01T00:00:00Z",
        "status": "active",
    }


def test_multi_region_active_active_sync():
    hub = CentralGovernanceHub(primary_region="us-east-1")
    node_us = RegionalPrevalidatorNode(region_id="us-east-1")
    node_eu = RegionalPrevalidatorNode(region_id="eu-west-1")
    node_ap = RegionalPrevalidatorNode(region_id="ap-southeast-1")

    hub.register_region("us-east-1", node_us)
    hub.register_region("eu-west-1", node_eu)
    hub.register_region("ap-southeast-1", node_ap)

    # Initial state: Sequence 1000, 0 entries
    assert node_us.current_sequence == 0
    assert node_eu.current_sequence == 0

    # Publish snapshot 1
    entries_v1 = {
        "file://sales/q3.csv": make_test_entry("file://sales/q3.csv"),
    }
    snap1 = hub.set_active_entries(entries_v1)
    assert snap1["sequence_number"] == 1001

    # Verify all regions synchronized in-memory
    assert node_us.current_sequence == 1001
    assert node_eu.current_sequence == 1001
    assert node_ap.current_sequence == 1001


def test_split_brain_monotonic_sequence_enforcement():
    hub = CentralGovernanceHub(primary_region="us-east-1")
    node_eu = RegionalPrevalidatorNode(region_id="eu-west-1")
    hub.register_region("eu-west-1", node_eu)

    # Advance hub to sequence 1005
    for i in range(5):
        hub.set_active_entries({"file://doc.txt": make_test_entry("file://doc.txt")})

    assert node_eu.current_sequence == 1005

    # Attempt to inject a stale snapshot (Split-Brain or Replay attack) with seq 1003
    stale_snap = {
        "snapshot_id": "stale-snap-1003",
        "sequence_number": 1003,
        "entries": {},
    }
    accepted = node_eu.receive_snapshot(stale_snap)
    assert accepted is False, "Edge node must reject stale snapshot with seq <= current_sequence"
    assert node_eu.current_sequence == 1005

    # Attempt to inject an equal sequence snapshot
    equal_snap = {
        "snapshot_id": "equal-snap-1005",
        "sequence_number": 1005,
        "entries": {},
    }
    accepted_equal = node_eu.receive_snapshot(equal_snap)
    assert accepted_equal is False, "Edge node must reject equal sequence snapshot to prevent state corruption"


def test_wan_partition_local_autonomy():
    hub = CentralGovernanceHub(primary_region="us-east-1")
    node_eu = RegionalPrevalidatorNode(region_id="eu-west-1")
    hub.register_region("eu-west-1", node_eu)

    cat_sha = hashlib.sha256(b"Catalog").hexdigest()
    entries = {
        "file://sales/catalog.json": make_test_entry("file://sales/catalog.json", content="Catalog"),
    }
    hub.set_active_entries(entries)
    assert node_eu.current_sequence == 1001

    # Simulate WAN partition cutting off eu-west-1
    hub.partition_region("eu-west-1")
    assert node_eu.is_partitioned is True

    # Hub publishes sequence 1002 while EU is disconnected
    hub.set_active_entries({"file://new_file.txt": make_test_entry("file://new_file.txt")})

    # EU node must not have received sequence 1002
    assert node_eu.current_sequence == 1001

    # Edge node evaluates traffic autonomously in partition mode
    payload = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "user",
                "content": f'<pod:object locator="file://sales/catalog.json" sha256="{cat_sha}">Catalog</pod:object>',
            }
        ],
    }
    outcome = node_eu.evaluate_request(payload, headers={"X-POD-Caller-Key": "pod-key-public"})

    assert outcome.allowed_to_forward is True
    assert node_eu.total_evaluations == 1
    assert node_eu.partition_evaluations == 1
    assert len(node_eu.local_audit_buffer) == 1
    assert node_eu.local_audit_buffer[0].autonomous_partition_served is True


def test_partition_healing_and_audit_drain():
    hub = CentralGovernanceHub(primary_region="us-east-1")
    node_ap = RegionalPrevalidatorNode(region_id="ap-southeast-1")
    hub.register_region("ap-southeast-1", node_ap)

    doc_sha = hashlib.sha256(b"Doc").hexdigest()
    hub.set_active_entries({"file://initial.md": make_test_entry("file://initial.md", content="Doc")})
    assert node_ap.current_sequence == 1001

    # Partition AP region
    hub.partition_region("ap-southeast-1")

    # Serve 3 requests during partition
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": f'<pod:object locator="file://initial.md" sha256="{doc_sha}">Doc</pod:object>'}],
    }
    for _ in range(3):
        node_ap.evaluate_request(payload, headers={"X-POD-Caller-Key": "pod-key-public"})

    assert len(node_ap.local_audit_buffer) == 3
    assert len(hub.central_worm_ledger) == 0

    # Advance central hub to sequence 1004
    hub.set_active_entries({"file://v2.md": make_test_entry("file://v2.md")})
    hub.set_active_entries({"file://v3.md": make_test_entry("file://v3.md")})
    hub.set_active_entries({"file://v4.md": make_test_entry("file://v4.md")})

    # Heal the partition
    drained_count = hub.heal_partition("ap-southeast-1")
    assert drained_count == 3
    assert node_ap.is_partitioned is False

    # Verify AP node fast-forwarded to latest sequence 1004
    assert node_ap.current_sequence == 1004

    # Verify Central WORM ledger collected all partitioned events
    assert len(hub.central_worm_ledger) == 3
    assert all(e.region_id == "ap-southeast-1" for e in hub.central_worm_ledger)
    assert all(e.autonomous_partition_served is True for e in hub.central_worm_ledger)
    assert len(node_ap.local_audit_buffer) == 0
