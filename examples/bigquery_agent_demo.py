#!/usr/bin/env python3
"""G1 Docket — Google BigQuery AI Agent & Admission Control Walkthrough.

Demonstrates:
  1. Connecting to the G1 Docket Prevalidator gateway (:18082).
  2. Querying Google BigQuery analytics tables with diverse sensitivity tiers:
     - Public: `public_release_benchmarks` (performance & latency specs)
     - Internal: `platform_ops_cluster_inventory` (node IPs, VPC cluster topologies)
     - Restricted: `hipaa_patient_encounters` (SSNs, MRNs, ICD-10 medical diagnoses)
  3. Using `@attested_tool` for dynamic BigQuery SQL tool execution and automated SHA-256 calculation.
  4. Evaluating the 4 zero-trust admission gates:
     - Scenario 1: Public caller -> Public table (ALLOW)
     - Scenario 2: Public caller -> Internal infrastructure table (DENY: INSUFFICIENT_CLEARANCE)
     - Scenario 3: Cleared caller -> Internal table to private cloud model (ALLOW)
     - Scenario 4: Non-restricted caller -> Restricted HIPAA table (DENY: INSUFFICIENT_CLEARANCE)
     - Scenario 5: Dynamic In-Flight Field Masking on patient records (DYNAMIC MASKING: 200 OK)
     - Scenario 6: Attestation hash tampering & schema drift detection (DENY: HASH_DRIFT)
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from docket import DocketClient, PolicyDenialError
from docket.integrations import attested_tool

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BQ_BASE = "bigquery://contoso-gcp-analytics/enterprise_mart"


def main() -> int:
    print("=" * 80)
    print("      G1 DOCKET: GOOGLE BIGQUERY AI AGENT ADMISSION CONTROL DEMO       ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Prevalidator Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Agent Queries Public BigQuery Benchmark Table
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Agent queries Public table: public_release_benchmarks")
        print("-" * 80)

        @attested_tool(f"{BQ_BASE}/public_release_benchmarks", auto_hash=True)
        def query_benchmarks() -> str:
            return "benchmark_id:preval-gate-v1 | p50_us:71.1 | p95_us:142.0 | zero_db_calls:true"

        benchmark_data = query_benchmarks()
        print("  [+] BigQuery SQL Tool Output (Tagged with DSSE Provenance):")
        print(f"      {benchmark_data}")

        res1 = client.chat_completions(
            messages=[{"role": "user", "content": f"Summarize benchmarks: {benchmark_data}"}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Output: {res1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Public Agent queries Internal BigQuery Cluster Inventory Table
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Public Agent queries Internal table: platform_ops_cluster_inventory")
        print("-" * 80)

        @attested_tool(f"{BQ_BASE}/platform_ops_cluster_inventory", auto_hash=True)
        def query_cluster_inventory() -> str:
            return "cluster_id:gke-prod-us-central1 | node_ip:10.128.15.44 | internal_project:PROJECT-APOLLO"

        inv_data = query_cluster_inventory()
        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Inspect node topology: {inv_data}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Internal BigQuery table leaked to public caller!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Uniform Error: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Reason: Agent has Public clearance; table requires Internal clearance.")

        # ---------------------------------------------------------------------
        # Scenario 3: Cleared SRE routes Internal BigQuery table to Private Cloud Model
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] Cleared Agent routes Internal table to Private Cloud Model (gpt-4)")
        print("-" * 80)

        res3 = client.chat_completions(
            messages=[{"role": "user", "content": f"Analyze node topology: {inv_data}"}],
            model="gpt-4",
            caller_key="pod-key-internal",
        )
        print("  [+] Gatekeeper Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Output: {res3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 4: Non-Restricted Caller queries Restricted HIPAA BigQuery Table
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 4] Confidential Caller queries Restricted table: hipaa_patient_encounters")
        print("-" * 80)

        @attested_tool(f"{BQ_BASE}/hipaa_patient_encounters", auto_hash=True)
        def query_patient_encounters() -> str:
            return "encounter_id:ENC-9921 | ssn:412-58-9021 | mrn:MRN-8839201 | diagnosis:ICD10-J45.909"

        hipaa_data = query_patient_encounters()
        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Analyze patient diagnosis: {hipaa_data}"}],
                model="local-model",
                caller_key="pod-key-confidential",
            )
            print("  [-] UNEXPECTED: Restricted HIPAA table leaked to Confidential caller!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Uniform Error: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Reason: Caller lacks Restricted clearance for HIPAA protected health information.")

        # ---------------------------------------------------------------------
        # Scenario 5: Dynamic In-Flight Field Masking on Patient Encounters
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 5] Dynamic In-Flight Field Masking on HIPAA data (permit_masked=True)")
        print("-" * 80)

        res5 = client.chat_completions(
            messages=[{"role": "user", "content": f"Analyze encounter statistics: {hipaa_data}"}],
            model="local-model",
            caller_key="pod-key-public",
            permit_masked=True,
        )
        print("  [+] Gatekeeper Decision: DYNAMIC MASKING (HTTP 200 OK)")
        print(f"  [+] Sanitized Model Input: {res5['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 6: Cryptographic Hash Mismatch / Query Result Drift Detection
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 6] Attestation Hash Tampering / Drift Detection")
        print("-" * 80)

        tampered_bq_data = (
            f'<pod:object locator="{BQ_BASE}/public_release_benchmarks" '
            'sha256="0000000000000000000000000000000000000000000000000000000000000000">'
            'benchmark_id:preval-gate-v1 | p50_us:99999.0 | zero_db_calls:false'
            '</pod:object>'
        )

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Verify benchmark: {tampered_bq_data}"}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Tampered BigQuery benchmark bypassed gatekeeper!")
        except PolicyDenialError as err:
            print(f"  [+] Gatekeeper Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Cryptographic Integrity Enforced: Live query digest does not match signed snapshot.")

    print("\n" + "=" * 80)
    print("      Google BigQuery AI Agent Admission Control Demo Complete!       ")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
