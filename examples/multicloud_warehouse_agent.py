#!/usr/bin/env python3
"""G1 Docket — Federated Multi-Cloud Warehouse Agent Admission Control.

Demonstrates:
  1. Federated cross-cloud SQL & Object Store agent querying:
     - Snowflake: `snowflake://.../FINANCE_PROD/PUBLIC/PUBLIC_PRODUCT_SKU_CATALOG` (Public)
     - Google BigQuery: `bigquery://contoso-gcp-analytics/enterprise_mart/public_release_benchmarks` (Public)
     - AWS S3: `s3://acme-corp-datalake-prod/rag-knowledge/public_reference_dataset.parquet` (Public)
  2. Federated prompt with multi-cloud `@attested_tool` wrapped outputs.
  3. Prevalidator (< 1 ms in-memory) verifying provenance across all 3 cloud locators simultaneously.
  4. Cross-cloud boundary enforcement:
     - Scenario 1: Multi-cloud Public Join -> gpt-4o (ALLOW)
     - Scenario 2: Mixed Federation (Public Snowflake + Confidential AWS S3 CRM) -> gpt-4o (DENY: EGRESS_DENIED)
     - Scenario 3: Cleared Routing of Mixed Federation to Private / Local Model (ALLOW)
     - Scenario 4: Restricted Cloud Spill Prevention (BigQuery HIPAA Patient Encounters) -> gpt-4o (DENY: INSUFFICIENT_CLEARANCE)
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

SF_CATALOG = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/PUBLIC_PRODUCT_SKU_CATALOG"
BQ_BENCHMARKS = "bigquery://contoso-gcp-analytics/enterprise_mart/public_release_benchmarks"
S3_PUBLIC = "s3://acme-corp-datalake-prod/rag-knowledge/public_reference_dataset.parquet"

S3_CONFIDENTIAL = "s3://acme-corp-datalake-prod/rag-knowledge/customer_crm_records.parquet"
BQ_HIPAA = "bigquery://contoso-gcp-analytics/enterprise_mart/hipaa_patient_encounters"


def main() -> int:
    print("=" * 80)
    print("   G1 DOCKET: FEDERATED MULTI-CLOUD WAREHOUSE AGENT ADMISSION CONTROL   ")
    print("                 (Snowflake + Google BigQuery + AWS S3)                  ")
    print("=" * 80)

    with DocketClient(base_url="http://localhost:18082") as client:
        health = client.get_health()
        print(f"\n[+] Prevalidator Online: mode={health.get('mode')} | snapshot_seq={health.get('snapshot_sequence')}")

        # ---------------------------------------------------------------------
        # Scenario 1: Federated Public Cross-Cloud Query (Snowflake + BigQuery + S3)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 1] Federated Public Join across 3 Clouds -> gpt-4o")
        print("-" * 80)

        @attested_tool(SF_CATALOG, auto_hash=True)
        def query_snowflake_catalog() -> str:
            return "SKU-100 | Quantum Router | $1,299.00 | Available"

        @attested_tool(BQ_BENCHMARKS, auto_hash=True)
        def query_bigquery_benchmarks() -> str:
            return "benchmark_id:preval-gate-v1 | p50_us:71.1 | p95_us:142.0 | zero_db_calls:true"

        @attested_tool(S3_PUBLIC, auto_hash=True)
        def query_s3_reference() -> str:
            return "Public reference dataset in s3://acme-corp-datalake-prod/rag-knowledge. Approved for external AI egress."

        sf_out = query_snowflake_catalog()
        bq_out = query_bigquery_benchmarks()
        s3_out = query_s3_reference()

        federated_public_prompt = (
            "Summarize the enterprise technical posture based on our cloud estates:\n\n"
            f"1. Snowflake: {sf_out}\n"
            f"2. BigQuery: {bq_out}\n"
            f"3. AWS S3: {s3_out}\n"
        )

        resp1 = client.chat_completions(
            messages=[{"role": "user", "content": federated_public_prompt}],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        print("  [+] Federated Evaluation: 3 multi-cloud locators verified in-memory (< 1 ms).")
        print("  [+] Prevalidator Decision: ALLOW (HTTP 200 OK)")
        print(f"  [+] Model Gateway Reply: {resp1['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 2: Mixed Federation (Public Snowflake + Confidential S3)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 2] Mixed Federation: Public Snowflake + Confidential S3 CRM -> gpt-4o")
        print("-" * 80)

        @attested_tool(S3_CONFIDENTIAL, auto_hash=True)
        def query_s3_confidential_crm() -> str:
            return "customer_email: alice.vance@example.org | phone: 415-555-0133 | revenue_tier: Enterprise"

        s3_conf_out = query_s3_confidential_crm()

        mixed_prompt = (
            "Correlate product catalog with financial CRM records:\n"
            f"Snowflake Product: {sf_out}\n"
            f"AWS S3 CRM: {s3_conf_out}\n"
        )

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": mixed_prompt}],
                model="gpt-4o",
                caller_key="pod-key-public",
            )
            print("  [-] UNEXPECTED: Confidential S3 CRM reached external public model!")
        except PolicyDenialError as err:
            print(f"  [+] Prevalidator Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Denial Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Boundary Protection: Confidential S3 data blocked from public cloud egress.")

        # ---------------------------------------------------------------------
        # Scenario 3: Cleared Routing to Private Cloud / Local Model
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 3] Cleared Agent routes Mixed Federation to Private / Local Model")
        print("-" * 80)

        resp3 = client.chat_completions(
            messages=[{"role": "user", "content": mixed_prompt}],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        print("  [+] Prevalidator Decision: ALLOW (HTTP 200 OK)")
        print("  [+] Policy Alignment: Caller possesses 'Confidential' clearance and target model is 'local_only'.")
        print(f"  [+] Model Gateway Reply: {resp3['choices'][0]['message']['content']}")

        # ---------------------------------------------------------------------
        # Scenario 4: Restricted Cloud Spill Prevention (BigQuery HIPAA Data)
        # ---------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[Scenario 4] Restricted BigQuery HIPAA Patient Data -> External LLM")
        print("-" * 80)

        @attested_tool(BQ_HIPAA, auto_hash=True)
        def query_bigquery_hipaa() -> str:
            return "encounter_id:ENC-9921 | ssn:412-58-9021 | mrn:MRN-8839201 | diagnosis:ICD10-J45.909"

        bq_hipaa_out = query_bigquery_hipaa()

        try:
            client.chat_completions(
                messages=[{"role": "user", "content": f"Analyze clinical diagnosis: {bq_hipaa_out}"}],
                model="gpt-4o",
                caller_key="pod-key-analyst",
            )
            print("  [-] UNEXPECTED: Restricted HIPAA records reached external model!")
        except PolicyDenialError as err:
            print(f"  [+] Prevalidator Decision: HARD BLOCK (HTTP {err.status_code} Forbidden)")
            print(f"  [+] Reason: {err.response_body.get('error', {}).get('message')}")
            print("  [+] Healthcare Compliance: BigQuery HIPAA data cannot egress outside local boundary.")

    print("\n" + "=" * 80)
    print("   Federated Multi-Cloud Warehouse Agent Admission Control Complete!    ")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
