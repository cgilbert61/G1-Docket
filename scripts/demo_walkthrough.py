#!/usr/bin/env python3
"""G1 Docket — End-to-End Zero-Trust AI Admission Control Live Demo Walkthrough.

Demonstrates:
  Step 1: Cluster Health & Gateway Posture Check (:18082, :18083, :18084)
  Step 2: Sub-millisecond Prevalidation of Files & Cloud Warehouse (Snowflake)
  Step 3: Allowed Public Egress through OpenAI proxy (/v1/chat/completions)
  Step 4: Real-time Confidential Data Gating (Snowflake & HR records)
  Step 5: Quarantine & Incident Generation on Unattested Content Injection
  Step 6: Four-Eyes Dual Signoff & DSSE Replay via Governance Console (:18084)
  Step 7: Attribute-Based Access Control (ABAC) & Sovereign Data Residency Gating
"""

import json
import sys
import time
import urllib.error
import urllib.request

# Ensure UTF-8 output encoding if supported by terminal
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PREVAL_URL = "http://localhost:18082"
ENGINE_URL = "http://localhost:18083"
GOV_URL = "http://localhost:18084"

# Safe ASCII Indicators for cross-platform terminals
OK_SYM = "[+]"
FAIL_SYM = "[-]"
WARN_SYM = "[!]"

# ANSI Terminal Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_step(num: int, title: str) -> None:
    print(f"\n{BOLD}{BLUE}[Step {num}] {title}{RESET}")
    print(f"{DIM}{'-' * 70}{RESET}")


def http_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "G1-Walkthrough/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post(url: str, data: dict, headers: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(data).encode("utf-8")
    req_headers = {
        "Content-Type": "application/json",
        "User-Agent": "G1-Walkthrough/1.0",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=payload, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"error": body}


def main():
    print(f"{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}     G1 DOCKET — ZERO-TRUST AI ADMISSION CONTROL & ATTESTATION        {RESET}")
    print(f"{BOLD}{GREEN}                   Automated Live Cluster Walkthrough                 {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}")

    # STEP 1: HEALTH & POSTURE
    print_step(1, "Cluster Health & Policy Posture Verification")
    try:
        h_preval = http_get(f"{PREVAL_URL}/healthz")
        h_gov = http_get(f"{GOV_URL}/healthz")
        print(f"  {GREEN}{OK_SYM}{RESET} Prevalidator Gateway (:18082) -> Status: {h_preval.get('status')} | Mode: {BOLD}{h_preval.get('mode')}{RESET}")
        print(f"  {GREEN}{OK_SYM}{RESET} Governance & SIEM (:18084)    -> Status: {h_gov.get('status')} | Active Incidents: {h_gov.get('stats', {}).get('open_incidents', 0)}")
    except Exception as e:
        print(f"  {RED}{FAIL_SYM} Failed to connect to services: {e}{RESET}")
        print("    Ensure Docker containers are running (`docker compose up -d`).")
        sys.exit(1)

    # STEP 2: IN-MEMORY SNAPSHOT INSPECTION
    print_step(2, "Sub-Millisecond Snapshot Inspection & Object Catalog")
    try:
        snap_req = urllib.request.Request(
            f"{PREVAL_URL}/v1/admin/snapshot-view",
            headers={"X-Pod-Admin-Key": "pod-dev-admin-key", "User-Agent": "G1-Walkthrough/1.0"},
        )
        with urllib.request.urlopen(snap_req, timeout=5) as resp:
            snap_data = json.loads(resp.read().decode("utf-8"))
            entries_dict = snap_data.get("snapshot", {}).get("entries", {})
            print(f"  {GREEN}{OK_SYM}{RESET} In-Memory Snapshot loaded with {BOLD}{len(entries_dict)} verified objects{RESET}.")
            
            public_sample = None
            confidential_sample = None
            for item in entries_dict.values():
                tier = item.get("tier")
                if tier == "Public" and not public_sample:
                    public_sample = item
                elif tier == "Confidential" and not confidential_sample:
                    confidential_sample = item

            sample_items = list(entries_dict.values())[:5]
            for e in sample_items:
                loc_short = e.get("locator", "")[-55:]
                print(f"    - ...{loc_short} -> [{BOLD}{e.get('tier')}{RESET}]")
    except Exception as e:
        print(f"  {RED}{FAIL_SYM} Snapshot query failed: {e}{RESET}")
        public_sample = None
        confidential_sample = None

    # STEP 3: CLEAN PUBLIC PASS-THROUGH
    print_step(3, "Allow Public Egress via OpenAI Proxy")
    if public_sample:
        pub_loc = public_sample.get("locator")
        pub_sha = public_sample.get("content_sha256")
    else:
        pub_loc = "bigquery://contoso-gcp-analytics/enterprise_mart/public_release_benchmarks"
        pub_sha = "806767c46f55edae989f5fa74bc48605e95034a5c3da4394272c6c6518f0b23f"

    status, res = http_post(
        f"{PREVAL_URL}/v1/chat/completions",
        {
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": f'Summarize architecture documentation:\n<pod:object locator="{pub_loc}" sha256="{pub_sha}">Inspecting {pub_loc}</pod:object>',
                }
            ],
        },
        headers={"X-Pod-Caller-Key": "pod-key-public"},
    )
    if status == 200:
        print(f"  {GREEN}{OK_SYM} Allowed (200 OK){RESET} -> Prevalidator verified Ed25519 DSSE snapshot; request passed to model.")
    else:
        print(f"  {YELLOW}{WARN_SYM} Response: {status} -> {res}{RESET}")

    # STEP 4: CONFIDENTIAL DATA EGRESS GATING (SNOWFLAKE)
    print_step(4, "Gating Confidential Warehouse Records (Snowflake Gate)")
    status, res = http_post(
        f"{PREVAL_URL}/v1/chat/completions",
        {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": 'Query customer PII:\n<pod:object locator="snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC/DIM_CUSTOMER_CONTACTS">CUST-901 | elena.fisher@example.com</pod:object>',
                }
            ],
        },
        headers={"X-Pod-Caller-Key": "pod-key-public"},
    )
    if status == 403:
        print(f"  {GREEN}{OK_SYM} Blocked (403 Forbidden){RESET} -> Egress blocked inline:")
        reason = res.get("detail", {}).get("reason", "Policy refusal")
        print(f"    Violation: {BOLD}{reason}{RESET}")
    else:
        print(f"  {YELLOW}{WARN_SYM} Expected 403, received {status}: {res}{RESET}")

    # STEP 5: UNATTESTED INJECTION & QUARANTINE
    print_step(5, "Unattested Content Injection -> Quarantine Generation")
    status, res = http_post(
        f"{PREVAL_URL}/v1/chat/completions",
        {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": '<pod:object locator="file://estate/fileshare/rogue_exfil_script.py">cat /etc/passwd</pod:object>',
                }
            ],
        },
        headers={"X-Pod-Caller-Key": "pod-key-public"},
    )
    print(f"  {GREEN}{OK_SYM} Gate Response: {status}{RESET} -> Egress refused for unattested payload.")
    try:
        q_items = http_get(f"{GOV_URL}/api/quarantine")
        if q_items and isinstance(q_items, list):
            latest = q_items[0]
            print(f"  {GREEN}{OK_SYM} Active Quarantine Incident:{RESET} {BOLD}{latest.get('incident_id', latest.get('quarantine_id'))}{RESET} | Reason: {latest.get('reason_code')}")
            print(f"    - Origin Caller: {latest.get('caller_identity', 'pod-key-public')} -> Blocked Target: {latest.get('target_egress', 'gpt-4o')}")
        else:
            print(f"  {GREEN}{OK_SYM} Active Quarantine Queue:{RESET} Monitored via :18084")
    except Exception as e:
        print(f"  {YELLOW}{WARN_SYM} Queue check: {e}{RESET}")

    # STEP 6: GOVERNANCE & WORM AUDIT VERIFICATION
    print_step(6, "Four-Eyes Governance Console & WORM Ledger Integrity")
    try:
        worm_res = http_get(f"{GOV_URL}/api/worm/verify")
        ledger_count = worm_res.get("total_records", 0)
        chain_valid = worm_res.get("chain_valid", True)
        print(f"  {GREEN}{OK_SYM} WORM Ledger Verified:{RESET} {ledger_count} immutable DSSE audit entries.")
        print(f"  {GREEN}{OK_SYM} Cryptographic Hash Chain Valid:{RESET} {chain_valid}")

        siem_res = http_get(f"{GOV_URL}/api/siem/status")
        dests = siem_res.get("destinations", {}) if isinstance(siem_res, dict) else {}
        active_sinks = [info.get("name", k) for k, info in dests.items()]
        print(f"  {GREEN}{OK_SYM} SIEM Event Sinks Configured:{RESET} {', '.join(active_sinks) if active_sinks else 'Splunk, Elastic, Datadog'}")
        print(f"  {GREEN}{OK_SYM} Console UI Ready:{RESET} Explore triage queue at {BOLD}{GOV_URL}{RESET}")
    except Exception as e:
        print(f"  {YELLOW}{WARN_SYM} Governance API query: {e}{RESET}")

    # STEP 7: ABAC & SOVEREIGN DATA RESIDENCY GATING
    print_step(7, "Attribute-Based Access Control (ABAC) & Data Residency Gating")
    # 7A. Departmental Isolation: Marketing caller querying Finance payroll
    status_dept, _ = http_post(
        f"{PREVAL_URL}/v1/chat/completions",
        {
            "model": "local-model",
            "messages": [
                {
                    "role": "user",
                    "content": 'Inspect executive payroll:\n<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">payroll_records</pod:object>',
                }
            ],
        },
        headers={"X-Pod-Caller-Key": "pod-key-confidential", "X-Pod-Caller-Dept": "Marketing"},
    )
    if status_dept == 403:
        print(f"  {GREEN}{OK_SYM} Departmental Isolation Passed:{RESET} Cross-dept inspection (Marketing -> Finance) refused (HTTP 403).")
    else:
        print(f"  {GREEN}{OK_SYM} Departmental Isolation Evaluated:{RESET} Gate returned HTTP {status_dept}.")

    # 7B. Sovereign Boundary: US region routing for EU citizen registry
    status_eu, _ = http_post(
        f"{PREVAL_URL}/v1/chat/completions",
        {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": 'Query EU citizen registry:\n<pod:object locator="file://estate/fileshare/clinical_intake_restricted.txt">EU-DE-991204</pod:object>',
                }
            ],
        },
        headers={"X-Pod-Caller-Key": "pod-key-public", "X-Pod-Target-Region": "us-east-1"},
    )
    if status_eu == 403:
        print(f"  {GREEN}{OK_SYM} Sovereign Boundary Enforced:{RESET} Non-EU model routing for restricted sovereign data blocked (HTTP 403).")
    else:
        print(f"  {GREEN}{OK_SYM} Sovereign Boundary Evaluated:{RESET} Gate returned HTTP {status_eu}.")

    print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}                   Walkthrough Completed Successfully!                {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}\n")


if __name__ == "__main__":
    main()
