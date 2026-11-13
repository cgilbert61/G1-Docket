#!/usr/bin/env python3
"""
G1 Docket — Environment Mode & Readiness Checker.
Validates whether Docket is configured for 'demo' mode or 'production' mode,
inspects security safeguards, and verifies production readiness.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def determine_mode() -> tuple[str, bool]:
    env_val = os.getenv("DOCKET_ENVIRONMENT", "").strip().lower()
    if env_val in ("production", "prod"):
        return "production", False
    if env_val in ("demo", "dev", "test"):
        return "demo", True

    legacy = os.getenv("DOCKET_DEMO_MODE", "").strip().lower()
    if legacy in ("false", "0", "no"):
        return "production", False
    if legacy in ("true", "1", "yes"):
        return "demo", True

    return "demo", True


def run_checks() -> int:
    mode_name, is_demo = determine_mode()

    print("=" * 78)
    print("           G1 DOCKET: ENVIRONMENT CONFIGURATION & MODE CHECKER            ")
    print("=" * 78)
    print(f"\n[+] Active Docket Mode: \033[1m{mode_name.upper()}\033[0m")
    print(f"    - DOCKET_ENVIRONMENT : {os.getenv('DOCKET_ENVIRONMENT', '(unset)')}")
    print(f"    - DOCKET_DEMO_MODE    : {os.getenv('DOCKET_DEMO_MODE', '(unset)')}")

    warnings: list[str] = []
    errors: list[str] = []
    info: list[str] = []

    if is_demo:
        info.append("HITL Governance Console: 1-Click Dual Signoff & Demo Autofill enabled.")
        info.append("Inference Upstream: Local or Mock Gateway permitted.")
        info.append("Key Management: Ephemeral / local file-based keyring (.pod_keys).")

        # Check if local keys exist
        key_dir = Path(os.getenv("POD_KEY_DIR", ".pod_keys"))
        if key_dir.exists():
            info.append(f"Key directory detected at: {key_dir.resolve()}")
        else:
            info.append("Key directory not yet created (will auto-initialize on startup).")
    else:
        # Production Mode Checks
        print("\n[*] Validating Enterprise Production Prerequisites...")

        # 1. Check Upstream Gateway URL
        gw_url = os.getenv("POD_UPSTREAM_GATEWAY_URL", "")
        if not gw_url:
            errors.append("POD_UPSTREAM_GATEWAY_URL is unset. Production requires an authoritative LLM gateway endpoint.")
        elif "localhost" in gw_url or "127.0.0.1" in gw_url or "litellm-gateway" in gw_url:
            warnings.append(f"POD_UPSTREAM_GATEWAY_URL points to local/mock host ({gw_url}). Verify if this is intended.")
        else:
            info.append(f"Authoritative LLM Gateway: {gw_url}")

        # 2. Check Admin Keys
        admin_key = os.getenv("POD_ADMIN_API_KEY", "")
        if not admin_key or admin_key in ("pod-dev-admin-key", "change-me-in-production-admin-key"):
            errors.append("POD_ADMIN_API_KEY is using a default or insecure placeholder value!")
        else:
            info.append("POD_ADMIN_API_KEY is set to a custom secret.")

        # 3. Check Control Plane Token
        cp_token = os.getenv("POD_CONTROL_PLANE_TOKEN", "")
        if not cp_token or cp_token in ("pod-dev-control-plane-token", "change-me-in-production-token"):
            errors.append("POD_CONTROL_PLANE_TOKEN is using a default or insecure placeholder value!")
        else:
            info.append("POD_CONTROL_PLANE_TOKEN is set to a custom secret.")

        # 4. Check Database Connection
        db_url = os.getenv("POD_REGISTRY_DB_URL", "")
        if not db_url or "pod_password" in db_url:
            warnings.append("POD_REGISTRY_DB_URL is either unset or using default demo credentials.")
        else:
            info.append("POD_REGISTRY_DB_URL is configured.")

        # 5. Check WORM Ledger Path
        worm_path = os.getenv("WORM_JSONL_PATH", "")
        if not worm_path:
            warnings.append("WORM_JSONL_PATH is unset (defaulting to local data path).")
        else:
            info.append(f"WORM Compliance Ledger: {worm_path}")

        # 6. Check Production Crawl Target
        crawl_dir = os.getenv("DOCKET_CRAWL_DIRECTORY", "")
        if not crawl_dir or "pc_demo_folder" in crawl_dir:
            warnings.append(f"DOCKET_CRAWL_DIRECTORY is pointing to local demo folder ({crawl_dir or 'unset'}). Set to enterprise share or lakehouse URI in production.")
        else:
            info.append(f"Production Storage Target: {crawl_dir}")

        # 7. Check Enterprise Data Steward Routing
        steward = os.getenv("DOCKET_DEFAULT_STEWARD", "")
        if not steward or "@" not in steward or "example.org" in steward or "contoso.com" in steward or "demo.internal" in steward:
            warnings.append("DOCKET_DEFAULT_STEWARD is unset or using a synthetic demo email address.")
        else:
            info.append(f"Accountable Data Steward: {steward}")

    print("\n--- Diagnostic Findings ---")
    for msg in info:
        print(f"  [i] {msg}")
    for msg in warnings:
        print(f"  \033[33m[!] WARNING: {msg}\033[0m")
    for msg in errors:
        print(f"  \033[31m[x] ERROR: {msg}\033[0m")

    print("\n" + "=" * 78)
    if errors:
        print(f"RESULT: FAILED ({len(errors)} critical configuration issues for {mode_name.upper()} mode).")
        return 1
    elif warnings:
        print(f"RESULT: PASSED WITH WARNINGS ({len(warnings)} non-critical notices).")
        return 0
    else:
        print(f"RESULT: ALL CHECKS PASSED for {mode_name.upper()} mode.")
        return 0


if __name__ == "__main__":
    sys.exit(run_checks())
