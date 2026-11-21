#!/usr/bin/env python3
"""G1 Docket Developer Client CLI.

Provides command-line utilities for developers integrating G1 Docket attestation
into AI agents, RAG pipelines, and LLM applications.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from docket import __version__
from docket.client import DocketClient, DocketError, PolicyDenialError, compute_file_sha256, wrap_object_tag
from docket.watermark import embed_invisible_watermark, extract_invisible_watermark, has_invisible_watermark


def run_mode_check() -> int:
    """Assess G1 Docket environment mode (DEMO vs PRODUCTION) and operational readiness."""
    env_val = os.getenv("DOCKET_ENVIRONMENT", "").strip().lower()
    legacy = os.getenv("DOCKET_DEMO_MODE", "").strip().lower()
    profile = os.getenv("DOCKET_PROFILE", "").strip().lower()
    if env_val in ("production", "prod") or profile in ("production", "prod") or legacy in ("false", "0", "no"):
        mode_name, is_demo = "production", False
    else:
        mode_name, is_demo = "demo", True

    print("=" * 78)
    print("           G1 DOCKET: ENVIRONMENT CONFIGURATION & MODE CHECKER            ")
    print("=" * 78)
    print(f"\n[+] Active Docket Mode: {mode_name.upper()}")
    print(f"    - DOCKET_ENVIRONMENT          : {os.getenv('DOCKET_ENVIRONMENT', '(unset)')}")
    print(f"    - DOCKET_PROFILE              : {os.getenv('DOCKET_PROFILE', '(unset)')}")
    print(f"    - DOCKET_ENABLE_DEMO_BOOTSTRAP: {os.getenv('DOCKET_ENABLE_DEMO_BOOTSTRAP', 'false')}")

    errors: list[str] = []
    warnings: list[str] = []
    if not is_demo:
        gw_url = os.getenv("POD_UPSTREAM_GATEWAY_URL", "")
        if not gw_url:
            errors.append("POD_UPSTREAM_GATEWAY_URL is unset in production mode.")
        admin_key = os.getenv("POD_ADMIN_API_KEY", "")
        if not admin_key or admin_key in ("pod-dev-admin-key", "change-me-in-production-admin-key"):
            errors.append("POD_ADMIN_API_KEY is using a default or placeholder value.")
        cp_token = os.getenv("POD_CONTROL_PLANE_TOKEN", "")
        if not cp_token or cp_token in ("pod-dev-control-plane-token", "change-me-in-production-token"):
            errors.append("POD_CONTROL_PLANE_TOKEN is using a default or placeholder value.")
        db_url = os.getenv("POD_REGISTRY_DB_URL", "")
        if not db_url or "pod_password" in db_url:
            warnings.append("POD_REGISTRY_DB_URL is unset or using default demo credentials.")

    for w in warnings:
        print(f"  [!] WARNING: {w}")
    for e in errors:
        print(f"  [x] ERROR: {e}")

    if errors:
        print(f"\nRESULT: FAILED ({len(errors)} critical configuration issues for {mode_name.upper()} mode).")
        return 1
    print(f"\nRESULT: ALL CHECKS PASSED for {mode_name.upper()} mode.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument(
        "--url",
        default=argparse.SUPPRESS,
        help="G1 Docket Prevalidator / Gateway base URL (default: http://localhost:18082 or $DOCKET_BASE_URL)",
    )
    sub_common.add_argument(
        "--api-key",
        default=argparse.SUPPRESS,
        help="Optional API key for authenticated gateways ($DOCKET_API_KEY)",
    )

    parser = argparse.ArgumentParser(
        prog="docket",
        description=(
            f"G1 Docket Developer Client CLI (G1-Docket-SDK v{__version__})\n"
            "Client-side tool for AI agent developers. Interacts with remote G1 Docket\n"
            "Prevalidator gateways and performs local prompt wrapping & forensic watermarking."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        default=os.getenv("DOCKET_BASE_URL", "http://localhost:18082"),
        help="G1 Docket Prevalidator / Gateway base URL (default: http://localhost:18082 or $DOCKET_BASE_URL)",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("DOCKET_API_KEY", None),
        help="Optional API key for authenticated gateways ($DOCKET_API_KEY)",
    )
    parser.add_argument(
        "--check-mode",
        action="store_true",
        help="Validate environment configuration and production/demo readiness",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"G1-Docket-SDK v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # status
    p_status = subparsers.add_parser(
        "status",
        parents=[sub_common],
        help="Check connectivity and health of the target G1 Docket gateway",
    )
    p_status.add_argument("--json", action="store_true", help="Output raw JSON response")

    # check-mode
    subparsers.add_parser(
        "check-mode",
        parents=[sub_common],
        help="Validate environment configuration and production/demo readiness",
    )

    # lookup
    p_lookup = subparsers.add_parser(
        "lookup",
        parents=[sub_common],
        help="Query attestation record for a canonical locator from the gateway",
    )
    p_lookup.add_argument("locator", help="Canonical locator URI (e.g. file:///data/report.pdf)")
    p_lookup.add_argument("--json", action="store_true", help="Output raw JSON response")

    # wrap
    p_wrap = subparsers.add_parser(
        "wrap",
        parents=[sub_common],
        help="Wrap text or a local file into a canonical <pod:object> tag for RAG prompts",
    )
    p_wrap.add_argument("locator", help="Canonical locator URI to attribute to the object")
    p_wrap.add_argument("--file", "-f", default=None, help="Path to local file to read content and compute SHA-256")
    p_wrap.add_argument("--text", "-t", default=None, help="Raw text content to wrap")

    # watermark-embed
    p_wme = subparsers.add_parser(
        "watermark-embed",
        parents=[sub_common],
        help="Embed an invisible zero-width cryptographic watermark into text or file",
    )
    p_wme.add_argument("target", help="Text string or path to a text file")
    p_wme.add_argument("--agent-id", default="developer-agent", help="Agent identifier to embed")
    p_wme.add_argument("--owner", default="developer", help="Owner / developer identifier")
    p_wme.add_argument("--tier", default="Internal", choices=["Public", "Internal", "Confidential", "Restricted"], help="Attestation tier")
    p_wme.add_argument("--output", "-o", default=None, help="Optional output file path")

    # watermark-inspect
    p_wmi = subparsers.add_parser(
        "watermark-inspect",
        parents=[sub_common],
        help="Inspect and extract invisible cryptographic watermark from text or file",
    )
    p_wmi.add_argument("target", help="Text string or path to a text file to inspect")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "check_mode", False) or args.command == "check-mode":
        return run_mode_check()

    if not args.command:
        parser.print_help()
        print("\nNote: This is the developer client SDK. To deploy and run the server infrastructure")
        print("(Prevalidator proxy, Authoritative Registry, SIEM forwarders, WORM ledger),")
        print("see the full repository at: https://github.com/cgilbert61/G1-Docket")
        return 0

    if args.command == "status":
        try:
            with DocketClient(base_url=args.url, api_key=args.api_key, timeout=5.0) as client:
                health = client.get_health()
                if getattr(args, "json", False):
                    print(json.dumps(health, indent=2))
                else:
                    print(f"G1 Docket Gateway: {args.url}")
                    print(f"Status: {health.get('status', 'ok').upper()}")
                    print(f"Prevalidator Mode: {health.get('mode', 'unknown')}")
                    print(f"Active Snapshot Sequence: {health.get('snapshot_sequence', 'none')}")
                return 0
        except Exception as e:
            print(f"Error connecting to G1 Docket Gateway at {args.url}: {e}", file=sys.stderr)
            print("Verify that your G1 Docket server stack is running.", file=sys.stderr)
            return 1

    if args.command == "lookup":
        try:
            with DocketClient(base_url=args.url, api_key=args.api_key) as client:
                record = client.lookup_record(args.locator)
                if record is None:
                    print(f"Record NOT_FOUND for locator: {args.locator}", file=sys.stderr)
                    return 1
                if getattr(args, "json", False):
                    print(json.dumps(record, indent=2))
                else:
                    print(f"Locator: {record.get('locator')}")
                    print(f"Tier: {record.get('tier')}")
                    print(f"Status: {record.get('status')}")
                    print(f"Fingerprint: {record.get('content_sha256')}")
                return 0
        except Exception as e:
            print(f"Lookup failed: {e}", file=sys.stderr)
            return 1

    if args.command == "wrap":
        if args.file:
            path = Path(args.file)
            if not path.is_file():
                print(f"File not found: {args.file}", file=sys.stderr)
                return 1
            content = path.read_text(encoding="utf-8", errors="replace")
            sha256 = compute_file_sha256(path)
        elif args.text is not None:
            content = args.text
            import hashlib
            sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        else:
            print("Error: Specify either --file or --text to wrap.", file=sys.stderr)
            return 1
        print(wrap_object_tag(locator=args.locator, content=content, sha256=sha256))
        return 0

    if args.command == "watermark-embed":
        if Path(args.target).is_file():
            text = Path(args.target).read_text(encoding="utf-8", errors="replace")
        else:
            text = args.target
        watermarked = embed_invisible_watermark(
            text=text,
            owner=args.owner,
            agent_id=args.agent_id,
            tier=args.tier,
        )
        if args.output:
            Path(args.output).write_text(watermarked, encoding="utf-8")
            print(f"Watermarked text saved to {args.output}")
        else:
            print(watermarked)
        return 0

    if args.command == "watermark-inspect":
        if Path(args.target).is_file():
            text = Path(args.target).read_text(encoding="utf-8", errors="replace")
        else:
            text = args.target
        if not has_invisible_watermark(text):
            print("No G1 Docket invisible watermark detected.")
            return 1
        payload = extract_invisible_watermark(text)
        if payload:
            print("Invisible Watermark Detected:")
            print(f"  Owner: {payload.owner}")
            print(f"  Agent ID: {payload.agent_id}")
            print(f"  Tier: {payload.tier}")
            print(f"  Timestamp: {payload.timestamp}")
            return 0
        else:
            print("Watermark marker detected, but cryptographic payload extraction failed.", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
