"""POD Command-Line Interface (`pod`): key management, attestation, lookup, verification, and lifecycle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from engine.pipeline import AttestationEngine
from registry.signing import Keyring, compute_file_sha256, verify_dsse_envelope
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pod",
        description="POD (Proof Of Data) — Data Attestation Framework CLI",
    )
    parser.add_argument("--db-url", default=None, help="Registry SQLAlchemy database URL")
    parser.add_argument("--key-dir", default=None, help="Operator keyring directory")

    sub = parser.add_subparsers(dest="command", required=True)

    # keygen / key-rotate
    p_key = sub.add_parser("keygen", help="Generate or rotate local operator signing keys")
    p_key.add_argument("--algorithm", choices=["Ed25519", "ECDSA_P256_SHA256"], default="Ed25519")
    p_key.add_argument("--rotate", action="store_true", help="Rotate active key")

    # attest
    p_att = sub.add_parser("attest", help="Discover, classify, and attest a file, directory share, or database")
    p_att.add_argument("target", help="File path, directory path, or database SQLAlchemy URL")
    p_att.add_argument("--owner", default="data-governance@example.org", help="Accountable owner identifier")
    p_att.add_argument("--locator", default=None, help="Optional canonical locator URI override")
    p_att.add_argument("--output", default=None, help="Optional path to write the signed DSSE envelope JSON")

    # lookup
    p_look = sub.add_parser("lookup", help="Look up the current attestation record by locator")
    p_look.add_argument("locator", help="Canonical object locator URI")

    # verify
    p_ver = sub.add_parser("verify", help="Verify a DSSE-signed attestation or snapshot envelope")
    p_ver.add_argument("envelope_path", help="Path to the DSSE JSON file")
    p_ver.add_argument("--file", default=None, help="Optional file on disk to verify content SHA-256 against")

    # list-expiring
    p_exp = sub.add_parser("list-expiring", help="List active records expiring within N days")
    p_exp.add_argument("--within-days", type=int, default=30, help="Horizon in days (default: 30)")

    # renew
    p_ren = sub.add_parser("renew", help="Renew a record if its content fingerprint is unchanged")
    p_ren.add_argument("locator", help="Canonical object locator URI")
    p_ren.add_argument("--sha256", default=None, help="Observed SHA-256 hex digest")
    p_ren.add_argument("--file", default=None, help="Compute observed SHA-256 from this file")

    # raise-tier
    p_raise = sub.add_parser("raise-tier", help="Immediately raise an object's classification tier")
    p_raise.add_argument("locator", help="Canonical object locator URI")
    p_raise.add_argument("new_tier", choices=["Internal", "Confidential", "Restricted"])

    # lower-tier
    p_lower = sub.add_parser("lower-tier", help="Lower an object's classification tier (requires dual approval)")
    p_lower.add_argument("locator", help="Canonical object locator URI")
    p_lower.add_argument("new_tier", choices=["Public", "Internal", "Confidential"])
    p_lower.add_argument("--approver", action="append", required=True, help="Approver ID (must specify at least 2 distinct)")
    p_lower.add_argument("--rationale", default="Dual-approved tier downgrade", help="Approval rationale")

    # revoke
    p_rev = sub.add_parser("revoke", help="Immediately revoke an attestation record")
    p_rev.add_argument("locator", help="Canonical object locator URI")
    p_rev.add_argument("--reason", default="Administrative revocation", help="Revocation reason")

    # review queue
    p_rq = sub.add_parser("review-list", help="List items in the human-review queue")
    p_rq.add_argument("--status", default="PENDING_REVIEW", help="Filter by status (default: PENDING_REVIEW)")

    p_ra = sub.add_parser("review-approve", help="Approve a pending item in the human-review queue")
    p_ra.add_argument("review_id", help="Review queue ID")
    p_ra.add_argument("--approver", required=True, help="Reviewer principal ID")
    p_ra.add_argument("--tier", default=None, choices=["Public", "Internal", "Confidential", "Restricted"])
    p_ra.add_argument("--rationale", default="Confirmed in human review")

    # publish-snapshot
    p_snap = sub.add_parser("publish-snapshot", help="Publish a signed DSSE snapshot of Registry records")
    p_snap.add_argument("--output", default="./pod_snapshot.dsse.json", help="Output path for the signed snapshot")
    p_snap.add_argument("--ttl-seconds", type=int, default=300, help="Snapshot TTL in seconds")

    # doctor
    p_doc = sub.add_parser("doctor", help="Run cluster health diagnostics and audit WORM chain integrity")
    p_doc.add_argument("--prevalidator-url", default="http://localhost:18082", help="Prevalidator gateway URL")
    p_doc.add_argument("--governance-url", default="http://localhost:18084", help="Governance triage server URL")
    p_doc.add_argument("--registry-url", default="http://localhost:18080", help="Authoritative Registry URL")
    p_doc.add_argument("--snapshot-url", default="http://localhost:18081", help="Snapshot Publisher URL")

    # watermark-inspect
    p_wi = sub.add_parser("watermark-inspect", help="Extract and cryptographically verify forensic provenance watermark from text or file")
    p_wi.add_argument("target", help="Text string or path to file to inspect")

    # watermark-embed
    p_we = sub.add_parser("watermark-embed", help="Embed an invisible zero-width cryptographic watermark into a file")
    p_we.add_argument("file", help="Path to text file to watermark")
    p_we.add_argument("--seq", type=int, default=None, help="Snapshot sequence number (defaults to live gateway sequence)")
    p_we.add_argument("--caller-key", default="pod-key-analyst", help="Caller key identity to bind to watermark")
    p_we.add_argument("--output", default=None, help="Output file path (defaults to overwrite input)")

    return parser


def run_doctor_diagnostics(preval_url: str, gov_url: str, reg_url: str, snap_url: str) -> int:
    """Probe all cluster services, report latency, and verify cryptographic WORM chain integrity."""
    import time
    import urllib.request

    def check(name: str, url: str) -> tuple[bool, str, float]:
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "G1-Doctor/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                elapsed = (time.perf_counter() - t0) * 1000
                data = json.loads(resp.read().decode("utf-8"))
                details = []
                if "mode" in data:
                    details.append(f"mode={data['mode']}")
                if "snapshot_sequence" in data:
                    details.append(f"seq={data['snapshot_sequence']}")
                if "worm_events" in data:
                    details.append(f"worm_events={data['worm_events']}")
                if "quarantine_pending" in data:
                    details.append(f"quarantine={data['quarantine_pending']}")
                detail_str = f" ({', '.join(details)})" if details else ""
                return True, f"Online{detail_str}", elapsed
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return False, f"Offline ({exc})", elapsed

    print("======================================================================")
    print("                 G1 DOCKET CLUSTER HEALTH & DIAGNOSTICS               ")
    print("======================================================================")

    targets = [
        ("Prevalidator Gateway", f"{preval_url.rstrip('/')}/healthz"),
        ("Governance & SIEM", f"{gov_url.rstrip('/')}/healthz"),
        ("Authoritative Registry", f"{reg_url.rstrip('/')}/healthz"),
        ("Snapshot Publisher", f"{snap_url.rstrip('/')}/healthz"),
    ]

    all_ok = True
    for name, url in targets:
        ok, msg, ms = check(name, url)
        status_tag = "[PASS]" if ok else "[FAIL]"
        print(f" {status_tag} {name:<26} -> {msg} [{ms:.1f}ms]")
        if not ok:
            all_ok = False

    # Check WORM ledger integrity
    print("-" * 70)
    try:
        t0 = time.perf_counter()
        req = urllib.request.Request(f"{gov_url.rstrip('/')}/api/worm/verify")
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            v_data = json.loads(resp.read().decode("utf-8"))
            elapsed = (time.perf_counter() - t0) * 1000
            if v_data.get("valid"):
                print(f" [PASS] WORM Audit Merkle Chain    -> Valid ({v_data.get('total_entries', 0)} events verified) [{elapsed:.1f}ms]")
            else:
                print(f" [FAIL] WORM Audit Merkle Chain    -> Chain broken: {v_data.get('error')}")
                all_ok = False
    except Exception as exc:
        print(f" [WARN] WORM Audit Merkle Chain    -> Could not verify ({exc})")

    print("======================================================================")
    if all_ok:
        print(" [OK] All cluster admission control services are operational.")
        return 0
    else:
        print(" [!] One or more cluster services failed health verification.")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        return run_doctor_diagnostics(
            preval_url=args.prevalidator_url,
            gov_url=args.governance_url,
            reg_url=args.registry_url,
            snap_url=args.snapshot_url,
        )

    if args.command == "keygen":
        keyring = Keyring(args.key_dir or "./.pod_keys")
        meta = (
            keyring.rotate_key(algorithm=args.algorithm)
            if args.rotate
            else keyring.generate_key(algorithm=args.algorithm)
        )
        print(json.dumps({"keyid": meta["keyid"], "algorithm": meta["algorithm"], "status": meta["status"]}, indent=2))
        return 0

    registry = RegistryService(db_url=args.db_url, key_dir=args.key_dir)
    try:
        if args.command == "attest":
            engine = AttestationEngine(registry=registry)
            target = args.target
            if "://" in target and not target.startswith("file://"):
                res = engine.crawl_database(db_url=target, owner=args.owner, locator_override_base=args.locator)
                print(json.dumps(res, indent=2))
                return 0

            path = Path(target.replace("file://", ""))
            if path.is_dir():
                res = engine.crawl_file_share(root_dir=path, owner=args.owner, locator_base=args.locator)
                print(json.dumps(res, indent=2))
                return 0

            res = engine.attest_file(file_path=path, owner=args.owner, locator_override=args.locator)
            if args.output and res.get("record"):
                Path(args.output).write_text(
                    json.dumps(res["record"]["dsse_envelope"], indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            print(json.dumps(res, indent=2))
            return 0

        if args.command == "lookup":
            rec = registry.lookup_by_locator(args.locator)
            if not rec:
                print(json.dumps({"error": "NOT_FOUND", "locator": args.locator}), file=sys.stderr)
                return 1
            print(json.dumps(rec, indent=2))
            return 0

        if args.command == "verify":
            env = json.loads(Path(args.envelope_path).read_text(encoding="utf-8"))
            expected_sha = compute_file_sha256(args.file) if args.file else None
            try:
                ver = verify_dsse_envelope(
                    envelope=env,
                    keyring=registry.keyring,
                    expected_content_sha256=expected_sha,
                )
                print(
                    json.dumps(
                        {
                            "verified": ver.verified,
                            "keyid": ver.keyid,
                            "algorithm": ver.algorithm,
                            "predicate_type": ver.predicate_type,
                            "subject_name": ver.subject_name,
                            "subject_sha256": ver.subject_sha256,
                        },
                        indent=2,
                    )
                )
                return 0
            except Exception as exc:
                print(json.dumps({"verified": False, "error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "list-expiring":
            records = registry.list_expiring(within_days=args.within_days)
            print(json.dumps({"count": len(records), "records": records}, indent=2))
            return 0

        if args.command == "renew":
            sha = args.sha256 or (compute_file_sha256(args.file) if args.file else None)
            if not sha:
                print(json.dumps({"error": "Must provide --sha256 or --file"}), file=sys.stderr)
                return 1
            try:
                rec = registry.renew_record(locator=args.locator, observed_content_sha256=sha)
                print(json.dumps(rec, indent=2))
                return 0
            except Exception as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "raise-tier":
            try:
                rec = registry.raise_tier(locator=args.locator, new_tier=args.new_tier)
                print(json.dumps(rec, indent=2))
                return 0
            except Exception as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "lower-tier":
            approvals = [{"approver_id": a, "rationale": args.rationale} for a in args.approver]
            try:
                rec = registry.lower_tier(locator=args.locator, new_tier=args.new_tier, approvals=approvals)
                print(json.dumps(rec, indent=2))
                return 0
            except Exception as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "revoke":
            try:
                rec = registry.revoke_record(locator=args.locator, reason=args.reason)
                print(json.dumps(rec, indent=2))
                return 0
            except Exception as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "review-list":
            items = registry.list_review_queue(status=args.status)
            print(json.dumps({"count": len(items), "reviews": items}, indent=2))
            return 0

        if args.command == "review-approve":
            try:
                res = registry.approve_pending_review(
                    review_id=args.review_id,
                    approver_id=args.approver,
                    confirmed_tier=args.tier,
                    rationale=args.rationale,
                )
                print(json.dumps(res, indent=2))
                return 0
            except Exception as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 1

        if args.command == "publish-snapshot":
            pub = SnapshotPublisher(
                registry=registry,
                ttl_seconds=args.ttl_seconds,
                snapshot_output_path=args.output,
            )
            env = pub.publish_snapshot()
            print(json.dumps({"published": True, "path": str(args.output), "signatures": env["signatures"]}, indent=2))
            return 0

        if args.command == "watermark-inspect":
            target = args.target
            p = Path(target)
            content = p.read_text(encoding="utf-8") if (p.exists() and p.is_file()) else target

            from docket.watermark import extract_invisible_watermark, has_invisible_watermark
            import re
            
            res: dict[str, Any] = {"inspected_target": str(p) if (p.exists() and p.is_file()) else "raw_text_input"}
            if has_invisible_watermark(content):
                payload = extract_invisible_watermark(content)
                if payload:
                    res.update({
                        "watermark_found": True,
                        "format": "invisible_steganography",
                        **payload.to_dict(),
                    })
                else:
                    res.update({"watermark_found": False, "note": "Zero-width characters detected but payload corrupt or invalid signature"})
            else:
                m = re.search(r'<!--\s*pod:provenance\s+seq="(\d+)"\s+caller="([^"]+)"\s+timestamp="([^"]+)"\s+sig="([^"]+)"\s*-->', content)
                if m:
                    res.update({
                        "watermark_found": True,
                        "format": "structural_comment",
                        "snapshot_sequence": int(m.group(1)),
                        "caller_key": m.group(2),
                        "timestamp_iso": m.group(3),
                        "signature": m.group(4),
                    })
                else:
                    res.update({"watermark_found": False})

            print(json.dumps(res, indent=2))
            return 0 if res.get("watermark_found") else 1

        if args.command == "watermark-embed":
            p = Path(args.file)
            if not p.exists() or not p.is_file():
                print(json.dumps({"error": f"File not found: {args.file}"}), file=sys.stderr)
                return 1

            seq = args.seq
            if seq is None:
                try:
                    import urllib.request
                    with urllib.request.urlopen("http://localhost:18082/healthz", timeout=2.0) as resp:
                        h_data = json.loads(resp.read().decode("utf-8"))
                        seq = h_data.get("snapshot_sequence", 1)
                except Exception:
                    seq = 1

            from docket.watermark import embed_invisible_watermark
            content = p.read_text(encoding="utf-8")
            watermarked = embed_invisible_watermark(content, snapshot_sequence=seq, caller_key=args.caller_key)

            out_path = Path(args.output) if args.output else p
            out_path.write_text(watermarked, encoding="utf-8")

            print(json.dumps({
                "watermarked": True,
                "file": str(out_path),
                "snapshot_sequence": seq,
                "caller_key": args.caller_key,
            }, indent=2))
            return 0

        return 1
    finally:
        registry.close()


if __name__ == "__main__":
    raise SystemExit(main())
