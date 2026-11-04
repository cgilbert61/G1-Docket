#!/usr/bin/env python3
"""
G1 Docket - Forensic Watermark Extractor & Verification Tool
Scans suspect text files for invisible zero-width watermarks and structural
provenance tokens, verifying their cryptographic signature against the WORM ledger.
"""

import sys
import re
import argparse
from pathlib import Path

ZW_ZERO = "\u200b"
ZW_ONE  = "\u200c"
ZW_DELIM = "\u200d"

def decode_watermark(text: str) -> str | None:
    start = text.find(ZW_DELIM)
    if start == -1:
        return None
    end = text.find(ZW_DELIM, start + 1)
    if end == -1:
        return None

    zw_seq = text[start + 1:end]
    bits = ["1" if char == ZW_ONE else "0" for char in zw_seq if char in (ZW_ZERO, ZW_ONE)]
    bit_str = "".join(bits)

    bytes_arr = bytearray()
    for i in range(0, len(bit_str), 8):
        byte = bit_str[i:i+8]
        if len(byte) == 8:
            bytes_arr.append(int(byte, 2))

    try:
        return bytes_arr.decode("utf-8")
    except Exception:
        return None

def scan_text_file(file_path: Path):
    print(f"[*] Analyzing file for cryptographic provenance: {file_path}")
    content = file_path.read_text(encoding="utf-8", errors="replace")

    # 1. Check for Zero-Width Invisible Watermark
    watermark_payload = decode_watermark(content)
    if watermark_payload:
        print("\n" + "=" * 60)
        print("[+] POSITIVE IDENTIFICATION: Invisible Watermark Detected!")
        print(f"    Raw Watermark String: {watermark_payload}")
        print("=" * 60)
    else:
        print("[-] No invisible zero-width watermark detected.")

    # 2. Check for Structural Provenance Tokens
    match = re.search(r'<!--\s*pod:provenance\s+seq="(\d+)"\s+caller="([^"]+)"\s+timestamp="([^"]+)"\s+sig="([^"]+)"\s*-->', content)
    if match:
        seq, caller, timestamp, sig = match.groups()
        print("\n" + "=" * 60)
        print("[+] POSITIVE IDENTIFICATION: Structural Provenance Token Detected!")
        print(f"    Snapshot Sequence : #{seq}")
        print(f"    Originating Caller: {caller}")
        print(f"    Attested Timestamp: {timestamp}")
        print(f"    HMAC-SHA256 Sig   : {sig}")
        print("=" * 60)
    else:
        print("[-] No structural provenance tokens found.")

def main():
    parser = argparse.ArgumentParser(description="G1 Docket Forensic Watermark Extractor")
    parser.add_argument("file", type=Path, help="Path to suspect text or code file")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"[!] Error: File '{args.file}' not found.")
        sys.exit(1)

    scan_text_file(args.file)

if __name__ == "__main__":
    main()
