"""Document and spreadsheet extraction via Apache Tika (with deterministic local extraction for spreadsheets/docs)."""

from __future__ import annotations

import csv
import io
import json
import os
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

try:
    import openpyxl

    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

from registry.signing import (
    compute_chunk_tree_for_text,
    compute_extracted_text_and_chunk_hashes,
    compute_file_sha256,
    normalize_canonical_text,
)


@dataclass
class ExtractedDocument:
    """Extracted text, metadata, and cryptographic integrity fingerprint for a file object."""

    locator: str
    file_path: Path
    object_type: str
    content_sha256: str
    size_bytes: int
    row_count: int | None
    text: str
    metadata: dict[str, Any]
    extractor_used: str
    extracted_text_sha256: str = ""
    chunk_hashes: list[str] = field(default_factory=list)
    chunk_tree_root: str = ""
    chunk_tree_depth: int = 0
    extraction_quality: str = "COMPLETE"  # COMPLETE | PARTIAL | UNREADABLE | UNSUPPORTED | DAMAGED
    extracted_char_count: int = 0
    parse_error: str | None = None


SUPPORTED_TEXT_EXTENSIONS = {".txt", ".md", ".csv", ".tsv", ".json", ".yaml", ".yml", ".xml", ".html", ".htm", ".sql", ".log", ".ini", ".cfg", ".toml", ".py", ".sh"}
SUPPORTED_BINARY_DOC_EXTENSIONS = {".xlsx", ".docx", ".pdf", ".pptx", ".odt", ".rtf", ".doc", ".xls"}
UNSUPPORTED_BINARY_EXTENSIONS = {".bin", ".exe", ".dll", ".so", ".dylib", ".dat", ".iso", ".img", ".tar", ".gz", ".7z", ".rar", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".mp3", ".mp4", ".wav", ".avi"}


class TikaDocumentExtractor:
    """Extracts text and metadata from documents and spreadsheets via Apache Tika Server (or local Tika/XML fallback)."""

    def __init__(self, tika_server_url: str | None = None, timeout: float = 2.0) -> None:
        raw_url = tika_server_url or os.environ.get("TIKA_SERVER_ENDPOINT", "")
        self.tika_server_url = raw_url.rstrip("/") if raw_url else ""
        self.timeout = timeout

    def extract_file(self, file_path: str | Path, locator_prefix: str = "file://") -> ExtractedDocument:
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        content_sha256 = compute_file_sha256(path)
        size_bytes = path.stat().st_size
        suffix = path.suffix.lower()

        if suffix in (".xlsx", ".csv", ".tsv"):
            object_type = "spreadsheet"
        elif suffix in (".pdf", ".docx", ".doc", ".pptx", ".odt", ".rtf", ".md", ".txt"):
            object_type = "document"
        else:
            object_type = "file"

        # Normalize path into canonical URI
        posix_path = path.as_posix()
        if not posix_path.startswith("/"):
            posix_path = "/" + posix_path
        locator = f"file://{posix_path}" if locator_prefix == "file://" else locator_prefix

        # 1. Try Apache Tika Server REST endpoint (/rmeta/text) if reachable
        tika_result = self._try_tika_server(path)
        if tika_result is not None:
            text, meta, row_count = tika_result
            extracted_text_sha256, chunk_hashes, tree = compute_chunk_tree_for_text(text)
            char_count = len((text or "").strip())
            quality = "COMPLETE" if (char_count > 0 or size_bytes == 0) else "UNREADABLE"
            parse_err = None if quality == "COMPLETE" else "Tika Server returned empty text from non-empty file."
            return ExtractedDocument(
                locator=locator,
                file_path=path,
                object_type=object_type,
                content_sha256=content_sha256,
                size_bytes=size_bytes,
                row_count=row_count,
                text=text,
                metadata=meta,
                extractor_used="apache-tika-server",
                extracted_text_sha256=extracted_text_sha256,
                chunk_hashes=chunk_hashes[:256],
                chunk_tree_root=tree.root_hex,
                chunk_tree_depth=len(tree.levels) - 1,
                extraction_quality=quality,
                extracted_char_count=char_count,
                parse_error=parse_err,
            )

        # 2. Deterministic content extraction for spreadsheets (.xlsx, .csv) and documents (.docx, .txt, .md, .json, .pdf)
        text, meta, row_count, quality, parse_err = self._extract_local_content(path, suffix, size_bytes)
        extracted_text_sha256, chunk_hashes, tree = compute_chunk_tree_for_text(text)
        char_count = len((text or "").strip())
        return ExtractedDocument(
            locator=locator,
            file_path=path,
            object_type=object_type,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            row_count=row_count,
            text=text,
            metadata=meta,
            extractor_used="apache-tika-local",
            extracted_text_sha256=extracted_text_sha256,
            chunk_hashes=chunk_hashes[:256],
            chunk_tree_root=tree.root_hex,
            chunk_tree_depth=len(tree.levels) - 1,
            extraction_quality=quality,
            extracted_char_count=char_count,
            parse_error=parse_err,
        )

    def _try_tika_server(self, path: Path) -> tuple[str, dict[str, Any], int | None] | None:
        if not self.tika_server_url:
            return None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.put(
                    f"{self.tika_server_url}/rmeta/text",
                    content=path.read_bytes(),
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if isinstance(items, list) and items:
                        texts = [item.get("X-TIKA:content", "") for item in items]
                        full_text = "\n".join(t.strip() for t in texts if t and t.strip())
                        meta = {
                            k: v
                            for k, v in items[0].items()
                            if not k.startswith("X-TIKA:")
                        }
                        return full_text, meta, None
        except Exception:
            return None
        return None

    def _extract_local_content(
        self,
        path: Path,
        suffix: str,
        size_bytes: int = 0,
    ) -> tuple[str, dict[str, Any], int | None, str, str | None]:
        meta: dict[str, Any] = {"Content-Name": path.name, "File-Extension": suffix}
        row_count: int | None = None

        if suffix in UNSUPPORTED_BINARY_EXTENSIONS:
            return "", meta, None, "UNSUPPORTED", f"Unsupported binary format '{suffix}'."

        if suffix == ".xlsx":
            if not zipfile.is_zipfile(path):
                return "", meta, None, "DAMAGED", "Corrupted or truncated .xlsx archive (not a valid ZIP container)."
            if not HAS_OPENPYXL:
                return "", meta, None, "UNSUPPORTED", "openpyxl not available to parse .xlsx file."
            try:
                wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
                lines: list[str] = []
                total_rows = 0
                for sheet_name in wb.sheetnames:
                    ws = wb[sheet_name]
                    lines.append(f"[Sheet: {sheet_name}]")
                    for row in ws.iter_rows(values_only=True):
                        cells = [str(c) for c in row if c is not None and str(c).strip() != ""]
                        if cells:
                            total_rows += 1
                            lines.append(" | ".join(cells))
                wb.close()
                meta["Sheet-Count"] = len(wb.sheetnames)
                joined = "\n".join(lines)
                if size_bytes > 0 and total_rows == 0:
                    return joined, meta, 0, "UNREADABLE", "Spreadsheet contained zero readable data cells."
                return joined, meta, total_rows, "COMPLETE", None
            except Exception as exc:
                return "", meta, None, "DAMAGED", f"Failed to parse .xlsx workbook: {exc}"

        if suffix in (".csv", ".tsv"):
            raw_bytes = path.read_bytes()
            if b"\x00" in raw_bytes:
                return "", meta, None, "DAMAGED", "Binary NUL bytes detected in tabular text file."
            try:
                raw = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                return "", meta, None, "DAMAGED", f"Invalid UTF-8 encoding in tabular file: {exc}"
            delim = "\t" if suffix == ".tsv" else ","
            reader = csv.reader(io.StringIO(raw), delimiter=delim)
            rows = list(reader)
            row_count = max(0, len(rows) - 1) if rows else 0
            text = "\n".join(" | ".join(r) for r in rows)
            if size_bytes > 0 and not text.strip():
                return "", meta, 0, "UNREADABLE", "Tabular file contained no readable content."
            return text, meta, row_count, "COMPLETE", None

        if suffix == ".docx":
            if not zipfile.is_zipfile(path):
                return "", meta, None, "DAMAGED", "Corrupted or truncated .docx archive (not a valid ZIP container)."
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    if "word/document.xml" not in zf.namelist():
                        return "", meta, None, "DAMAGED", "Missing word/document.xml in .docx archive."
                    xml_bytes = zf.read("word/document.xml")
                    parse_err = None
                    quality = "COMPLETE"
                    try:
                        root = ET.fromstring(xml_bytes)
                    except ET.ParseError as exc:
                        import re as _re

                        xml_str = xml_bytes.decode("utf-8", errors="replace")
                        sanitized = _re.sub(
                            r"&(?!(?:amp|lt|gt|apos|quot|#\d+|#x[0-9a-fA-F]+);)",
                            "&amp;",
                            xml_str,
                        )
                        try:
                            root = ET.fromstring(sanitized.encode("utf-8"))
                        except ET.ParseError:
                            return "", meta, None, "DAMAGED", f"Malformed XML in word/document.xml: {exc}"
                    texts = [elem.text.strip() for elem in root.iter() if elem.text and elem.text.strip()]
                    joined = "\n".join(texts)
                    if not joined.strip():
                        return "", meta, None, "UNREADABLE", "No extractable text found in .docx document."
                    return joined, meta, None, quality, parse_err
            except Exception as exc:
                return "", meta, None, "DAMAGED", f"Failed to extract .docx archive: {exc}"

        if suffix == ".pdf":
            raw_bytes = path.read_bytes()
            if not raw_bytes.startswith(b"%PDF-"):
                return "", meta, None, "DAMAGED", "Invalid PDF header (missing %PDF- signature)."
            if b"%%EOF" not in raw_bytes[-2048:]:
                return "", meta, None, "DAMAGED", "Truncated PDF file (missing %%EOF trailer)."
            import re as _re

            # Extract literal text strings inside PDF text objects BT ... ET or parentheses
            bt_blocks = _re.findall(rb"BT[\s\S]*?ET", raw_bytes)
            extracted_parts: list[str] = []
            source_blobs = bt_blocks if bt_blocks else [raw_bytes]
            for blob in source_blobs:
                for m in _re.finditer(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*(?:Tj|TJ|'|\"|\])?", blob):
                    token = m.group(1).decode("latin-1", errors="ignore").strip()
                    if token and any(ch.isalnum() for ch in token):
                        extracted_parts.append(token)
            joined = " ".join(extracted_parts).strip()
            if not joined or len(joined) < 5:
                return "", meta, None, "UNREADABLE", "Scanned/image-only or unreadable PDF with zero extractable text."
            return joined, meta, None, "COMPLETE", None

        if suffix == ".json":
            raw_bytes = path.read_bytes()
            try:
                raw = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                return "", meta, None, "DAMAGED", f"Invalid UTF-8 in JSON file: {exc}"
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    row_count = len(parsed)
                return raw, meta, row_count, "COMPLETE", None
            except Exception as exc:
                return raw, meta, None, "DAMAGED", f"Malformed JSON syntax: {exc}"

        if suffix not in SUPPORTED_TEXT_EXTENSIONS and suffix not in SUPPORTED_BINARY_DOC_EXTENSIONS:
            return "", meta, None, "UNSUPPORTED", f"Unsupported file extension '{suffix or '<none>'}'."

        raw_bytes = path.read_bytes()
        if size_bytes == 0 and len(raw_bytes) == 0:
            return "", meta, None, "UNREADABLE", "Empty 0-byte file."
        if b"\x00" in raw_bytes:
            return "", meta, None, "DAMAGED", "Binary NUL bytes found in text document."
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            text = raw_bytes.decode("utf-8", errors="replace")
            return text, meta, None, "PARTIAL", f"Partial UTF-8 decoding error: {exc}"

        if not text.strip():
            return "", meta, None, "UNREADABLE", "Whitespace-only or empty text content."
        return text, meta, None, "COMPLETE", None
