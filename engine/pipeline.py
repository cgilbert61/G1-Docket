"""Attestation Engine orchestrating file-share and database discovery, classification, and Registry issuance."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from engine.classifier import CategoryFinding, PresidioClassifier
from engine.directory_bridge import iter_scannable_files, iter_scannable_files_unbounded
from engine.dlp_connectors import extract_purview_label_from_file
from engine.extractor import TikaDocumentExtractor
from engine.openlineage_intake import OpenLineageIntake
from engine.openmetadata_connector import OpenMetadataDatabaseScanner
from registry.schema_validator import SchemaValidationError
from registry.store import RegistryService


class AttestationEngine:
    """Discovers data across file shares and databases, classifies it, and issues signed records via the Registry."""

    def __init__(
        self,
        registry: RegistryService,
        extractor: TikaDocumentExtractor | None = None,
        classifier: PresidioClassifier | None = None,
        db_scanner: OpenMetadataDatabaseScanner | None = None,
        lineage_intake: OpenLineageIntake | None = None,
        engine_id: str = "pod-engine-v0.1",
    ) -> None:
        self.registry = registry
        self.extractor = extractor or TikaDocumentExtractor()
        self.classifier = classifier or PresidioClassifier()
        self.db_scanner = db_scanner or OpenMetadataDatabaseScanner()
        self.lineage_intake = lineage_intake or OpenLineageIntake()
        self.engine_id = engine_id

    def ingest_openlineage_event(self, event: dict[str, Any]) -> int:
        """Ingest an OpenLineage RunEvent to populate `derived_from` provenance links."""
        links = self.lineage_intake.ingest_event(event)
        return len(links)

    def attest_file(
        self,
        file_path: str | Path,
        owner: str | None = None,
        locator_override: str | None = None,
        environment: str = "production",
        force_rescan: bool = False,
        jurisdiction: str | None = None,
        org_unit: str | None = None,
    ) -> dict[str, Any]:
        """Extract, classify, and attest a single file or spreadsheet."""
        resolved_owner = owner or os.getenv("DOCKET_DEFAULT_OWNER", "data-owners@example.org")
        doc = self.extractor.extract_file(file_path)
        locator = locator_override or doc.locator

        existing = self.registry.lookup_by_locator(locator, include_expired_or_revoked=False)
        if (
            existing
            and not force_rescan
            and existing["content_sha256"] == doc.content_sha256
            and existing.get("chunk_hashes")
        ):
            return {"action": "unchanged", "record": existing, "review": None}

        # Stage 1 (Labels-First Fast Lane): Read embedded Purview / MIP sensitivity label directly off the file if present
        embedded_label = extract_purview_label_from_file(file_path, doc.metadata)
        findings = self.classifier.scan_text_segment(doc.text)
        metadata_hints: dict[str, Any] = {}
        classifier_engine_label = "presidio"
        source_sys_label = f"{doc.extractor_used}+presidio"
        if embedded_label.has_label and embedded_label.mapped_tier:
            findings.append(
                CategoryFinding(
                    category=f"PURVIEW_LABEL_{embedded_label.mapped_tier.upper()}",
                    count=1,
                    max_confidence=0.99,
                    column_or_field=embedded_label.source_property or "msip_label",
                )
            )
            metadata_hints["default_tier"] = embedded_label.mapped_tier
            metadata_hints["purview_label"] = embedded_label.raw_label_name
            classifier_engine_label = "msip-purview-label+presidio"
            source_sys_label = f"{doc.extractor_used}+msip-purview-label"

        verdict = self.classifier.evaluate_findings(
            findings=findings,
            metadata_hints=metadata_hints,
            classifier_engine=classifier_engine_label,
            extraction_quality=doc.extraction_quality,
            extracted_char_count=doc.extracted_char_count,
            parse_error=doc.parse_error,
        )
        derived_from = self.lineage_intake.get_derived_from(locator)

        return self.registry.issue_or_queue_finding(
            locator=locator,
            content_sha256=doc.content_sha256,
            tier=verdict.tier,
            owner=resolved_owner,
            confidence=verdict.confidence,
            low_confidence=verdict.low_confidence,
            sensitive_categories=[f.to_dict() for f in verdict.sensitive_categories],
            object_type=doc.object_type,
            display_name=doc.file_path.name,
            environment=environment,
            attested_by=self.engine_id,
            source_system=source_sys_label,
            derived_from=derived_from,
            size_bytes=doc.size_bytes,
            row_count=doc.row_count,
            fingerprint_method="raw_bytes_sha256",
            extracted_text_sha256=doc.extracted_text_sha256,
            chunk_hashes=doc.chunk_hashes,
            chunk_tree_root=doc.chunk_tree_root,
            classifier_engine=verdict.classifier_engine,
            jurisdiction=jurisdiction,
            org_unit=org_unit,
            extraction_quality=doc.extraction_quality,
            extracted_char_count=doc.extracted_char_count,
            parse_error=doc.parse_error,
        )

    def crawl_file_share(
        self,
        root_dir: str | Path,
        owner: str | None = None,
        locator_base: str | None = None,
        environment: str = "production",
        max_files: int = 120,
        include_code_dirs: bool = False,
        force_rescan: bool = False,
    ) -> list[dict[str, Any]]:
        """Crawl a directory tree or entire drive, extract with Tika, classify with Presidio, and issue/update records."""
        resolved_owner = owner or os.getenv("DOCKET_DEFAULT_OWNER", "fileshare-owners@example.org")
        root = Path(root_dir).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"Directory not found: {root}")

        results: list[dict[str, Any]] = []
        skipped_count = 0
        validation_error_count = 0

        for path, rel in iter_scannable_files_unbounded(root, include_code_dirs=include_code_dirs):
            try:
                if locator_base:
                    loc_override = f"{locator_base.rstrip('/')}/{rel}"
                else:
                    posix_path = path.resolve().as_posix()
                    if not posix_path.startswith("/"):
                        posix_path = "/" + posix_path
                    loc_override = f"file://{posix_path}"

                res = self.attest_file(
                    file_path=path,
                    owner=resolved_owner,
                    locator_override=loc_override,
                    environment=environment,
                    force_rescan=force_rescan,
                )
                results.append(res)
                if max_files > 0 and len(results) >= max_files:
                    break
            except SchemaValidationError as exc:
                skipped_count += 1
                validation_error_count += 1
                print(f"Skipped {path}: {exc}")
            except Exception as exc:
                if "validation" in exc.__class__.__name__.lower():
                    skipped_count += 1
                    validation_error_count += 1
                    print(f"Skipped {path}: {exc}")
                else:
                    # Genuinely unsupported file types may still be skipped quietly, but count them in the summary.
                    skipped_count += 1
                    continue

        self.last_crawl_stats = {
            "attested": len(results),
            "skipped": skipped_count,
            "validation_errors": validation_error_count,
        }
        return results

    def crawl_database(
        self,
        db_url: str,
        owner: str | None = None,
        locator_override_base: str | None = None,
        environment: str = "production",
        injected_om_findings: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """Crawl a database via OpenMetadata + deterministic schema/row hashing and issue records."""
        resolved_owner = owner or os.getenv("DOCKET_DEFAULT_OWNER", "db-owners@example.org")
        tables = self.db_scanner.scan_database(
            db_url=db_url,
            locator_override_base=locator_override_base,
            injected_om_findings=injected_om_findings,
        )
        results: list[dict[str, Any]] = []
        for tbl in tables:
            existing = self.registry.lookup_by_locator(tbl.locator, include_expired_or_revoked=False)
            if (
                existing
                and existing["content_sha256"] == tbl.content_sha256
                and existing.get("extracted_text_sha256") == tbl.extracted_text_sha256
                and existing.get("chunk_hashes")
            ):
                results.append({"action": "unchanged", "record": existing, "review": None})
                continue

            verdict = self.classifier.classify_columns(
                column_samples=tbl.column_samples,
                openmetadata_findings=tbl.openmetadata_findings,
            )
            lineage_links = self.lineage_intake.get_derived_from(tbl.locator) or tbl.derived_from

            res = self.registry.issue_or_queue_finding(
                locator=tbl.locator,
                content_sha256=tbl.content_sha256,
                schema_sha256=tbl.schema_sha256,
                tier=verdict.tier,
                owner=tbl.owner_hint or resolved_owner,
                steward=tbl.steward_hint,
                confidence=verdict.confidence,
                low_confidence=verdict.low_confidence,
                sensitive_categories=[f.to_dict() for f in verdict.sensitive_categories],
                object_type="database_table",
                display_name=f"{tbl.schema_name}.{tbl.table_name}",
                environment=environment,
                attested_by=self.engine_id,
                source_system="openmetadata+presidio",
                derived_from=lineage_links,
                size_bytes=tbl.size_bytes,
                row_count=tbl.row_count,
                fingerprint_method="table_schema_and_canonical_rows_sha256",
                classifier_engine=verdict.classifier_engine,
                extracted_text_sha256=tbl.extracted_text_sha256,
                chunk_hashes=tbl.chunk_hashes,
            )
            results.append(res)
        return results
