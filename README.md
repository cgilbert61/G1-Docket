<p align="center">
  <img src="prevalidator/g1_logo.png" alt="G1 Logo" width="110" />
</p>

# G1 Docket — by G1163RT Security Labs

**Cryptographic Data Attestation Framework & Zero-DB-Call AI Gateway Prevalidator (`v0.1`) — G1163RT Security Labs.**

AI gateways govern requests. Nothing attests the data those requests touch. **G1 Docket** closes that gap with three components and one open contract:

1. **The Attestation Engine (`engine/`)** — Discovers data where it lives (files, spreadsheets, databases via Apache Tika, OpenMetadata, and the **3-Stage Microsoft Purview & Multi-Cloud DLP Connector**), classifies it with Microsoft Presidio and embedded sensitivity labels (recording sensitive entity types and counts, never raw values), and issues a DSSE-signed in-toto v1 attestation record per object.
2. **The Registry (`registry/`)** — The authoritative catalog of signed records on PostgreSQL/SQLAlchemy, enforcing tier-based expiry (`Restricted`: 30d, `Confidential`: 90d, `Internal`: 180d, `Public`: 365d), human-review queues for `Restricted` and low-confidence findings, immediate tier elevation, dual-approval tier lowering, and re-classification on content hash drift.
3. **The Signed Snapshot Publisher (`snapshot/`) & Consumer Conformance Suite (`conformance/`)** — Publishes short-TTL, DSSE-signed snapshots with monotonic sequence numbers and active + `expired`/`revoked` tombstones so downstream consumers enforce policy in memory with zero Registry calls in the request path.
4. **The Prevalidator (`prevalidator/`)** — A fast proxy placed in front of any AI gateway speaking standard OpenAI (`/v1/chat/completions`) or Anthropic (`/v1/messages`) formats (including SSE streaming). It evaluates `<pod:object>` blocks and request headers against the in-memory snapshot to forward, strip, or refuse requests before the gateway sees them.

---

## Repository Layout

- `schemas/` — JSON Schemas (`attestation-predicate.schema.json`, `snapshot-predicate.schema.json`, `dsse-envelope.schema.json`) and `CHANGELOG.md`
- `engine/` — Discovery and classification pipelines (OpenMetadata connector, Apache Tika extractor, Microsoft Presidio classifier, OpenLineage intake)
- `registry/` — Registry service, lifecycle state machine, human-review queue, hardened FastAPI server, local DSSE/Sigstore signing toolkit, and `pod` CLI
- `snapshot/` — Signed Snapshot Publisher service and API
- `prevalidator/` — OpenAI & Anthropic Prevalidator proxy (Enforce & Observe modes)
- `conformance/` — Reference consumer simulator and Consumer Conformance Test Suite
- `docket/` — Typed synchronous & asynchronous Python Remote Client SDK (`DocketClient`, `AsyncDocketClient`)
- `examples/` — Phase 0 worked example, Golden Synthetic Sample Estate generator, LiteLLM gateway config, and reproducible end-to-end demo
- `docs/` — [Python SDK Guide](docs/sdk.md), [Record Format Spec](docs/record-format.md), [Consumer Contract Spec](docs/consumer-contract.md), and [Security Review](docs/security-review.md)

---

## Attestation Record Schema (32 Fields)

Every data asset evaluated and attested by G1 Docket produces a DSSE-signed in-toto v1 attestation record. The payload adheres to a comprehensive 32-field governance schema across 6 functional dimensions:

### 1. Object Identity & Storage (5 Fields)
| Field | Description |
| :--- | :--- |
| `locator` | Canonical URI of the object (`file://...`, `s3://...`, `postgresql://...`). |
| `file_name` | Display filename (e.g., `07_purview_labeled_board_strategy.docx`). |
| `file_path` | Full local host or cloud storage relative path. |
| `mime_type` | Detected file content format (e.g., `application/vnd.openxmlformats...`). |
| `file_size_bytes` | Physical file size in bytes. |

### 2. Cryptographic Integrity & Provenance (5 Fields)
| Field | Description |
| :--- | :--- |
| `content_sha256` | Cryptographic SHA-256 digest of the raw content payload. |
| `attestation_id` | Unique UUID of the signed in-toto v1 attestation record. |
| `issued_at` | UTC ISO-8601 timestamp of record issuance. |
| `expires_at` | Expiry timestamp based on tier policy (`30d`, `90d`, `180d`, or `365d`). |
| `signature_key_id` | Key ID of the active Ed25519/ECDSA operator key that signed the DSSE envelope. |

### 3. Classification & AI Gateway Policy (6 Fields)
| Field | Description |
| :--- | :--- |
| `tier` | Classification tier (`Public`, `Internal`, `Confidential`, `Restricted`). |
| `ai_eligibility` | Prevalidator policy action (`allow`, `strip`, `deny`). |
| `minimum_clearance` | Lowest caller clearance key required to access the data. |
| `egress_class` | Network egress boundary allowed (`local_only`, `private_cloud`, `public_api`). |
| `classification_confidence` | Probabilistic confidence score from Presidio / ML classification (`0.0`–`1.0`). |
| `classification_method` | Classification mechanism (`purview_label`, `presidio_dlp`, `regex_heuristic`, `manual_human_review`). |

### 4. DLP, Purview & Sensitivity Findings (6 Fields)
| Field | Description |
| :--- | :--- |
| `sensitive_entity_types` | Array of detected sensitive data types (`PII`, `PHI`, `PCI`, `API_KEY`, etc.). |
| `sensitive_entity_counts` | Map of entity frequencies (records sensitive types and counts only—never raw values). |
| `total_sensitive_matches` | Aggregate count of sensitive findings in the object. |
| `purview_sensitivity_label_name` | Microsoft Purview / MIP label extracted from document XML metadata. |
| `purview_sensitivity_label_id` | Unique GUID of the Microsoft Information Protection label. |
| `purview_watermark_present` | Boolean indicating whether an enterprise protection watermark or visual marking exists. |

### 5. Ownership, Stewardship & Lineage (5 Fields)
| Field | Description |
| :--- | :--- |
| `owner_id` | Accountable business owner or email (`security@company.org`). |
| `owner_department` | Department or cost center responsible for the data asset. |
| `data_custodian` | Technical administrator / system owning storage. |
| `upstream_lineage_sources` | Origin sources or ingestion pipeline IDs (OpenLineage / OpenMetadata). |
| `downstream_consumers` | Known AI models, applications, or pipelines consuming the asset. |

### 6. Lifecycle State Machine & Review (5 Fields)
| Field | Description |
| :--- | :--- |
| `status` | Lifecycle state (`active`, `pending_review`, `expired`, `revoked`). |
| `last_scanned_at` | Timestamp of the most recent crawl/re-evaluation. |
| `last_verified_at` | Timestamp when cryptographic hash matching was last confirmed. |
| `review_queue_id` | Foreign key to the human-review governance queue if flagged for low confidence or Restricted findings. |
| `governance_approvals` | Dual-approval audit log recording approver IDs and rationales (required for declassifications). |

---

## Quickstart (Local Evaluation & Demo)

### 1. Run the Reproducible End-to-End Demo (Phases 0–3)
```bash
python -m examples.run_demo
```
This executes:
- **Phase 0**: Attests a single synthetic clinical file end-to-end, verifies the DSSE signature, and confirms that tampered files and tampered envelopes fail verification.
- **Phase 1**: Generates the synthetic estate (documents, `.xlsx` spreadsheets, and database tables), crawls both paths, holds low-confidence findings in the review queue, and exercises `raise_tier`, dual-approved `lower_tier`, and `renew`.
- **Phase 2**: Publishes a DSSE-signed snapshot (`pod_snapshot.dsse.json`).
- **Phase 3**: Runs the Prevalidator proxy against OpenAI `/v1/chat/completions` and Anthropic `/v1/messages`, verifying allowed requests, inline Confidential block stripping (`[POD:STRIPPED]`), and uniform 403 refusal on `Restricted` and `Unattested` objects.

### 2. Run the Full Test & Conformance Suite
```bash
pytest -v
```

### 3. Exercise the `pod` CLI
```bash
# Generate or rotate local operator keys
python -m registry.cli keygen

# Attest a file, directory share, or database
python -m registry.cli attest ./examples/out_demo/estate/fileshare --owner security@example.org

# Look up a record by canonical locator
python -m registry.cli lookup "file://estate/fileshare/product_overview_public.md"

# Publish a signed snapshot for the Prevalidator
python -m registry.cli publish-snapshot --output ./pod_snapshot.dsse.json
```

---

## One-Click Automated Docker Installers

Self-contained automated installers are provided for Windows and Linux/macOS. They verify prerequisites (Docker, WSL mounts if on secondary drives), prepare `.env`, build all images, launch the stack, and poll health endpoints until ready:

- **Windows**:
  ```cmd
  install.bat
  ```
- **Linux / macOS**:
  ```bash
  chmod +x install.sh
  ./install.sh
  ```

---

## Docker Compose Profiles

Three Compose profiles are provided in `docker-compose.yml`:

```bash
# 1. Core profile: Engine, Registry, Snapshot Publisher, Postgres
docker compose --profile core up -d --build

# 2. Demo profile: Everything in core + Prevalidator + Local AI Gateway + automated synthetic estate bootstrap
docker compose --profile demo up -d --build
python -m examples.verify_docker_stack

# 3. Prevalidator profile: The proxy alone, deployed beside an existing AI gateway
docker compose --profile prevalidator up -d --build
```

---

## Troubleshooting & Automated Health Loop

If secondary drives (such as `D:`) unmount after a Windows reboot, or if you need to poll for stack readiness:

### Automated WSL Remount & Health Polling Loop (PowerShell)
```powershell
# 1. Remount Drive D in Docker Desktop WSL if needed
wsl -d docker-desktop -u root -e sh -c "mkdir -p /mnt/host/d /mnt/d; mountpoint -q /mnt/host/d || mount -t drvfs D: /mnt/host/d -o metadata; mountpoint -q /mnt/d || mount --bind /mnt/host/d /mnt/d"

# 2. Poll health endpoints until active
$endpoints = @(
    "http://localhost:18080/docs",
    "http://localhost:18081/docs",
    "http://localhost:18082/healthz",
    "http://localhost:18083/healthz",
    "http://localhost:14000/healthz"
)

Write-Host "Waiting for G1 Docket services to stabilize..." -ForegroundColor Cyan
for ($i = 1; $i -le 40; $i++) {
    $pending = 0
    foreach ($url in $endpoints) {
        try {
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing
            if ($resp.StatusCode -ne 200) { $pending++ }
        } catch {
            $pending++
        }
    }
    if ($pending -eq 0) {
        Write-Host "`n[+] All G1 Docket services are healthy and active!" -ForegroundColor Green
        break
    }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 2
}
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
