<p align="center">
  <img src="prevalidator/g1_logo.png" alt="G1 Logo" width="110" />
</p>

# G1 Docket — by G1163RT Security Labs

**Cryptographic Data Attestation Framework & Zero-DB-Call AI Gateway Prevalidator (`v0.1`) — G1163RT Security Labs.**

AI gateways govern requests. Nothing attests the data those requests touch. **G1 Docket** closes that gap with three components and one open contract:

1. **The Attestation Engine (`engine/`)** — Discovers data where it lives (files, spreadsheets, databases via Apache Tika, OpenMetadata, and the **3-Stage Microsoft Purview & Multi-Cloud DLP Connector**), classifies it with Microsoft Presidio and embedded sensitivity labels (recording sensitive entity types and counts, never raw values), provides real-time ETL intake webhooks (`/v1/events/etl`) for dbt Cloud and Apache Airflow, and issues a DSSE-signed in-toto v1 attestation record per object.
2. **The Registry (`registry/`)** — The authoritative catalog of signed records on PostgreSQL/SQLAlchemy, enforcing tier-based expiry (`Restricted`: 30d, `Confidential`: 90d, `Internal`: 180d, `Public`: 365d), human-review queues for `Restricted` and low-confidence findings, immediate tier elevation, dual-approval tier lowering, and re-classification on content hash drift.
3. **The Signed Snapshot Publisher (`snapshot/`) & Consumer Conformance Suite (`conformance/`)** — Publishes short-TTL, DSSE-signed snapshots with monotonic sequence numbers and active + `expired`/`revoked` tombstones so downstream consumers enforce policy in memory with zero Registry calls in the request path.
4. **The Prevalidator (`prevalidator/`)** — A fast proxy placed in front of any AI gateway speaking standard OpenAI (`/v1/chat/completions`) or Anthropic (`/v1/messages`) formats (including SSE streaming). It evaluates `<pod:object>` blocks and request headers against the in-memory snapshot to forward, strip, or refuse requests before the gateway sees them.
5. **Governance Subsystem (`governance/`)** — Downstream compliance and triage stack featuring an immutable cryptographic WORM audit ledger, a 7-target enterprise SIEM forwarder engine with persistent SQLite buffering, and a Four-Eyes Dual-Key Human-in-the-Loop (HITL) triage interface minting Ed25519 DSSE emergency admission tickets.

---

## Repository Layout

- `schemas/` — JSON Schemas (`attestation-predicate.schema.json`, `snapshot-predicate.schema.json`, `dsse-envelope.schema.json`) and `CHANGELOG.md`
- `engine/` — Discovery and classification pipelines (OpenMetadata connector, Apache Tika extractor, Microsoft Presidio classifier, OpenLineage intake)
- `registry/` — Registry service, lifecycle state machine, human-review queue, hardened FastAPI server, local DSSE/Sigstore signing toolkit, and `pod` CLI
- `snapshot/` — Signed Snapshot Publisher service and API
- `prevalidator/` — OpenAI & Anthropic Prevalidator proxy (Enforce & Observe modes)
- `governance/` — Cryptographic WORM audit ledger, multi-target SIEM forwarders, and HITL Dual-Key triage GUI & server
- `conformance/` — Reference consumer simulator and Consumer Conformance Test Suite
- `docket/` — Typed synchronous & asynchronous Python Remote Client SDK (`DocketClient`, `AsyncDocketClient`), CLI aliases (`docket` / `pod doctor`), cryptographic prompt watermarking & forensic steganography (`docket.watermark`), prompt-audit callback handlers (`DocketLangChainCallbackHandler`), ingestion components (`DocketTransformComponent`), and RAG framework adapters (`wrap_rag_documents`, `DocketDocumentTransformer`, `DocketLlamaIndexPostprocessor`, `@attested_tool`, `DocketCrewAITool`, `@docket_langgraph_node`, `DocketAutoGenHook`, and dynamic ABAC policy hooks)
- `examples/` — Interactive Quickstart Notebook (`quickstart_interactive.ipynb`), Phase 0 worked example, Golden Synthetic Sample Estate generator, LiteLLM gateway config, reproducible end-to-end demo (`run_demo.py`), Docker stack verification (`verify_docker_stack.py`), live Enterprise Governance & Dual-Key simulation (`simulate_enterprise_governance.py`), RAG agent retrieval pipeline walkthrough (`rag_agent_walkthrough.py`), Multi-Agent Orchestration Benchmark (`multi_agent_orchestration_demo.py`), CrewAI Multi-Agent Team demo (`crewai_agent_demo.py`), LangGraph State Workflow demo (`langgraph_agent_demo.py`), Microsoft AutoGen Multi-Agent demo (`autogen_agent_demo.py`), Snowflake Zero-Trust Admission demo (`snowflake_rag_agent_demo.py`), Databricks Unity Catalog AI Agent walkthrough (`databricks_agent_demo.py`), Apache Iceberg Lakehouse walkthrough (`iceberg_agent_demo.py`), Google BigQuery walkthrough (`bigquery_agent_demo.py`), Dynamic In-Flight Field Masking walkthrough (`dynamic_masking_agent_demo.py`), and Federated Multi-Cloud Warehouse Agent walkthrough (`multicloud_warehouse_agent.py`)
- `benchmarks/` — High-Concurrency Latency & Throughput Benchmark (`benchmark_gateway_concurrency.py`) measuring sub-millisecond p50/p99 admission latencies under multi-threaded concurrency
- `docs/` — [Fortune 500 Enterprise Reference Architecture](docs/enterprise-reference-architecture.md), [Hyperscale Architecture (100M+ Objects)](docs/hyperscale-architecture.md), [Observability & Telemetry Guide](docs/observability.md), [Audit Period Determination Guide](docs/audit-period-determination.md), [Governance Subsystem](docs/governance-subsystem.md), [Operator CLI Reference](docs/cli.md), [Python SDK Guide](docs/sdk.md), [Record Format Spec](docs/record-format.md), [Consumer Contract Spec](docs/consumer-contract.md), and [Security Review](docs/security-review.md)
- `deploy/` — [Production Helm Chart](deploy/helm/g1-docket/README.md) and [Kubernetes Manifests & Edge Sidecar Patterns](deploy/k8s/README.md) for production deployment across AWS EKS, Google GKE, Azure AKS, and on-premise clusters with built-in Horizontal Pod Autoscaling (HPA) and Prometheus `/metrics` scraping
- `k8s/` — Production-grade Kubernetes manifests (Namespace, Deployment, HPA, ConfigMap, Secrets, and Zero-Trust NetworkPolicy)
- `terraform/` — AWS Infrastructure-as-Code foundation module provisioning dedicated KMS Customer Managed Keys (CMK), S3 Object Lock in non-erasable `COMPLIANCE` mode (7-year retention), and IAM IRSA service accounts
- `reports/` — [High-Concurrency Latency Benchmark Report](reports/CONCURRENCY_BENCHMARK.md), [SOC 2 & ISO 27001 Cryptographic Compliance Audit](reports/COMPLIANCE_AUDIT_REPORT.md), [Consolidated 18-Phase Verification Scorecard](reports/VERIFICATION_SCORECARD.json), and [Dual-Plane Security Benchmark Report (Docket vs. Combine)](reports/DOCKET_VS_COMBINE_BENCHMARK_REPORT.md) (600-probe empirical benchmark evaluating cryptographic data provenance vs. NLP cognitive safety)
- `scripts/` — Consolidated 18-phase verification suite (`run_all_verifications.py`), Interactive Operator & Auditor Control Menu (`interactive_menu.py`), Enterprise SIEM & SOC exporter (`export_siem_events.py`), SOC 2 evidence packager (`export_soc2_evidence.py`), standalone air-gapped auditor verifier (`docket_verify_standalone.py`), forensic token extractor (`forensic_extractor.py`), Prevalidator proxy launcher (`run_prevalidator.py`), interactive demo walkthrough (`demo_walkthrough.py`), and compliance report generator (`generate_compliance_report.py`)

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

### 4. Interactive Operator & Auditor Control Menu
Launch the interactive terminal console to run any of the enterprise verification demos, benchmarks, or cluster diagnostics with a single keystroke:
```bash
python scripts/interactive_menu.py
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

## Service Architecture & Swagger API Directory

G1 Docket deploys a modular, microservice-based attestation, prevalidation, and compliance stack:

| Port | Service Component | Interactive Swagger / UI | Key Role & Scope |
| :--- | :--- | :--- | :--- |
| **`18080`** | Registry Service | `http://localhost:18080/docs` | Authoritative PostgreSQL catalog of DSSE-signed in-toto attestation records and review queues. |
| **`18081`** | Snapshot Publisher | `http://localhost:18081/docs` | Issues short-TTL, monotonic DSSE snapshot contracts for zero-DB gate evaluation. |
| **`18082`** | Prevalidator Proxy | `http://localhost:18082/` | OpenAI/Anthropic gateway proxy, continuous estate scanner, and unified operator dashboard. |
| **`18083`** | **Attestation Engine Service** | `http://localhost:18083/docs` | Enterprise crawler, Purview/Presidio classifier, and cloud/warehouse connector API. |
| **`18084`** | **HITL Governance & SIEM Hub** | `http://localhost:18084/` & `/docs` | Cryptographic WORM audit ledger, dual-key quarantine triage GUI, and multi-target SIEM dispatcher. |
| **`14000`** | LiteLLM Mock Gateway | `http://localhost:14000/healthz` | Upstream OpenAI/Anthropic model router and mock gateway for testing. |

---

### Attestation Engine Service (`:18083/docs`)

The **Attestation Engine Service** (OpenAPI 3.1, `v0.1.0`) provides programmatic APIs to discover, inspect, and attest assets across local disks, network shares, and enterprise cloud data lakes:

```
default
├── GET  /healthz                     Service health and readiness probe
├── GET  /v1/browse-dir               Browse host drives and directories for estate targeting
├── POST /v1/attest-selected          Trigger cryptographic attestation across selected drive or path
├── GET  /v1/pc-folders               List auto-discovered workstation directories & document stores
├── GET  /v1/datastores               Query registered enterprise data stores (S3, Azure, GCS, Snowflake, BigQuery, Databricks)
├── POST /v1/datastores               Register new enterprise cloud data lake or warehouse connection
└── GET  /v1/datastores/objects       Enumerate discovered objects and partitions within enterprise datastores
```

- **`GET /v1/browse-dir`**: Takes `?path=` query parameter to navigate the host filesystem, reporting directory entries, file counts, and accessibility.
- **`POST /v1/attest-selected`**: Initiates discovery, DLP classification (Presidio + Purview metadata extraction), and cryptographic DSSE envelope issuance over all scannable files in the path.
- **`GET /v1/datastores` & `POST /v1/datastores`**: Configures enterprise cloud data stores with zero-secret credentials (AWS IAM roles, Azure Managed Identity, GCP Workload Identity / ADC, Snowflake key-pair, Databricks OAuth M2M) and runs partition-level attestation.

---

### HITL Governance Subsystem & WORM Ledger (`:18084` & `:18084/docs`)

The **Governance Subsystem** (OpenAPI 3.1, `v4.0.0`) operates the downstream compliance, immutable audit ledger, quarantine triage, and real-time SIEM streaming pipeline:

```
default
├── GET  /                            Unified HITL Triage, WORM Chain Audit & SIEM Operations Dashboard
├── GET  /api/quarantine              List all quarantined objects (un-papered files, forged envelopes, Presidio blocks)
├── GET  /api/quarantine/{id}         Inspect quarantined object metadata, payload snippet, and audit status
├── POST /api/quarantine/{id}/stage-override    Key 1: Requester stages override with operational rationale
├── POST /api/quarantine/{id}/approve-override  Key 2: Distinct Approver signs release with Ed25519 DSSE emergency ticket
├── POST /api/quarantine/{id}/reject            Formal reviewer rejection and permanent block of quarantined item
├── GET  /api/worm/verify             Full Merkle/hash-chain integrity audit from genesis block ("0"*64) to tip
├── GET  /api/worm/events             Query paginated tamper-evident WORM audit records
├── GET  /api/siem/status             Real-time health, buffer queue length, and delivered count across all 7 forwarders
├── POST /api/siem/{dest_id}/test     Synthetic probe injection with automatic fallback to persistent SQLite buffer
├── GET  /api/siem/mock-receivers     Status of embedded local mock receiver cluster (ports 18088, 19200, 15514, etc.)
├── POST /api/siem/mock-receivers/toggle Toggle local mock receivers on/off
├── GET  /api/siem/{dest_id}/config   Fetch destination parameters (URL, API keys, headers, indices, Syslog TLS)
├── POST /api/siem/{dest_id}/config   Live update destination parameters and persist to governance/config.yaml
├── POST /api/intercept               Boundary intercept webhook for Prevalidator and Combine cognitive denials
└── GET  /events/stream               Server-Sent Events (SSE) live security telemetry stream
```

#### Core Capabilities:
1. **Cryptographic WORM Audit Ledger (`worm_ledger.py`)**:
   - Implements dual-store append-only audit persistence: SQLite with triggers that raise an immediate error on any `UPDATE` or `DELETE` attempt, coupled with a canonical JSON Lines log.
   - Hash-chained with SHA-256 Merkle links from genesis block (`previous_hash = "0" * 64`) to tip.
   - `verify_ledger_integrity()` recalculates the entire chain, pinpointing line numbers and byte-level mutations if tampering occurs.
2. **Four-Eyes Dual-Key Triage Workflow (`dual_key.py`)**:
   - Intercepted un-papered data objects, forged DSSE envelope blocks, or Presidio/Combine PII denials are isolated in quarantine.
   - Override requires **two distinct authorized identities**: Requester (Key 1) stages a business justification; Approver (Key 2) validates the diff and signs an Ed25519 DSSE emergency admission ticket.
   - Upon release, the clean payload is automatically replayed through `:18082`, a `HITL_DUAL_KEY_RELEASE` record is locked into the WORM ledger, and audit notifications stream to downstream SIEMs.
3. **Multi-Target Enterprise SIEM Integration Engine (`siem_forwarder.py`)**:
   - Streams security telemetry to 7 pre-configured destinations:
     - **Splunk HEC**: `/services/collector/event`
     - **Elasticsearch / OpenSearch**: `ecs-1.12` compliant index mapping
     - **Syslog CEF Streamer**: RFC 5424 Common Event Format over TCP/TLS
     - **OpenTelemetry / SOAR Webhook**: CloudEvents structured HTTP POST
     - **Datadog Logs API**: `/api/v2/logs`
     - **Microsoft Sentinel / Azure Log Analytics**: Data Collector API
     - **AWS CloudWatch Logs**: PutLogEvents structured JSON format
   - Zero sensitive data leakage: payloads are scrubbed to hashes, rule IDs, and ticket identifiers.
   - Offline resilience: failed socket transmissions automatically persist to a local SQLite buffer queue and retry upon network reconnection.
   - Integrated GUI editor: update live endpoints, API keys, and Syslog TLS parameters on the fly with automatic persistence to `governance/config.yaml`.

---

## Enterprise AI Agent & RAG Framework Ecosystem

G1 Docket provides turnkey zero-trust admission control adapters for all leading AI agent and RAG frameworks via `docket.integrations`:

| Framework / Source | Adapter Class / Decorator | Primary Role & Guarantee |
| :--- | :--- | :--- |
| **LlamaIndex** | `DocketLlamaIndexPostprocessor` | Intercepts `NodeWithScore` batches, binds SHA-256 hashes, and rejects poisoned nodes or clearance mismatches |
| **Vector DBs** *(Milvus, Pinecone, Qdrant, Weaviate, Chroma)* | `DocketVectorRetriever` | Formats similarity search chunks into verified `<pod:object>` envelopes with automatic digest computation |
| **LangChain** | `DocketLangChainCallbackHandler` | Pre-dispatch callback auditor catching untagged context, data smuggling, or character threshold breaches |
| **CrewAI** | `DocketCrewAITool` / wrapper | Attests agent tool execution results before inter-agent communication or final delegation |
| **LangGraph** | `@docket_langgraph_node` | Wraps state transitions and messages between graph nodes with cryptographic provenance |
| **AutoGen** | `DocketAutoGenHook` | Inter-agent message hook validating and tagging conversational exchanges between conversable agents |
| **Snowflake Data Warehouse** | `@attested_tool("snowflake://...")` | Binds SQL queries and Snowpark results to verifiable table-level and column-level attestation contracts |
| **Google BigQuery** | `@attested_tool("bigquery://...")` | Validates data residency and departmental isolation on BigQuery enterprise datasets |

---

## License & Third-Party Open Source Software

G1 Docket is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).

### Open Source Dependencies & Licenses

This project relies on and incorporates open-source libraries and standards. We gratefully acknowledge the upstream maintainers:

| Package / Project | Version | Upstream License | Project URL / Source | Primary Role in G1 Docket |
| :--- | :--- | :--- | :--- | :--- |
| **FastAPI** | `>=0.109.0` | **MIT** | [tiangolo/fastapi](https://github.com/fastapi/fastapi) | Async REST API framework for Registry, Engine, Prevalidator, and Governance servers |
| **Starlette** | `~=1.10.0` | **BSD 3-Clause** | [encode/starlette](https://github.com/encode/starlette) | ASGI web core, routing, Server-Sent Events (SSE), and request processing |
| **Uvicorn** | `>=0.27.0` | **BSD 3-Clause** | [encode/uvicorn](https://github.com/encode/uvicorn) | High-performance lightning-fast ASGI server |
| **Pydantic** | `>=2.5.0` | **MIT** | [pydantic/pydantic](https://github.com/pydantic/pydantic) | Strict data validation, schema enforcement, and JSON serialization |
| **Pydantic Core** | `>=2.14.0` | **MIT** | [pydantic/pydantic-core](https://github.com/pydantic/pydantic-core) | High-speed Rust core for data parsing |
| **Cryptography** | `>=41.0.0` | **Apache-2.0 / BSD** | [pyca/cryptography](https://github.com/pyca/cryptography) | Ed25519 signing, verification, SHA-256 digests, and X.509 certificates |
| **PyJWT** | `>=2.8.0` | **MIT** | [jpadilla/pyjwt](https://github.com/jpadilla/pyjwt) | JSON Web Token (JWT) encode/decode for role-based service authentication |
| **SQLAlchemy** | `>=2.0.25` | **MIT** | [sqlalchemy/sqlalchemy](https://github.com/sqlalchemy/sqlalchemy) | Database abstraction, WAL transactions, and SQLite/PostgreSQL persistence |
| **HTTPX** | `>=0.26.0` | **BSD 3-Clause** | [encode/httpx](https://github.com/encode/httpx) | Asynchronous HTTP client for SIEM forwarder and AI Gateway reverse proxy |
| **HTTPCore** | `~=1.0.9` | **BSD 3-Clause** | [encode/httpcore](https://github.com/encode/httpcore) | Low-level HTTP transport and connection pooling |
| **JSONSchema** | `>=4.20.0` | **MIT** | [python-jsonschema/jsonschema](https://github.com/python-jsonschema/jsonschema) | Draft 2020-12 schema verification for in-toto attestation records |
| **OpenPyXL** | `>=3.1.2` | **MIT** | [openpyxl](https://foss.heptapod.net/openpyxl/openpyxl) | Spreadsheet parsing, cell extraction, and Excel workbook classification |
| **Jinja2** | `>=3.1.0` | **BSD 3-Clause** | [pallets/jinja](https://github.com/pallets/jinja) | Institutional HTML template rendering for HITL Governance dashboard |
| **PyYAML** | `>=6.0.0` | **MIT** | [yaml/pyyaml](https://github.com/yaml/pyyaml) | SIEM configuration serialization and persistent setting storage |
| **AnyIO** | `>=4.0.0` | **MIT** | [agronholm/anyio](https://github.com/agronholm/anyio) | Structured asynchronous concurrency primitives |
| **Pytest** | `>=8.0.0` | **MIT** | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) | Automated unit, regression, and conformance testing framework |
| **Click** | `>=8.0.0` | **BSD 3-Clause** | [pallets/click](https://github.com/pallets/click) | Command-line interface driver for the `pod` CLI |
| **OpenTelemetry API** | `>=1.20.0` | **Apache-2.0** | [open-telemetry/opentelemetry-python](https://github.com/open-telemetry/opentelemetry-python) | Distributed tracing, security audit events, and trace propagation |
| **Microsoft Presidio** | `>=2.2.35` | **MIT** | [microsoft/presidio](https://github.com/microsoft/presidio) | Sensitive entity recognition (PII/PHI/PCI/API keys) in document content |
| **Apache Tika** | `>=2.6.0` | **Apache-2.0** | [apache/tika](https://tika.apache.org/) | Multi-format content detection and document text extraction |
| **in-toto Specification** | `v1.0` | **Apache-2.0** | [in-toto/attestation](https://github.com/in-toto/attestation) | Standardized metadata format for cryptographic software & data supply chain attestation |
| **DSSE Specification** | `v1.0` | **Apache-2.0** | [secure-systems-lab/dsse](https://github.com/secure-systems-lab/dsse) | Dead Simple Signing Envelope for multi-key detached signatures |
| **LiteLLM** | `>=1.0.0` | **MIT** | [BerriAI/litellm](https://github.com/BerriAI/litellm) | Upstream AI gateway and OpenAI/Anthropic protocol translation |
| **SQLite** | `v3` | **Public Domain** | [sqlite.org](https://www.sqlite.org/) | Embedded transactional storage for WORM ledger, quarantine queue, and SIEM buffer |

---

## Production Observability & Prometheus Metrics

G1 Docket exposes standard Prometheus text exposition format (`text/plain; version=0.0.4; charset=utf-8`) for monitoring, alerting, and SLA tracking:

| Subsystem | Port | Endpoint | Metrics Exported |
| :--- | :--- | :--- | :--- |
| **Prevalidator Gateway** | `:18082` | `GET /metrics` | `g1_docket_mode`, `g1_docket_evaluations_total`, `g1_docket_evaluations_by_decision_total{decision="allow\|deny\|strip\|mask"}`, `g1_docket_policy_denials_by_reason_total`, `g1_docket_evaluation_duration_seconds{quantile="0.5\|0.95\|0.99"}`, `g1_docket_active_snapshot_sequence`, `g1_docket_active_snapshot_entries` |
| **HITL Governance & SIEM** | `:18084` | `GET /metrics` | `g1_docket_governance_worm_events_total`, `g1_docket_governance_quarantine_items{status="QUARANTINED\|RELEASED\|REJECTED"}`, `g1_docket_governance_siem_destinations{enabled="true\|false"}` |

### Prometheus Alerting Rules & Helm Integration

Pre-configured Prometheus alert definitions are bundled for Helm and vanilla Kubernetes deployments under [`deploy/k8s/prometheus-alerts.yaml`](deploy/k8s/prometheus-alerts.yaml) and [`deploy/helm/g1-docket/templates/prometheusrule.yaml`](deploy/helm/g1-docket/templates/prometheusrule.yaml):

* **`G1DocketSubMillisecondSLABreached`**: Critical alert when p95 admission latency breaches the $5\text{ ms}$ SLA budget.
* **`G1DocketHashDriftSpike`**: Critical alert when $> 5$ hash drift / tamper events occur within 5 minutes.
* **`G1DocketWORMVerificationFailure`**: Critical alert when Merkle hash-chain verification detects broken ledger integrity.
* **`G1DocketQuarantineBacklog`**: Warning alert when $> 50$ quarantined items await Four-Eyes dual-key triage.

See the complete [Observability & Monitoring Guide](docs/observability.md) for Prometheus scrape configurations, Grafana dashboard JSON models, and ServiceMonitor manifests.

