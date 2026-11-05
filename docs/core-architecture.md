# Core Architectural Principles

**G1 DOCKET — DATA ATTESTATION FOR YOUR GATEWAY AND YOUR AI**  
*G1163RT Security Labs · ops@g1163rt.ai · G1 Docket Core Architecture*

> 📄 **Downloadable Whitepaper**: [`G1-Docket-Core-Architecture.pdf`](whitepapers/G1-Docket-Core-Architecture.pdf)

---

G1 Docket does not require GPUs. Prevalidation operates on cryptographic byte hashing (SHA-256), Ed25519 DSSE signatures, and in-memory authenticated lookup against a signed snapshot. The workload is bound by **single-thread CPU clock speed, memory bandwidth, and network I/O** — not tensor compute. Every sizing figure in this document follows from that one principle.

> **How to read this document.** This is the enterprise reference architecture for deploying G1 Docket at 10M–100M governed objects: the topology, sizing, and operating patterns an adopter implements on their own platform (Kubernetes sizing is given as the common enterprise case). The open-source build itself ships on Docker Compose and runs the same engine, snapshot format, and prevalidator at workstation scale. Performance figures are the benchmark suite's measured values; where a number in this document is a projection rather than a measurement, it is labelled as one.

---

## 1 · Enterprise sizing & resource matrix (10M – 100M objects)

| Subsystem component | Role & function | Sizing (per pod / node) | F500 cluster topology | Cloud sizing examples |
| :--- | :--- | :--- | :--- | :--- |
| **Prevalidator AI Gateway (:18082)** | Inline ingress proxy in front of LLMs & LiteLLM / vLLM clusters | 2–4 vCPU, 2–4 GB RAM (fast DDR5), zero disk dependency | 3 to 10 replicas (HPA at 70% CPU / request velocity) | AWS `c6i.xlarge` / `c7i.xlarge` · Azure `F4s_v2` · GCP `c2-standard-4` |
| **Attestation & DLP Engine (:18083)** | Background crawler, Tika extractor & Presidio DLP classifier | 16–32 vCPU, 32–64 GB RAM, high-IOPS NVMe | 2 to 4 worker nodes (partitioned by bucket or data store) | AWS `c6i.4xlarge` / `m6i.4xlarge` · Azure `D16s_v5` · GCP `c2-standard-16` |
| **Authoritative Registry DB** | PostgreSQL catalog of signed in-toto v1 records & state machine | 4–8 vCPU, 32–64 GB RAM, Multi-AZ / high availability | Managed cloud PostgreSQL (1 TB NVMe, provisioned IOPS) | AWS Aurora PostgreSQL `db.r6g.xlarge` · Azure PostgreSQL Flexible 4–8 vCore · GCP Cloud SQL |
| **Governance & WORM Ledger (:18084)** | HITL dual-key triage server & SIEM forwarder | 2–4 vCPU, 4–8 GB RAM, 100 GB SSD PVC | 2 replicas (active-standby, replicated WORM log) | AWS `m6i.large` · Azure `D4s_v5` · GCP `e2-standard-4` |

---

## 2 · Sizing details by component

### A. Prevalidator edge gateway (hot inference path)
The gateway's working set is the signed snapshot held in memory: per the benchmark sheet, ~350 bytes per record — 3.6 GB at ten million records — with chunk-hash membership served by compact bitmap and counting-Bloom structures inside that footprint. Decisions average **159 µs** (p99 1.6 ms) with zero database calls; capacity scales horizontally across replicas, each holding the full snapshot or a shard of it. Deploy as a Kubernetes service in front of your gateway, or as a lightweight sidecar container inside your AI application pods (requests: 500m CPU, 512Mi memory).

### B. Attestation & delta crawler engine (batch / CDC path)
Initial full estate sweep at the benchmarked scan rate of 15,867 files/sec: **1M objects ≈ 63 seconds · 10M ≈ 10.5 minutes · 100M ≈ 105 minutes**. Daily delta churn at 5%: 500K changed files at the 10M scale re-attest in ~32 seconds of scan time; 5M changed files at the 100M scale take ~5 minutes single-stream and parallelise across engine workers. Ensure workers have high network bandwidth to S3 / Azure Blob / GCS to avoid ingest throttling.

### C. Database & cryptographic WORM storage
Provision the registry volume at 500 GB – 1 TB with auto-expand for estates up to 100M records. The tamper-evident WORM JSONL log belongs on append-only storage (AWS EFS / Azure Managed Disk SSD, or S3 Object Lock for archival tiers — §8), mounted read-append only.

---

## 3 · On-premise / bare-metal recommendation

For air-gapped banking, healthcare, or defence environments:
- **2× compute nodes** (prevalidation & engine workers) — dual AMD EPYC 9354 (32 cores / 64 threads, 3.25 GHz base), 128 GB DDR5 ECC, 2× 1.92 TB enterprise PCIe 4.0 NVMe (RAID-1), 2× 25 GbE SFP28;
- **2× DB / governance nodes** (high-availability PostgreSQL) — single Intel Xeon Gold 6426Y or AMD EPYC 16-core, 64 GB DDR5 ECC, 4× 1.92 TB NVMe in RAID-10.

---

## 4 · Network topology & deployment patterns

On the inference hot path, the AI service reaches the Prevalidator over a Unix domain socket or localhost (`:18082`); evaluation is local, in-RAM, and adds no network hop before the request proceeds to the internal gateway (LiteLLM, COMBINE) or cloud API. The control plane stays out of the hot path: the Snapshot Publisher and Attestation Engine publish signed DSSE snapshots (hourly) to object storage or CDN, and edge gateways in each region pull and verify them locally.

| Metric | Pattern A: Sidecar (zero-hop) | Pattern B: Ingress cluster (central gateway) |
| :--- | :--- | :--- |
| **Placement** | Prevalidator runs inside the same pod as the AI service (`localhost:18082` or Unix domain socket) | Prevalidator runs as a dedicated load-balanced service fronting the corporate AI gateway |
| **Network hop overhead** | Local IPC / loopback | VPC ingress, load balancer, intra-cluster routing |
| **Failure isolation** | Blast radius isolated to the individual calling application pod | Shared ingress cluster; requires horizontal pod autoscaling |
| **Memory tradeoff** | Each pod allocates ~500 MB RAM for the local snapshot | Central cluster shares RAM; application pods carry 0 MB Docket overhead |
| **Recommended for** | Latency-critical algorithmic trading, real-time agentic workflows, microservices | Shared corporate LLM proxy portals, developer sandboxes, enterprise chat gateways |

---

## 5 · Multi-region active-active & partition resilience

**Centralised signing, distributed verification.** The Attestation Engine and DSSE signer run in a primary control-plane region (or sovereign tenant). Gateways in secondary regions never query the primary database over a cross-region WAN; the primary publishes signed snapshots to a replicated object store (S3 Cross-Region Replication, CDN), and edge gateways download the compressed artifact on the publish cadence or consume delta streams. If the WAN is severed, edge gateways operate autonomously on their active in-memory snapshot; when that snapshot's lease expires without a signed renewal, gateways deterministically default to **FAIL_CLOSED** — protecting the perimeter without human intervention.

---

## 6 · Key hierarchy & HSM anchoring

In a regulated institution, attestation signing keys are anchored in tamper-resistant hardware, in three tiers:
- **Tier 0 — Root Attestation Authority:** the Ed25519 root key sits offline / air-gapped in a FIPS 140-2 Level 3 HSM (cold storage) and signs the intermediate authority (annually).
- **Tier 1 — Snapshot Publisher key:** held in cloud HSM / KMS (AWS CloudHSM, Azure Dedicated HSM, Vault), it signs DSSE snapshot manifests on the publish cadence.
- **Tier 2 — Edge Prevalidators:** verification public keys only — zero private keys on disk. Even a compromised gateway container yields no signing credentials.

Separately, human-in-the-loop overrides and quarantine releases on the governance server require **two distinct operator keys (Four-Eyes)**: the requester's identity token must differ from the approver's, mapped to enterprise IdP roles via OIDC / SAML 2.0, with database credentials and control tokens rotated from Vault-class secret stores.

---

## 7 · Phased rollout (AUDIT → ENFORCE)

| Phase | Duration | Posture | Objective & exit milestone |
| :--- | :--- | :--- | :--- |
| **Phase 1: Architecture & estate discovery** | Weeks 1–2 | Non-invasive | Run the Attestation Engine across enterprise stores (S3, Databricks, PostgreSQL). The initial sweep generates the first authoritative DSSE snapshot. |
| **Phase 2: Passive AUDIT mode** | Weeks 3–6 | OBSERVE (pass-through) | Deploy Prevalidators in front of AI gateways. Zero traffic blocked. Every request logged against the exit criteria. |
| **Phase 3: HITL triage & policy calibration** | Weeks 7–8 | OBSERVE (triage) | Stewards review the would-deny ledger via `:18084`. Classifications corrected, missing stores attested, legitimate denials accepted. |
| **Phase 4: Controlled ENFORCE cutover** | Day 60+ (per scale tier) | ENFORCE (inline blocking) | Flip when the exit criteria are met: ≥99% of objects in live traffic attested, daily would-deny rate flat for 7 consecutive days, every would-deny triaged. Every production denial is one already seen and accepted. |

*Audit-period length is scale-dependent and coverage-gated — see the companion sheet [How Long Should the Audit Run?](audit-period-determination.md) (30 days at mid-size to 90–180 days at sovereign scale).*

---

## 8 · Backup, retention & long-term archival

| Storage tier | Data asset | Media & retention policy | Cryptographic guarantee |
| :--- | :--- | :--- | :--- |
| **Hot cache** | Active signed DSSE snapshot | Memory (`/dev/shm`) & local node NVMe · 24 hours rolling | Ed25519 DSSE signature verified on load |
| **Operational DB** | Attestation record metadata & lineage | PostgreSQL managed cluster (Multi-AZ) · 365 days online | Row-level `content_sha256` + in-toto v1 attestation UUIDs |
| **Immutable ledger** | WORM audit log & override ledgers | AWS S3 Object Lock (Compliance mode) / Azure Immutable Blob · 7 years non-erasable | SHA-256 hash-chaining across JSONL records |
| **Cold vault** | Historical WORM checkpoints | AWS Glacier Deep Archive / Azure Archive Storage · 10 years | Archived checkpoint manifests signed with the master key |

In Compliance mode (e.g., a 2,557-day default retention ≈ 7 years), no user — including the cloud root account or corporate administrators — can overwrite, modify, or delete WORM audit logs during the retention window. Retention periods under SEC Rule 17a-4 vary by record category; the schedule above is the deployment's policy choice, not a universal statutory figure.

---

## 9 · Threat model & boundary hardening

| Attack vector | Attacker objective | Traditional gateway failure | G1 Docket defence |
| :--- | :--- | :--- | :--- |
| **Prompt tampering / context poisoning** | Inject malicious instructions or altered figures into a `<pod:object>` | LLM reads poisoned text; embedding guards miss the semantic delta | **Deterministic SHA-256 check:** the gateway recomputes the payload digest; one byte different from the signed snapshot and the request is denied (hash mismatch) |
| **Stolen / forged attestation token** | Fabricate an in-toto admission record to smuggle proprietary IP | Heuristic filters cannot verify signature authenticity | **Ed25519 DSSE signature:** the envelope is validated against the trusted public keyring, in memory; forged signatures fail |
| **Privilege escalation (clearance bypass)** | Low-clearance caller queries a Restricted document | Gateway RBAC relies on static headers that can be spoofed | **Cryptographic ABAC:** caller identity is cross-referenced against the object's classification in the snapshot; unauthorised context is stripped or blocked (`INSUFFICIENT_CLEARANCE`) |
| **Data-residency exfiltration (GDPR)** | Query EU sovereign data, route egress to an unpartitioned US model | Standard routers do not correlate data residency with model endpoints | **Sovereign region gating:** object jurisdiction is evaluated against model egress region; cross-border requests fail closed (`EGRESS_DENIED`) |
| **Replay of stale approvals** | Re-submit an old emergency bypass ticket after the document was revoked | Access caches fail to purge revoked entries in real time | **Tombstone invalidation:** revoked records publish with monotonic sequence increments; gateways hold tombstones in negative-lookup filters |

---

## 10 · Anti-patterns this architecture avoids

1. **The database-on-hot-path trap.** Querying PostgreSQL, Redis, or Elasticsearch inside the request loop exhausts connection pools under concurrency, adds 5–20 ms per request, and makes database maintenance an AI outage. Docket's answer: **zero database calls on the hot path** — the gateway evaluates an in-memory, DSSE-signed snapshot.
2. **The model-based-guardrail trap.** Using a second LLM or embedding cross-encoder to check whether a document was modified is non-deterministic, prompt-injectable, slow, and GPU-expensive. Docket's answer: **deterministic SHA-256 byte checks** — mathematical equality cannot be jailbroken.
3. **The unsigned-manifest trap.** Policy manifests in plain JSON/YAML on shared storage can be edited by any compromised credential or insider to whitelist exfiltration paths. Docket's answer: **manifests are in-toto v1 DSSE envelopes signed with Ed25519 keys**; gateways refuse to load anything without a valid signature.
4. **The premature-enforcement trap.** Flipping to active blocking on day one blocks the quarterly board deck and the month-end spreadsheet, and security gets switched off by executive backlash. Docket's answer: **the AUDIT runway** — observe until the exit criteria (99% coverage, 7-day flat would-deny rate, 100% triage) are empirically satisfied.

---

## 11 · Estate integration: connectors, CDC & RAG

Enterprise data does not live in one bucket. The Attestation Engine connects across cloud object storage (AWS S3, Azure ADLS Gen2 / OneLake, Google Cloud Storage), analytical lakehouses (Databricks Unity Catalog, Snowflake, BigQuery BigLake), and legacy on-premises shares (NFS / SMB, Dell PowerStore / Isilon, Pure FlashBlade) — via event streams (EventBridge, Event Grid, Pub/Sub) and change-data-capture feeds rather than polling, so workers stay idle until data moves. Crawling runs in two passes:
- **Pass 1** triages on watermarks (`mtime`, size, `ETag`) and skips unchanged objects at zero disk reads — on a 100M-object estate the ~95% unchanged majority is handled from metadata alone;
- **Pass 2** deep-extracts, hashes, and classifies only the changed ~5%.

For retrieval-augmented generation, **attestation is chunk-level**: the engine's chunking pipeline computes a canonical SHA-256 for each text segment and embeds the `chunk_hashes` array inside the signed in-toto statement. At inference time the Prevalidator verifies the retrieved chunk against the parent document's signed record and recomputes the inline hash — without re-downloading the source document. Tampered embeddings or poisoned vector index entries fail the hash check at the gate. The same signed snapshots replicate across a multi-cloud mesh (AWS estate, Azure inference, GCP Vertex, on-prem vLLM / LiteLLM): every node enforces locally, with zero cross-cloud calls on the decision path, and sovereign objects are stopped before cross-border transit occurs.

---

## 12 · Forensic verification & tamper evidence

The governance WORM ledger is a **cryptographic hash chain**: each event incorporates the hash of the preceding event. A verification pass recomputes the chain across all historical events and reports chain validity, event count, and every dual-key authorisation on record. If an attacker alters a single byte or timestamp in an archived entry, verification fails at that exact sequence number — establishing precisely where the tampering occurred, which is what an audit team or regulator actually needs.

---

## 13 · Procurement & platform checklist

- **Kubernetes:** EKS, AKS, GKE, or OpenShift.
- **CPU:** x86_64 with AVX2 (hardware SHA-256 acceleration) or ARM64 (Graviton-class instances hash efficiently).
- **Shared memory:** pod definitions mount `emptyDir.medium: Memory` at `/dev/shm` for zero-copy snapshot mapping.
- **Egress:** Prevalidator pods require egress only to the upstream LLM gateway and telemetry sinks — zero database connectivity on the inference path.
- **Metrics:** Prometheus scraping on `:18082` (`/metrics`) at a 15-second interval for gateway latency tracking.
- **Hardening:** pods run non-root with all capabilities dropped, read-only root filesystem, and public keys mounted read-only — the CIS-aligned profile an auditor asks for.

### Summary architectural verdict

| Assessment dimension | Position |
| :--- | :--- |
| **GPU dependency** | **Zero.** Entirely CPU- and RAM-bandwidth bound. |
| **Hot-path decision budget** | **159 µs average per evaluation** (p99 1.6 ms), per the benchmark suite |
| **Database dependency** | **Zero on the hot inference path.** In-memory DSSE-signed snapshots. |
| **Infrastructure sizing** | 3–10 gateway instances (`c6i.xlarge` / `F4s_v2` class); 2–4 background engine workers (`c6i.4xlarge` class) |
| **Cost posture** | **Open source.** No licence fee and no GPU line item; the adopter's cost is the commodity compute in §1, on infrastructure they already run. |
| **Compliance posture** | Designed to produce evidence aligned to SOC 2, ISO/IEC 27001, HIPAA, SEC Rule 17a-4, and GDPR reviews; FIPS 140-2 Level 3 HSM anchoring supported in the key hierarchy. |

> **Final takeaway.** G1 Docket turns data governance from a subjective, slow, GPU-priced inspection problem into a deterministic, sub-millisecond cryptographic guarantee: stateless Prevalidators in front of your AI gateways, a background engine continuously papering the estate, complete mathematical data provenance — with zero disruption to developer velocity and zero database calls on the hot inference path.

---

*Companion sheets: [Data Sizing, Memory Footprint & Throughput Benchmarks](benchmarks-sizing.md); [How Long Should the Audit Run?](audit-period-determination.md); [Doesn't Microsoft Purview Do the Same Thing?](purview-comparison.md). G1 Docket is open source: [github.com/cgilbert61/G1-Docket](https://github.com/cgilbert61/G1-Docket).*
