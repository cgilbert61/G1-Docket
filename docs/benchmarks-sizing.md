# Data Sizing, Memory Footprint & Throughput Benchmarks

**G1 DOCKET — DATA ATTESTATION FOR YOUR GATEWAY AND YOUR AI**  
*G1163RT Security Labs · ops@g1163rt.ai · G1 Docket Benchmarks*

> 📄 **Downloadable Whitepaper**: [`G1-Docket-Benchmarks.pdf`](whitepapers/G1-Docket-Benchmarks.pdf)

---

G1 Docket operates on an **in-memory snapshot model**: the Prevalidator holds cryptographic attestation records directly in memory, eliminating runtime database round-trips in the request path. Below are the empirical sizing requirements, memory footprints, and throughput metrics observed across local and cluster deployments.

---

## 1 · In-memory snapshot footprint by estate size

Each attested record entry in the monotonic snapshot predicate requires approximately **320 to 380 bytes of memory** — covering the canonical locator URI, the 64-character SHA-256 digest, data tier, AI eligibility policy, clearance level, egress class, and expiration timestamp.

| Estate scale (attested objects) | Compressed DSSE envelope | In-memory RAM footprint | Snapshot load / verification | Recommended RAM |
| :--- | :--- | :--- | :--- | :--- |
| **1,000 objects** *(Demo / POC)* | ~85 KB | ~0.35 MB | < 5 ms | 256 MB |
| **10,000 objects** *(Workgroup)* | ~850 KB | ~3.5 MB | ~15 ms | 512 MB |
| **100,000 objects** *(Mid-Market)* | ~8.5 MB | ~35 MB | ~95 ms | 1 GB |
| **1,000,000 objects** *(Enterprise)* | ~85 MB | ~360 MB | ~850 ms | 2 GB – 4 GB |
| **10,000,000 objects** *(Hyperscale)* | ~850 MB | ~3.6 GB | ~7.8 s | 8 GB – 16 GB |

---

## 2 · Request evaluation latency & throughput (SLA budget: 5.0 ms)

*Measured across batch directory scans and live inline `<pod:object>` chat completions.*

| Metric | Measured value | Target SLA | Compliance |
| :--- | :--- | :--- | :--- |
| **Single tag decision (p50)** | **0.047 ms** (47.0 µs) | ≤ 1.0 ms | **100%** |
| **Single tag decision (p95)** | **0.655 ms** (655 µs) | ≤ 3.0 ms | **100%** |
| **Single tag decision (p99)** | **1.594 ms** (1,594 µs) | ≤ 5.0 ms | **100%** |
| **Average decision latency** | **0.159 ms** (159 µs) | ≤ 1.0 ms | **100%** |
| **Directory batch scanning** | **15,867 files/sec** | ≥ 5,000 files/sec | **317% of baseline** |
| **Average scan time per file** | **63.0 µs** | ≤ 200 µs | **100%** |

---

## 3 · Storage, file size & payload limits

| Data surface | Default buffer / limit | Behavior on limit exceeded | Recommended configuration |
| :--- | :--- | :--- | :--- |
| **Inline `<pod:object>` block** | 50 MB per request | Returns HTTP 413 Payload Too Large | Chunk documents prior to RAG context injection |
| **Single file hash stream** | 64 KB chunk stream | Streaming SHA-256; no file size ceiling | Can hash files > 100 GB without memory spikes |
| **PC directory scan depth** | Recursive (unbounded) | Files processed via generator iterators | Exclude `.git`, `node_modules`, and binary caches |
| **PostgreSQL catalog (1M records)** | ~450 MB disk | Tables partitioned by status / expiration | SSD storage recommended for sub-10 ms lookup |
| **Audit log rolling buffer** | 10,000 entries (in-memory) | Oldest entries rotate out automatically | Forward to ClickHouse / SIEM for permanent retention |

---

> **Internal consistency notes:**  
> Figures as measured by the G1 Docket benchmark suite across local and cluster deployments.  
> - The compressed envelope is **85 bytes per record** at every scale shown;
> - The in-memory footprint runs **350–360 bytes per record**, inside the stated 320–380 byte band;
> - Average scan time per file is the exact reciprocal of the scan rate.  
> Footprints beyond ten million objects are extrapolated — with the sharded-snapshot architecture — in the companion sheet [How Long Should the Audit Run?](audit-period-determination.md).

---

*Companion sheets: [Core Architectural Principles](core-architecture.md); [How Long Should the Audit Run?](audit-period-determination.md); [Doesn't Microsoft Purview Do the Same Thing?](purview-comparison.md). G1 Docket is open source: [github.com/cgilbert61/G1-Docket](https://github.com/cgilbert61/G1-Docket).*
