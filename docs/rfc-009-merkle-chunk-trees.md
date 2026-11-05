# RFC-009: Cryptographic Merkle Chunk Trees (MCT) for Sub-Document Attestation

**Status:** Proposed / Accepted  
**Author:** G1 Docket Architecture Working Group  
**Target Release:** Phase 4 — High-Scale Attestation & Vector Lakehouses  
**Related Documents:**
* [`docs/core-architecture.md`](file:///d:/attestation/docs/core-architecture.md)
* [`docs/hyperscale-architecture.md`](file:///d:/attestation/docs/hyperscale-architecture.md)
* [`docs/benchmarks-sizing.md`](file:///d:/attestation/docs/benchmarks-sizing.md)

---

## 1. Executive Summary & Problem Statement

Modern enterprise generative AI architectures operate predominantly on **chunks** (retrieval fragments, embeddings, and context-window passages) rather than monolithic parent files. In real-world enterprise RAG pipelines:
* A 500-page corporate financial disclosure or clinical report breaks into 3,000–8,000 discrete chunk embeddings.
* Vector databases (Milvus, Weaviate, Pinecone, pgvector) index chunk embeddings alongside raw chunk text.
* Large Language Models ingest 5 to 50 individual chunks per prompt query.

### The Flat Chunk Attestation Ceiling
In earlier releases, G1 Docket recorded extracted chunks as a flat array of SHA-256 hashes (`att_chunks`) within the In-Toto predicate statement. To prevent attestation bloat, [`registry/signing.py`](file:///d:/attestation/registry/signing.py) enforced a hard limit of **256 chunks per document**:
```python
if len(seen) >= 256:
    return  # Cap to prevent attestation statement bloat
```
This flat-array architecture introduced three severe scaling bottlenecks:
1. **Truncation Vulnerability**: Documents exceeding ~25 pages had subsequent chunks discarded from attestation coverage, causing false-positive access denials (`UNATTESTED_OBJECT`) when legitimate passages were retrieved.
2. **Attestation Statement Bloat**: Storing 256 raw 64-character hexadecimal hashes in JSON consumes over 18 KB per attestation statement, ballooning WORM ledger storage and L1 gateway cache sizes.
3. **Linear Verification Cost**: Verifying membership of retrieved chunks required linear $\mathcal{O}(N)$ hash scanning, degrading prevalidator hot-path latency toward the 5 ms SLA ceiling.

---

## 2. Technical Architecture & Cryptographic Specification

RFC-009 replaces flat chunk hash arrays with **Cryptographic Merkle Chunk Trees (MCT)**. 

### 2.1 RFC 6962 Domain Separation
To prevent second-preimage attacks and ambiguity between leaf nodes and interior branch nodes, G1 Docket adopts strict RFC 6962 domain separation prefixes:
* **Leaf Node Prefix:** `0x00`
* **Interior Node Prefix:** `0x01`

$$\text{LeafHash}_i = \text{SHA256}(0\text{x}00 \mathbin{\Vert} \text{ChunkHash}_i)$$
$$\text{ParentNode} = \text{SHA256}(0\text{x}01 \mathbin{\Vert} \text{LeftChild} \mathbin{\Vert} \text{RightChild})$$

For odd numbers of nodes at any level, the lone rightmost node is promoted to the next level with domain separation, ensuring a deterministic, canonical Merkle root without duplicate-node malleability attacks (CVE-2012-2459).

```
                 Root Hash (Stored in In-Toto Statement: 32 bytes)
                           /             \
                  Node A (0x01)         Node B (0x01)
                  /          \          /          \
               Leaf 0      Leaf 1    Leaf 2      Leaf 3
               (0x00)      (0x00)    (0x00)      (0x00)
                 |           |         |           |
              Chunk 0     Chunk 1   Chunk 2     Chunk 3
```

### 2.2 Compact URL-Safe Binary Proof Wire Format
Individual chunk retrieval requests carry an authenticated `chunk_proof` token. To prevent HTTP header explosion in gateway proxies and MCP tool calls, proofs are serialized into a packed binary format before Base64-URL encoding:

```
+---------------+---------------+--------------------+--------------------+
| Magic (1 byte)| Depth (1 byte)| Direction Bitmask  | Sibling Hashes     |
| 0x4D ('M')    | K (1..32)     | 4 bytes (uint32_le)| K * 32 bytes       |
+---------------+---------------+--------------------+--------------------+
```
* **Bitmask Interpretation:** Bit $i$ indicates whether the sibling at level $i$ is to the left (`0`) or right (`1`) of the hash path.
* **Overhead Comparison:** For a 4,096-chunk document (depth 12):
  * Flat Array: $4096 \times 32\text{ bytes} \approx 131\text{ KB}$
  * MCT Wire Proof: $1 + 1 + 4 + (12 \times 32) = 390\text{ bytes}$ ($\mathbf{99.7\%}$ payload reduction).

### 2.3 Verification Algorithm (Hot-Path Invariant)
The Prevalidator evaluates inclusion proofs entirely in-memory with zero disk or database access:

```python
def verify_chunk_proof(leaf_hash: bytes, proof: ChunkProof, root: bytes) -> bool:
    curr = sha256(b"\x00" + leaf_hash)
    for sibling, is_right in proof.path:
        if is_right:
            curr = sha256(b"\x01" + curr + sibling)
        else:
            curr = sha256(b"\x01" + sibling + curr)
    return hmac.compare_digest(curr, root)
```
* **Computational Cost:** Exactly $\mathcal{O}(\log_2 N)$ SHA-256 operations.
* **Latency Profile:** For depth 12 (4,096 chunks), verification completes in $\approx 2.4\ \mu\text{s}$, using less than $0.05\%$ of the Prevalidator's $5.0\text{ ms}$ evaluation budget.

---

## 3. Storage & Cache Sizing Impact

| Metric | Flat Chunk Array (Previous) | Merkle Chunk Tree (RFC-009) | Improvement |
| :--- | :--- | :--- | :--- |
| **Max Document Chunks** | 256 chunks (~25 pages) | **Unlimited** ($2^{32}$ chunks) | $\infty$ scale |
| **Attestation Size** | 18.5 KB (256 hex hashes) | **32 bytes** (Merkle Root) | **99.8% reduction** |
| **L1 Cache per 100k Docs** | 1.85 GB | **3.2 MB** | **578x density** |
| **WORM Ledger Daily Delta**| 46.2 GB / million docs | **80 MB** / million docs | **98.2% reduction** |
| **Verification Complexity**| $\mathcal{O}(N)$ linear scan | $\mathcal{O}(\log N)$ tree fold | Constant low $\mu\text{s}$ |

---

## 4. Multi-Chunk Batch Proofs (Octopus Algorithm)

When an agent retrieves multiple adjacent or non-adjacent chunks from the same parent document (e.g. 10 context snippets), transmitting individual proofs redundantly duplicates shared ancestor hashes.

RFC-009 specifies multi-proof generation using the **Octopus algorithm**:
1. Common branch nodes are merged across target indices.
2. The minimal spanning tree of sibling digests is packed into a single batch proof payload.
3. For $k$ retrieved chunks across a tree of size $N$, proof size scales as $\mathcal{O}(k \log(N / k))$ instead of $k \cdot \log(N)$.

---

## 5. Security & Threat Modeling

1. **Second Preimage Resistance**: RFC 6962 prefixes (`0x00`, `0x01`) strictly prevent an attacker from presenting an interior node hash as a synthetic chunk leaf or vice-versa.
2. **Length-Extension Resistance**: SHA-256 input prefixes isolate domain states, preventing cryptographic padding exploitation.
3. **Constant-Time Verification**: Root comparison uses `hmac.compare_digest` to prevent timing-attack side channels.
4. **Post-Quantum Analysis**: SHA-256 Merkle trees provide 128-bit collision resistance and 256-bit preimage resistance against Grover's quantum search algorithm, requiring no asymmetric quantum-vulnerable cryptography.

---

## 6. Migration & Backward Compatibility

* Existing attestations lacking `docket.chunk_tree` metadata continue to verify via whole-document SHA-256 digests and fallback flat chunk arrays (`att_chunks`).
* The Prevalidator's cryptographic verification engine supports dual-mode evaluation:
  1. If `chunk_proof` header or query param is present, verify against `chunk_tree.tree_root`.
  2. Else if `att_chunks` is present, check set membership.
  3. Else verify against parent document SHA-256.

---

## 7. Empirical Performance & Compression Benchmarks

Automated benchmarks are provided via `benchmarks/benchmark_chunk_trees.py` (and tracked in [`reports/MCT_OCTOPUS_BENCHMARK.md`](../reports/MCT_OCTOPUS_BENCHMARK.md)):

### 1. Ingestion & Tree Construction Throughput
- **64 chunks** (Depth 6): `0.22 ms` (~288,000 chunks/s)
- **1,024 chunks** (Depth 10): `3.62 ms` (~283,000 chunks/s)
- **16,384 chunks** (Depth 14): `58.27 ms` (~281,000 chunks/s)

### 2. Hot-Path Single-Chunk Verification Latency (4,096-Chunk Tree)
- **Wire Proof Size**: `391 bytes` binary (522 Base64URL characters).
- **p50 Latency**: `20.0 µs` (in-memory traversal, zero database calls).
- **p95 Latency**: `38.7 µs`.
- **p99 Latency**: `94.5 µs` (well within the $\le 5.0\text{ ms}$ Prevalidator SLA budget).

### 3. Octopus Multi-Chunk Batch Proof Compression (1,024-Chunk Tree)
- **2 Contiguous Chunks**: $20 \rightarrow 9$ siblings (**55.0% payload savings**).
- **4 Clustered Chunks**: $40 \rightarrow 9$ siblings (**77.5% payload savings**).
- **8 Clustered Chunks**: $80 \rightarrow 8$ siblings (**90.0% payload savings**).
- **16 Dispersed Chunks**: $160 \rightarrow 56$ siblings (**65.0% payload savings**).
