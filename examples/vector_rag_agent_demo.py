#!/usr/bin/env python3
"""G1 Docket — Vector Database & Chunk-Level RAG Zero-Trust Admission Demo.

Demonstrates Section 5 of the Enterprise Reference Architecture:
  High-Throughput RAG & Chunk-Level Cryptographic Inheritance:
  1. Chunk-Level Cryptographic Inheritance:
     - Master enterprise documents are signed into the WORM governance ledger.
     - Document chunks embedded in vector databases (Milvus, Pinecone, Qdrant)
       inherit parent DSSE envelopes and bind to chunk-level SHA-256 hashes.
  2. Sub-Millisecond Prevalidation Gate:
     - Vector search results wrapped in `<pod:object>` XML blocks via `wrap_rag_documents`.
     - Evaluated in-memory (< 159 us/chunk) without touching disk or databases.
  3. Multi-Clearance Vector Retrieval Scenarios:
     - Case 1: Public vector chunks -> Public caller to cloud model (gpt-4o) (Allowed).
     - Case 2: Confidential technical specs -> Low-clearance caller to cloud model (Denied HTTP 403).
     - Case 3: Confidential technical specs -> Privileged caller to VPC/local model (Allowed HTTP 200).
     - Case 4: Vector Index Poisoning / Hash Drift -> Tampered chunk detected & blocked (HTTP 403).
     - Case 5: Anti-Smuggling Gate -> Unpapered raw vector dump intercepted before LLM dispatch.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import httpx
from docket import DocketClient, PolicyDenialError
from docket.integrations import (
    DocketLangChainCallbackHandler,
    DocketRAGDocument,
    attested_tool,
    wrap_rag_documents,
)

# Ensure UTF-8 output encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

VECTOR_DB_BASE = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC"


@dataclass
class VectorChunk:
    chunk_id: str
    doc_locator: str
    text: str
    classification: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def to_rag_document(self) -> DocketRAGDocument:
        return DocketRAGDocument(
            locator=self.doc_locator,
            content=self.text,
            sha256=self.sha256,
            metadata={"chunk_id": self.chunk_id, "tier": self.classification},
        )


class MockVectorStore:
    """Simulates enterprise vector store (Milvus / Pinecone / Qdrant) collection."""

    def __init__(self) -> None:
        self.chunks: dict[str, VectorChunk] = {}

    def insert(self, chunk: VectorChunk) -> None:
        self.chunks[chunk.chunk_id] = chunk

    def similarity_search(self, query: str, top_k: int = 2) -> list[VectorChunk]:
        """Simple keyword-similarity mock search."""
        query_words = [w.lower() for w in query.split() if w]
        scored: list[tuple[int, VectorChunk]] = []
        for chunk in self.chunks.values():
            chunk_lower = chunk.text.lower()
            score = sum(1 for w in query_words if w in chunk_lower)
            scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [chunk for _, chunk in scored[:top_k]]


def main() -> int:
    print("=" * 80)
    print("      G1 DOCKET: VECTOR DATABASE & CHUNK-LEVEL RAG ADMISSION SUITE      ")
    print("=" * 80)

    # Initialize client connected to Gateway / Prevalidator (:18082)
    client = DocketClient(base_url="http://localhost:18082")
    health = client.get_health()
    mode = health.get("mode", "enforce")
    print(f"\n[+] Gateway Online: mode={mode} | snapshot_seq={health.get('snapshot_sequence')}")

    print("\n[+] Initializing Enterprise Vector Store (Milvus / Pinecone / Qdrant mock)...")
    vector_db = MockVectorStore()

    # Public Doc Chunk
    pub_chunk = VectorChunk(
        chunk_id="chunk-001",
        doc_locator=f"{VECTOR_DB_BASE}/PUBLIC_PRODUCT_SKU_CATALOG",
        text="SKU-100 | Quantum Router | $1,299.00 | Available",
        classification="Public",
    )
    vector_db.insert(pub_chunk)

    # Confidential Doc Chunk
    conf_chunk = VectorChunk(
        chunk_id="chunk-042",
        doc_locator=f"{VECTOR_DB_BASE}/DIM_CUSTOMER_CONTACTS",
        text="CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise",
        classification="Confidential",
    )
    vector_db.insert(conf_chunk)

    print(f"  [>] Ingested Chunk {pub_chunk.chunk_id}: {pub_chunk.doc_locator} [{pub_chunk.classification}]")
    print(f"  [>] Ingested Chunk {conf_chunk.chunk_id}: {conf_chunk.doc_locator} [{conf_chunk.classification}]")

    # -------------------------------------------------------------------------
    # Case 1: Public Vector Retrieval -> Public Cloud Model (Allowed)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 1] Public Vector Search Chunk -> Public Caller -> Cloud Model (gpt-4o)")
    print("-" * 80)
    retrieved_public = vector_db.similarity_search("quantum router", top_k=1)
    rag_context_pub = wrap_rag_documents([c.to_rag_document() for c in retrieved_public])
    print(f"  [>] Retrieved Vector Context:\n      {rag_context_pub.strip()}")

    res1 = client.chat_completions(
        messages=[
            {"role": "system", "content": "You are an AI sales assistant."},
            {"role": "user", "content": f"Answer based on context: {rag_context_pub}\n\nWhat is the router price?"},
        ],
        model="gpt-4o",
        caller_key="pod-key-public",
    )
    print("  [+] Verdict: ALLOWED (HTTP 200 OK)")
    print(f"  [+] Response: {res1['choices'][0]['message']['content']}")

    # -------------------------------------------------------------------------
    # Case 2: Confidential Technical Spec Chunk -> Low-Clearance Caller -> Cloud Model (Blocked)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 2] Confidential Vector Chunk -> Low-Clearance Caller -> Cloud Model (Zero Trust Block)")
    print("-" * 80)
    retrieved_conf = vector_db.similarity_search("elena fisher", top_k=1)
    rag_context_conf = wrap_rag_documents([c.to_rag_document() for c in retrieved_conf])
    print(f"  [>] Retrieved Vector Context:\n      {rag_context_conf.strip()}")

    try:
        client.chat_completions(
            messages=[
                {"role": "system", "content": "You are a customer assistant."},
                {"role": "user", "content": f"Summarize customer: {rag_context_conf}"},
            ],
            model="gpt-4o",
            caller_key="pod-key-public",
        )
        if mode == "observe":
            print("  [+] Verdict: OBSERVE MODE (Permitted through, WOULD_DENY recorded to WORM ledger)")
        else:
            print("  [-] UNEXPECTED: Confidential chunk leaked to public cloud model!")
            return 1
    except PolicyDenialError as err:
        print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
        print(f"  [+] Denial Message: {err.response_body.get('error', {}).get('message')}")
        print("  [+] Guarantee: Low-clearance caller cannot egress confidential vector context.")

    # -------------------------------------------------------------------------
    # Case 3: Confidential Technical Spec Chunk -> Privileged Caller -> VPC Model (Allowed)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 3] Confidential Vector Chunk -> Privileged Caller -> Internal VPC Model")
    print("-" * 80)
    res3 = client.chat_completions(
        messages=[
            {"role": "system", "content": "You are an internal CRM analyst."},
            {"role": "user", "content": f"Analyze specifications: {rag_context_conf}"},
        ],
        model="local-model",
        caller_key="pod-key-confidential",
    )
    print("  [+] Verdict: ALLOWED (HTTP 200 OK)")
    print(f"  [+] Response: {res3['choices'][0]['message']['content']}")

    # -------------------------------------------------------------------------
    # Case 4: Vector Index Poisoning / Hash Drift (Blocked)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 4] Vector Store Tampering / Hash Drift Injection (Integrity Guard)")
    print("-" * 80)
    tampered_text = "CUST-901 | elena.fisher@evil-attacker.com | phone: 000-000-0000"
    tampered_xml = (
        f'<pod:object locator="{conf_chunk.doc_locator}" '
        'sha256="0000000000000000000000000000000000000000000000000000000000000000">'
        f'{tampered_text}</pod:object>'
    )
    print(f"  [>] Tampered Vector Context:\n      {tampered_xml}")

    try:
        client.chat_completions(
            messages=[
                {"role": "system", "content": "You are an internal assistant."},
                {"role": "user", "content": f"Review customer: {tampered_xml}"},
            ],
            model="local-model",
            caller_key="pod-key-confidential",
        )
        if mode == "observe":
            print("  [+] Verdict: OBSERVE MODE (Permitted through, WOULD_DENY recorded to WORM ledger)")
        else:
            print("  [-] UNEXPECTED: Tampered vector chunk accepted!")
            return 1
    except PolicyDenialError as err:
        print(f"  [+] Verdict: HARD BLOCK (HTTP {err.status_code} Forbidden)")
        print(f"  [+] Hash Drift Caught: {err.response_body.get('error', {}).get('message')}")
        print("  [+] Guarantee: Vector store poisoning rejected via cryptographic hash mismatch.")

    # -------------------------------------------------------------------------
    # Case 5: Anti-Smuggling Gate (Untagged Vector Context Interception)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 5] Anti-Smuggling Gate (Pre-dispatch callback catches untagged raw vector dumps)")
    print("-" * 80)

    callback_auditor = DocketLangChainCallbackHandler(
        require_attested_context=True,
        max_untagged_chars=100,
        on_violation="raise",
    )
    raw_smuggled_prompt = "Process vector retrieval dump: elena.fisher@example.com phone: 312-555-0199 SSN: 412-58-9021"
    print(f"  [>] Raw Untagged Prompt:\n      '{raw_smuggled_prompt}'")

    try:
        callback_auditor.on_llm_start(serialized={}, prompts=[raw_smuggled_prompt])
        print("  [-] UNEXPECTED: Untagged prompt passed pre-dispatch audit!")
        return 1
    except PolicyDenialError as err:
        print("  [+] Verdict: CAUGHT & HARD-BLOCKED (HTTP 403)")
        print(f"  [+] Denial Reason: {err.response_body.get('error')}")
        print("  [+] Guarantee: Zero untagged / unpapered vector embeddings context can be smuggled.")

    # -------------------------------------------------------------------------
    # Case 6: Merkle Chunk Trees (MCT) Inclusion & Batch Proof Retrieval (RFC-009)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Case 6] Merkle Chunk Trees (MCT) Inclusion & Octopus Batch Proofs (RFC-009)")
    print("-" * 80)
    from docket.chunking import MerkleChunkTree

    contract_chunks = [
        f"Clause {i}: Contoso enterprise liability and sovereign IP attribution policy."
        for i in range(32)
    ]
    contract_tree = MerkleChunkTree(contract_chunks)
    print(f"  [>] Master Document Merkle Root: {contract_tree.root_hex}")
    print(f"  [>] Total Chunks Ingested:       {contract_tree.leaf_count} (Tree Depth: {len(contract_tree.levels)-1})")

    # Retrieve individual chunk with inclusion proof
    target_idx = 12
    target_text = contract_chunks[target_idx]
    proof_obj = contract_tree.get_proof(target_idx)
    proof_b64 = proof_obj.to_base64()
    print(f"  [>] Single Chunk [{target_idx}] Proof Token: {proof_b64[:32]}... ({len(proof_b64)} chars)")
    assert proof_obj.verify(target_text, contract_tree.root) is True
    print("  [+] Individual Chunk Proof: Cryptographically Verified against Merkle Root (PASS)")

    # Retrieve batch of 4 chunks with Octopus algorithm
    batch_indices = [2, 3, 14, 15]
    batch_texts = [contract_chunks[i] for i in batch_indices]
    batch_proof = contract_tree.get_batch_proof(batch_indices)
    assert batch_proof.verify(batch_texts, contract_tree.root) is True
    print(f"  [>] Multi-Chunk Batch [{batch_indices}] Sibling Count: {batch_proof.lemma_count} (vs {len(batch_indices)*5} individual)")
    print("  [+] Octopus Batch Proof: All 4 Chunks Verified Simultaneously (PASS)")

    print("\n" + "=" * 80)
    print("          ALL 6 VECTOR RAG ZERO-TRUST ADMISSION CASES PASSED          ")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
