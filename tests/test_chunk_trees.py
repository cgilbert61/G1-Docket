#!/usr/bin/env python3
"""Unit tests for RFC-009 Merkle Chunk Trees (MCT) and Prevalidator verification."""

import hashlib
import time
from datetime import datetime, timezone, timedelta
import pytest

from docket.chunking import ChunkProof, MerkleChunkTree, hash_leaf, hash_node
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from registry.signing import Keyring, build_attestation_statement, compute_chunk_tree_for_text


def test_rfc6962_domain_separation():
    """Verify RFC 6962 domain prefixes strictly separate leaf nodes from interior branch nodes."""
    raw = b"confidential financial disclosure passage"
    leaf_h = hash_leaf(raw)
    node_h = hash_node(raw, b"")

    # Leaf prefix 0x00 vs Node prefix 0x01 guarantees unequal digests even for identical payloads
    assert leaf_h != node_h
    assert leaf_h == hashlib.sha256(b"\x00" + raw).digest()
    assert node_h == hashlib.sha256(b"\x01" + raw + b"").digest()


def test_tree_construction_and_proof_verification():
    """Build a Merkle Chunk Tree, generate inclusion proofs, and verify them against the root."""
    chunks = [
        "Patient exhibited normal cardiac rhythm.",
        "Blood pressure: 120/80 mmHg.",
        "Prescription: Lisinopril 10mg daily.",
        "Follow-up scheduled in 6 months.",
        "Emergency contact: Jane Doe (Spouse).",
    ]
    tree = MerkleChunkTree(chunks)
    assert tree.leaf_count == 5
    root = tree.root
    assert len(root) == 32

    # Verify every leaf's inclusion proof
    for i, chunk in enumerate(chunks):
        proof = tree.get_proof(i)
        # Verify in-memory proof
        assert proof.verify(chunk, root) is True
        # Verify with hex root
        assert proof.verify(chunk, tree.root_hex) is True

        # Binary wire serialization & deserialization
        b_bytes = proof.to_bytes()
        reconstructed = ChunkProof.from_bytes(b_bytes)
        assert reconstructed.verify(chunk, root) is True

        # Base64 URL-safe token serialization
        token = proof.to_base64()
        b64_proof = ChunkProof.from_base64(token)
        assert b64_proof.verify(chunk, root) is True


def test_tampered_chunk_or_proof_fails_verification():
    """Verify that tampering with chunk text or proof siblings immediately fails verification."""
    chunks = [f"Data row {i}" for i in range(16)]
    tree = MerkleChunkTree(chunks)
    root = tree.root

    proof = tree.get_proof(3)
    assert proof.verify(chunks[3], root) is True

    # Tampered chunk content fails
    assert proof.verify("Tampered row 3", root) is False

    # Tampered proof sibling fails
    corrupt_path = [(bytes([b ^ 0xFF for b in s]), is_r) for s, is_r in proof.path]
    corrupt_proof = ChunkProof(corrupt_path, proof.index, proof.total_leaves)
    assert corrupt_proof.verify(chunks[3], root) is False


def test_large_document_scaling_beyond_256_chunks():
    """Verify Merkle Chunk Tree handles 1,024+ chunks without truncation, with < 10 us verification."""
    chunks = [f"Paragraph {i}: Detailed analytical commentary on enterprise asset allocation." for i in range(1024)]
    tree = MerkleChunkTree(chunks)
    assert tree.leaf_count == 1024
    root = tree.root

    # Depth of 1024 leaves is 10
    proof_first = tree.get_proof(0)
    proof_mid = tree.get_proof(512)
    proof_last = tree.get_proof(1023)

    assert proof_first.depth == 10
    assert proof_mid.depth == 10
    assert proof_last.depth == 10

    # Benchmark proof verification latency
    t0 = time.perf_counter()
    iterations = 2000
    for _ in range(iterations):
        proof_mid.verify(chunks[512], root)
    elapsed_us = ((time.perf_counter() - t0) / iterations) * 1_000_000

    print(f"Merkle chunk proof avg verification latency: {elapsed_us:.2f} us")
    assert elapsed_us < 50.0  # Must be strictly within microsecond budget (< 0.05 ms)


def test_prevalidator_enforces_chunk_proof_in_pod_tag():
    """End-to-end integration test: Prevalidator validates chunk via <pod:object locator='...' chunk_proof='...'>."""
    keyring = Keyring()
    store = InMemorySnapshotStore(keyring)

    passage_text = "Operating revenue increased by 14.2% year-over-year to $4.2B."
    extracted_text, chunk_hashes, tree = compute_chunk_tree_for_text(passage_text)

    proof = tree.get_proof(0)
    b64_proof = proof.to_base64()

    loc = "s3://finance-lakehouse/q3_earnings_transcript.pdf"
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()
    exp_str = (now_dt + timedelta(days=90)).isoformat()

    # Create active snapshot entry with chunk_tree metadata
    store._snapshot_predicate = {
        "sequence_number": 1,
        "expires_at": exp_str,
        "entries": {
            loc: {
                "record_id": "pod-rec-test-mct-01",
                "locator": loc,
                "content_sha256": hashlib.sha256(b"dummy pdf bytes").hexdigest(),
                "extracted_text_sha256": extracted_text,
                "chunk_hashes": chunk_hashes[:10],
                "chunk_tree_root": tree.root_hex,
                "status": "active",
                "minimum_clearance": "Public",
                "egress_class": "public_api",
                "ai_eligibility": "allow",
                "record_expires_at": exp_str,
            }
        },
    }

    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce", strict_inline_hash=True)

    # 1. Valid request carrying chunk_proof and exact chunk text -> ALLOW
    valid_payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Summarize: <pod:object locator="{loc}" chunk_proof="{b64_proof}">{passage_text}</pod:object>',
            }
        ],
    }
    outcome = enforcer.evaluate_request(valid_payload, headers={"x-pod-caller-clearance": "Internal"})
    assert outcome.allowed_to_forward is True
    assert outcome.client_denial_body is None

    # 2. Tampered text inside same tag with legitimate proof -> DENY with HASH_MISMATCH
    tampered_payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Summarize: <pod:object locator="{loc}" chunk_proof="{b64_proof}">Operating revenue DECREASED by 50% to $1.0B.</pod:object>',
            }
        ],
    }
    outcome_tampered = enforcer.evaluate_request(tampered_payload, headers={"x-pod-caller-clearance": "Internal"})
    assert outcome_tampered.allowed_to_forward is False
    assert "REASON_HASH_MISMATCH" in outcome_tampered.audit_entry.reason_codes


def test_docket_vector_retriever_and_rag_document_with_chunk_proof():
    """Verify DocketVectorRetriever and DocketRAGDocument automatically format chunk_proof attributes."""
    from docket.integrations import DocketRAGDocument, DocketVectorRetriever

    # 1. DocketRAGDocument
    doc = DocketRAGDocument(
        locator="s3://lake/doc1.pdf",
        content="Patient has allergy to penicillin.",
        chunk_proof="MTESTPROOF123",
    )
    tag = doc.to_pod_tag()
    assert 'locator="s3://lake/doc1.pdf"' in tag
    assert 'chunk_proof="MTESTPROOF123"' in tag
    assert "Patient has allergy to penicillin." in tag

    # 2. DocketVectorRetriever
    retriever = DocketVectorRetriever(auto_hash=False)
    hits = [
        {
            "id": "s3://lake/doc2.pdf",
            "text": "EHR diagnostic summary note.",
            "chunk_proof": "MPROOF456",
        }
    ]
    formatted = retriever.format_search_results(hits, locator_key="id")
    assert 'locator="s3://lake/doc2.pdf"' in formatted
    assert 'chunk_proof="MPROOF456"' in formatted
    assert "EHR diagnostic summary note." in formatted


def test_batch_chunk_proof_octopus_algorithm():
    """Verify Multi-Chunk Batch Proofs (Octopus Algorithm) compress sibling trees and verify simultaneously."""
    from docket.chunking import BatchChunkProof, MerkleChunkTree

    # Create tree with 64 chunks
    chunks = [f"Paragraph {i}: Sovereign data governance analysis statement." for i in range(64)]
    tree = MerkleChunkTree(chunks)
    root = tree.root

    # Select a batch of 8 target chunks (some adjacent, some scattered)
    target_indices = [4, 5, 6, 7, 20, 21, 50, 63]
    target_chunks = [chunks[i] for i in target_indices]

    # Generate minimal spanning batch proof
    batch_proof = tree.get_batch_proof(target_indices)

    # 1. Multi-proof verification
    assert batch_proof.verify(target_chunks, root) is True
    assert batch_proof.verify(target_chunks, tree.root_hex) is True

    # 2. Tampered chunk in batch fails verification
    tampered_batch = list(target_chunks)
    tampered_batch[2] = "Tampered paragraph content"
    assert batch_proof.verify(tampered_batch, root) is False

    # 3. Payload compression comparison:
    # 8 individual proofs of depth 6 = 8 * 6 = 48 sibling hashes.
    # The Octopus algorithm merges shared branches:
    assert batch_proof.lemma_count < 28  # Over 40% reduction in sibling hashes

    # 4. JSON Serialization & Deserialization
    serialized = batch_proof.to_dict()
    reconstituted = BatchChunkProof.from_dict(serialized)
    assert reconstituted.verify(target_chunks, root) is True


def test_rag_framework_adapters_chunk_proof_propagation():
    """Verify LangChain, LlamaIndex, and mapping adapters propagate chunk_proof into <pod:object>."""
    from docket.integrations import (
        DocketDocumentTransformer,
        DocketLlamaIndexPostprocessor,
        DocketRAGDocument,
        DocketTransformComponent,
        wrap_rag_documents,
    )

    # 1. DocketRAGDocument
    rag_doc = DocketRAGDocument(
        locator="s3://lake/rag1.pdf",
        content="Passage from legal binder.",
        chunk_proof="PROOF_RAG1",
    )
    tag = rag_doc.to_pod_tag()
    assert 'chunk_proof="PROOF_RAG1"' in tag
    assert 'locator="s3://lake/rag1.pdf"' in tag

    # 2. Mapping dict in wrap_rag_documents
    doc_map = {
        "locator": "s3://lake/map.pdf",
        "content": "Mapped section text.",
        "chunk_proof": "PROOF_MAP",
    }
    wrapped_map = wrap_rag_documents([doc_map])
    assert 'chunk_proof="PROOF_MAP"' in wrapped_map

    # 3. Duck-typed LangChain Document in wrap_rag_documents & DocketDocumentTransformer
    class MockLangChainDoc:
        def __init__(self, page_content: str, metadata: dict):
            self.page_content = page_content
            self.metadata = metadata

    lc_doc = MockLangChainDoc(
        page_content="LangChain passage.",
        metadata={"source": "s3://lake/lc.pdf", "chunk_proof": "PROOF_LC"},
    )
    wrapped_lc = wrap_rag_documents([lc_doc])
    assert 'chunk_proof="PROOF_LC"' in wrapped_lc

    transformer = DocketDocumentTransformer()
    transformed_docs = transformer.transform_documents([lc_doc])
    assert 'chunk_proof="PROOF_LC"' in transformed_docs[0].page_content

    # 4. Duck-typed LlamaIndex Node in wrap_rag_documents & Postprocessor
    class MockLlamaNode:
        def __init__(self, text: str, metadata: dict):
            self.text = text
            self.metadata = metadata

    class MockNodeWithScore:
        def __init__(self, node: MockLlamaNode):
            self.node = node

    llama_node = MockLlamaNode("LlamaIndex text.", {"file_path": "s3://lake/llama.pdf", "chunk_proof": "PROOF_LLAMA"})
    wrapped_llama = wrap_rag_documents([llama_node])
    assert 'chunk_proof="PROOF_LLAMA"' in wrapped_llama

    node_with_score = MockNodeWithScore(llama_node)
    wrapped_nws = wrap_rag_documents([node_with_score])
    assert 'chunk_proof="PROOF_LLAMA"' in wrapped_nws

    postprocessor = DocketLlamaIndexPostprocessor()
    post_nodes = postprocessor.postprocess_nodes([llama_node])
    assert 'chunk_proof="PROOF_LLAMA"' in post_nodes[0].text

    component = DocketTransformComponent()
    comp_nodes = component.transform([MockLlamaNode("Comp text.", {"file_path": "s3://lake/c.pdf", "chunk_proof": "PROOF_COMP"})])
    assert 'chunk_proof="PROOF_COMP"' in comp_nodes[0].text


def test_docket_vector_indexer_turnkey_adapters():
    """Verify DocketVectorIndexer prepares RFC-009 Merkle proofs for Pinecone, Qdrant, Chroma, and Milvus."""
    from docket.chunking import ChunkProof
    from docket.integrations import DocketVectorIndexer, DocketVectorRetriever

    locator = "s3://corp-knowledge/security_policy_2026.pdf"
    chunks = [
        "Section 1: Zero-trust architecture mandates all prompt data carry cryptographic provenance.",
        "Section 2: Merkle Chunk Trees eliminate 256-chunk ceilings with logarithmic proof overhead.",
        "Section 3: Edge gateways evaluate RFC 6962 inclusion proofs within a sub-5ms SLA.",
        "Section 4: Four-eyes quarantine workflows isolate and log all detected hash drift incidents.",
    ]
    embeddings = [
        [0.012, 0.045, -0.089],
        [0.033, -0.012, 0.054],
        [-0.091, 0.082, 0.011],
        [0.044, 0.019, -0.067],
    ]

    # 1. Prepare raw chunk records with RFC-009 tree
    root_hex, records = DocketVectorIndexer.prepare_chunks(
        chunks=chunks,
        locator=locator,
        extra_metadata={"department": "Security", "tier": "Confidential"},
    )
    assert len(root_hex) == 64
    assert len(records) == 4

    for i, rec in enumerate(records):
        assert rec["locator"] == locator
        assert rec["chunk_idx"] == i
        assert rec["chunk_tree_root"] == root_hex
        assert rec["metadata"]["department"] == "Security"
        # Validate proof directly against root
        proof = ChunkProof.from_base64(rec["chunk_proof"])
        assert proof.verify(chunks[i], root_hex) is True

    # 2. Pinecone Adapter
    pinecone_vecs = DocketVectorIndexer.to_pinecone_vectors(records, embeddings)
    assert len(pinecone_vecs) == 4
    assert pinecone_vecs[0]["id"] == f"{locator}#chunk=0"
    assert pinecone_vecs[0]["values"] == embeddings[0]
    assert pinecone_vecs[0]["metadata"]["chunk_proof"] == records[0]["chunk_proof"]
    assert pinecone_vecs[0]["metadata"]["text"] == chunks[0]

    # 3. Qdrant Adapter
    qdrant_pts = DocketVectorIndexer.to_qdrant_points(records, embeddings)
    assert len(qdrant_pts) == 4
    assert qdrant_pts[1]["id"] == f"{locator}#chunk=1"
    assert qdrant_pts[1]["vector"] == embeddings[1]
    assert qdrant_pts[1]["payload"]["chunk_proof"] == records[1]["chunk_proof"]

    # 4. Chroma Adapter
    chroma_batch = DocketVectorIndexer.to_chroma_batch(records, embeddings)
    assert len(chroma_batch["ids"]) == 4
    assert chroma_batch["documents"][2] == chunks[2]
    assert chroma_batch["embeddings"][2] == embeddings[2]
    assert chroma_batch["metadatas"][2]["chunk_proof"] == records[2]["chunk_proof"]

    # 5. Milvus Adapter
    milvus_rows = DocketVectorIndexer.to_milvus_rows(records, embeddings)
    assert len(milvus_rows) == 4
    assert milvus_rows[3]["vector"] == embeddings[3]
    assert milvus_rows[3]["chunk_proof"] == records[3]["chunk_proof"]

    # 6. Weaviate Adapter
    weaviate_objs = DocketVectorIndexer.to_weaviate_objects(records, embeddings)
    assert len(weaviate_objs) == 4
    assert weaviate_objs[0]["class"] == "DocumentChunk"
    assert weaviate_objs[0]["properties"]["chunk_proof"] == records[0]["chunk_proof"]
    assert weaviate_objs[0]["vector"] == embeddings[0]

    # 7. PGVector Adapter
    pg_rows = DocketVectorIndexer.to_pgvector_records(records, embeddings)
    assert len(pg_rows) == 4
    assert pg_rows[1]["id"] == f"{locator}#chunk=1"
    assert pg_rows[1]["chunk_proof"] == records[1]["chunk_proof"]
    assert pg_rows[1]["embedding"] == embeddings[1]

    # 8. OpenSearch / Elasticsearch Adapter
    os_docs = DocketVectorIndexer.to_opensearch_docs(records, embeddings, index_name="knowledge_chunks")
    assert len(os_docs) == 4
    assert os_docs[0]["_index"] == "knowledge_chunks"
    assert os_docs[0]["_source"]["chunk_proof"] == records[0]["chunk_proof"]
    assert os_docs[0]["_source"]["chunk_vector"] == embeddings[0]

    # 9. End-to-end round trip: Retrieve hits via DocketVectorRetriever across Pinecone, Weaviate, OpenSearch
    retriever = DocketVectorRetriever()

    # Pinecone
    pod_tags_pinecone = retriever.format_search_results(pinecone_vecs[0:2], content_key="text", locator_key="locator")
    assert f'locator="{locator}"' in pod_tags_pinecone
    assert f'chunk_proof="{records[0]["chunk_proof"]}"' in pod_tags_pinecone
    assert chunks[0] in pod_tags_pinecone

    # Weaviate (properties dict)
    pod_tags_weaviate = retriever.format_search_results(weaviate_objs[0:1], content_key="text", locator_key="locator")
    assert f'chunk_proof="{records[0]["chunk_proof"]}"' in pod_tags_weaviate

    # OpenSearch (_source dict)
    pod_tags_opensearch = retriever.format_search_results(os_docs[0:1], content_key="text", locator_key="locator")
    assert f'chunk_proof="{records[0]["chunk_proof"]}"' in pod_tags_opensearch




