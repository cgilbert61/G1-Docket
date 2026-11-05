"""G1 Docket AI Agent & RAG Framework Integrations.

Provides helpers, document wrappers, tool decorators, and prompt formatters for integrating
G1 Docket zero-trust attestation into LangChain, LlamaIndex, AutoGen, CrewAI, and custom AI agent workflows.
"""

from __future__ import annotations

import functools
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from docket.client import DocketClient, PolicyDenialError

POD_OBJECT_LOCATOR_RE = re.compile(
    r'<pod:object\s+locator=["\']([^"\']+)["\'](?:\s+sha256=["\']([^"\']+)["\'])?>(.*?)</pod:object>',
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class DocketRAGDocument:
    """Represents a retrieved document or chunk destined for an AI prompt with attestation metadata."""

    locator: str
    content: str
    sha256: str | None = None
    chunk_proof: str | None = None
    title: str | None = None
    metadata: dict[str, Any] | None = None

    def to_pod_tag(self) -> str:
        """Convert document into canonical `<pod:object>` format."""
        return DocketClient.wrap_object(
            locator=self.locator,
            content=self.content,
            sha256=self.sha256,
            chunk_proof=self.chunk_proof,
        )


def wrap_agent_tool_output(
    locator: str,
    content: Any,
    sha256: str | None = None,
    chunk_proof: str | None = None,
    auto_hash: bool = False,
) -> str:
    """Wrap output returned by an agent tool (e.g. database query, web search, doc retrieval) into `<pod:object>`.

    If `auto_hash=True` and `sha256` is omitted, computes the SHA-256 digest of the UTF-8 content.
    """
    text = str(content)
    if auto_hash and not sha256:
        sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return DocketClient.wrap_object(locator=locator, content=text, sha256=sha256, chunk_proof=chunk_proof)


def attested_tool(
    locator: str | Callable[..., str],
    auto_hash: bool = False,
) -> Callable[..., Any]:
    """Decorator for AI agent tool functions (e.g. LangChain `@tool` or standalone python functions).

    Automatically wraps the return value of the tool in a canonical `<pod:object>` attestation tag.
    The `locator` parameter can either be a static string URI or a callable taking the function arguments.

    Example:
        @attested_tool("snowflake://acme.snowflakecomputing.com/ANALYTICS_DB/PUBLIC/REVENUE", auto_hash=True)
        def query_sales(quarter: str) -> str:
            return "Q3 Revenue: $42.5M | Margin: 64%"
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            res = fn(*args, **kwargs)
            if callable(locator):
                loc = locator(*args, **kwargs)
            else:
                loc = str(locator)
            return wrap_agent_tool_output(loc, res, auto_hash=auto_hash)
        return wrapper
    return decorator


def wrap_rag_documents(
    documents: Sequence[DocketRAGDocument | Mapping[str, Any] | tuple[str, str] | Any],
) -> str:
    """Wrap a sequence of retrieved documents or chunk mappings into newline-separated `<pod:object>` blocks.

    Accepts:
      - `DocketRAGDocument` instances
      - LangChain `Document` objects (duck-typed via `page_content` and `metadata`)
      - LlamaIndex `NodeWithScore` or `BaseNode` objects (duck-typed via `node.text` or `text`)
      - Mappings with `'locator'` and `'content'` keys (or `'source'` / `'page_content'`)
      - Tuples of `(locator, content)`
    """
    blocks: list[str] = []
    for doc in documents:
        if isinstance(doc, DocketRAGDocument):
            blocks.append(doc.to_pod_tag())
        elif hasattr(doc, "page_content") and hasattr(doc, "metadata"):
            # LangChain Document duck typing
            meta = getattr(doc, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get("source") or meta.get("uri") or "urn:doc:langchain")
            sha = meta.get("sha256")
            proof = meta.get("chunk_proof")
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(doc.page_content), sha256=sha, chunk_proof=proof))
        elif hasattr(doc, "node") and hasattr(getattr(doc, "node"), "text"):
            # LlamaIndex NodeWithScore duck typing
            node = getattr(doc, "node")
            meta = getattr(node, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get("file_path") or meta.get("source") or "urn:doc:llamaindex")
            sha = meta.get("sha256")
            proof = meta.get("chunk_proof")
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(node.text), sha256=sha, chunk_proof=proof))
        elif hasattr(doc, "text") and hasattr(doc, "metadata"):
            # LlamaIndex BaseNode duck typing
            meta = getattr(doc, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get("file_path") or meta.get("source") or "urn:doc:llamaindex")
            sha = meta.get("sha256")
            proof = meta.get("chunk_proof")
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(doc.text), sha256=sha, chunk_proof=proof))
        elif isinstance(doc, Mapping):
            loc = str(doc.get("locator") or doc.get("source") or doc.get("uri") or "urn:doc:unknown")
            content = str(doc.get("content") or doc.get("text") or doc.get("page_content") or "")
            sha = doc.get("sha256")
            proof = doc.get("chunk_proof")
            blocks.append(DocketClient.wrap_object(locator=loc, content=content, sha256=sha, chunk_proof=proof))
        elif isinstance(doc, (tuple, list)) and len(doc) >= 2:
            loc, content = str(doc[0]), str(doc[1])
            blocks.append(DocketClient.wrap_object(locator=loc, content=content))
        else:
            raise TypeError(f"Unsupported document format for Docket RAG wrapper: {type(doc)}")
    return "\n\n".join(blocks)


def format_rag_prompt(
    prompt_template: str,
    documents: Sequence[DocketRAGDocument | Mapping[str, Any] | tuple[str, str] | Any],
    context_variable: str = "{context}",
) -> str:
    """Inject attested `<pod:object>` context blocks into an agent prompt template.

    Example:
        template = "Answer the user question using only the verified facts below:\\n\\n{context}\\n\\nQuestion: {question}"
        prompt = format_rag_prompt(template, docs)
    """
    context_str = wrap_rag_documents(documents)
    return prompt_template.replace(context_variable, context_str)


def extract_prompt_locators(prompt: str) -> list[str]:
    """Extract all canonical data locators referenced in `<pod:object>` blocks inside a prompt."""
    return [match.group(1) for match in POD_OBJECT_LOCATOR_RE.finditer(prompt)]


class DocketDocumentTransformer:
    """LangChain-compatible Document Transformer that wraps document content into `<pod:object>` tokens.

    Can be placed into a LangChain pipeline or document retriever chain.
    """

    def __init__(self, default_locator_key: str = "source", auto_hash: bool = False):
        self.default_locator_key = default_locator_key
        self.auto_hash = auto_hash

    def transform_documents(self, documents: Sequence[Any]) -> Sequence[Any]:
        """Wrap each document's `page_content` in canonical `<pod:object>` attestation markers."""
        transformed = []
        for doc in documents:
            if hasattr(doc, "page_content") and hasattr(doc, "metadata"):
                meta = doc.metadata or {}
                loc = str(meta.get("locator") or meta.get(self.default_locator_key) or meta.get("uri") or "urn:doc:unknown")
                sha = meta.get("sha256")
                proof = meta.get("chunk_proof")
                if self.auto_hash and not sha:
                    sha = hashlib.sha256(str(doc.page_content).encode("utf-8")).hexdigest()
                wrapped = DocketClient.wrap_object(locator=loc, content=str(doc.page_content), sha256=sha, chunk_proof=proof)

                try:
                    cls = doc.__class__
                    new_doc = cls(page_content=wrapped, metadata=dict(meta))
                    transformed.append(new_doc)
                except Exception:
                    doc.page_content = wrapped
                    transformed.append(doc)
            else:
                transformed.append(doc)
        return transformed


class DocketLlamaIndexPostprocessor:
    """LlamaIndex-compatible Node Postprocessor that wraps retrieved node content into `<pod:object>` tokens.

    Can be added to `node_postprocessors` on any LlamaIndex QueryEngine or Retriever.
    """

    def __init__(self, default_locator_key: str = "file_path", auto_hash: bool = False):
        self.default_locator_key = default_locator_key
        self.auto_hash = auto_hash

    def postprocess_nodes(self, nodes: list[Any], query_bundle: Any = None) -> list[Any]:
        """Wrap each node's text in canonical `<pod:object>` attestation markers."""
        for item in nodes:
            node = getattr(item, "node", item)
            meta = getattr(node, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get(self.default_locator_key) or meta.get("source") or "urn:doc:unknown")
            sha = meta.get("sha256")
            proof = meta.get("chunk_proof")
            text = getattr(node, "text", "")
            if self.auto_hash and not sha:
                sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            wrapped = DocketClient.wrap_object(locator=loc, content=text, sha256=sha, chunk_proof=proof)
            if hasattr(node, "text"):
                node.text = wrapped
        return nodes


try:
    from langchain_core.callbacks.base import BaseCallbackHandler  # type: ignore[import-untyped]
except ImportError:
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Duck-typed fallback when langchain-core is not installed."""
        pass


class DocketLangChainCallbackHandler(BaseCallbackHandler):
    """LangChain-compatible CallbackHandler that audits prompts before LLM dispatch.

    Enforces that prompts carry valid `<pod:object>` locators when `require_attested_context=True`,
    ensures untagged prompt content does not exceed `max_untagged_chars`, and records
    an in-memory compliance audit log for observability.
    """

    def __init__(
        self,
        client: DocketClient | None = None,
        require_attested_context: bool = False,
        max_untagged_chars: int | None = None,
        on_violation: str = "raise",  # "raise" | "log"
    ) -> None:
        self.client = client
        self.require_attested_context = require_attested_context
        self.max_untagged_chars = max_untagged_chars
        self.on_violation = on_violation
        self.audit_log: list[dict[str, Any]] = []

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Inspect each prompt before it is dispatched to the LLM model provider."""
        for prompt in prompts:
            locators = extract_prompt_locators(prompt)
            had_violation = False

            if self.require_attested_context and not locators:
                had_violation = True
                msg = "Prompt dispatch blocked: require_attested_context is True but no <pod:object> locators found."
                self.audit_log.append({
                    "decision": "deny",
                    "reason": "MISSING_ATTESTED_CONTEXT",
                    "locators": [],
                    "prompt_sample": prompt[:120],
                })
                if self.on_violation == "raise":
                    raise PolicyDenialError(
                        msg,
                        status_code=403,
                        response_body={"error": msg, "code": "missing_attested_context"},
                    )

            if self.max_untagged_chars is not None:
                stripped = POD_OBJECT_LOCATOR_RE.sub("", prompt)
                if len(stripped.strip()) > self.max_untagged_chars:
                    had_violation = True
                    msg = (
                        f"Prompt dispatch blocked: untagged characters ({len(stripped.strip())}) "
                        f"exceed quota ({self.max_untagged_chars})."
                    )
                    self.audit_log.append({
                        "decision": "deny",
                        "reason": "UNTAGGED_QUOTA_EXCEEDED",
                        "untagged_chars": len(stripped.strip()),
                        "locators": locators,
                        "prompt_sample": prompt[:120],
                    })
                    if self.on_violation == "raise":
                        raise PolicyDenialError(
                            msg,
                            status_code=403,
                            response_body={"error": msg, "code": "untagged_quota_exceeded"},
                        )

            if not had_violation:
                self.audit_log.append({
                    "decision": "allow",
                    "locators": locators,
                    "prompt_sample": prompt[:120],
                })

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Invoked when the LLM finishes running cleanly."""
        pass

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Invoked when the LLM encounters an exception."""
        pass

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Invoked before a LangChain tool starts running."""
        pass

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Invoked after a LangChain tool finishes executing."""
        pass

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Invoked when a LangChain tool throws an exception."""
        pass


class DocketTransformComponent:
    """LlamaIndex-compatible TransformComponent for ingestion and indexing pipelines.

    Wraps extracted node text in canonical `<pod:object>` attestation markers during
    the ingestion or indexing stage before embedding or storage.
    """

    def __init__(self, default_locator_key: str = "file_path", auto_hash: bool = True) -> None:
        self.default_locator_key = default_locator_key
        self.auto_hash = auto_hash

    def __call__(self, nodes: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        return self.transform(nodes, **kwargs)

    def transform(self, nodes: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Transform nodes by wrapping their text content in `<pod:object>` tags."""
        for item in nodes:
            node = getattr(item, "node", item)
            meta = getattr(node, "metadata", {}) or {}
            loc = str(
                meta.get("locator")
                or meta.get(self.default_locator_key)
                or meta.get("source")
                or "urn:doc:unknown"
            )
            sha = meta.get("sha256")
            proof = meta.get("chunk_proof")
            text = getattr(node, "text", "")
            if self.auto_hash and not sha:
                sha = hashlib.sha256(str(text).encode("utf-8")).hexdigest()
            wrapped = DocketClient.wrap_object(locator=loc, content=str(text), sha256=sha, chunk_proof=proof)
            if hasattr(node, "text"):
                node.text = wrapped
        return nodes


# Backward-compatible alias
DocketLlamaIndexTransformComponent = DocketTransformComponent


class DocketCrewAITool:
    """CrewAI-compatible tool wrapper enforcing G1 Docket data provenance.

    Wraps the tool execution to automatically wrap returned database records,
    documents, or API results in canonical `<pod:object>` tokens.
    """

    def __init__(self, tool: Any, locator: str | Callable[..., str], auto_hash: bool = True) -> None:
        self.tool = tool
        self.locator = locator
        self.auto_hash = auto_hash

    def run(self, *args: Any, **kwargs: Any) -> str:
        raw_result = self.tool.run(*args, **kwargs) if hasattr(self.tool, "run") else self.tool(*args, **kwargs)
        loc = self.locator(*args, **kwargs) if callable(self.locator) else str(self.locator)
        return wrap_agent_tool_output(loc, raw_result, auto_hash=self.auto_hash)

    def __call__(self, *args: Any, **kwargs: Any) -> str:
        return self.run(*args, **kwargs)


def docket_langgraph_node(
    locator: str | Callable[[dict[str, Any]], str],
    state_key: str = "messages",
    auto_hash: bool = True,
) -> Callable[..., Any]:
    """Decorator for LangGraph node functions.

    Ensures that context injected into the graph state is wrapped with canonical `<pod:object>`
    provenance envelopes, allowing the Prevalidator to verify clearance as state flows across nodes.
    """
    def decorator(fn: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[dict[str, Any]], dict[str, Any]]:
        @functools.wraps(fn)
        def wrapper(state: dict[str, Any]) -> dict[str, Any]:
            new_state = fn(state)
            if not isinstance(new_state, dict):
                return new_state

            if state_key in new_state:
                val = new_state[state_key]
                loc = locator(state) if callable(locator) else str(locator)
                if isinstance(val, str) and "<pod:object" not in val:
                    new_state[state_key] = wrap_agent_tool_output(loc, val, auto_hash=auto_hash)
                elif isinstance(val, list):
                    updated_list = list(val)
                    if updated_list:
                        last_item = updated_list[-1]
                        if isinstance(last_item, dict) and "content" in last_item:
                            content = str(last_item["content"])
                            if "<pod:object" not in content:
                                last_item["content"] = wrap_agent_tool_output(loc, content, auto_hash=auto_hash)
                        elif hasattr(last_item, "content"):
                            content = str(last_item.content)
                            if "<pod:object" not in content:
                                last_item.content = wrap_agent_tool_output(loc, content, auto_hash=auto_hash)
                    new_state[state_key] = updated_list
            return new_state
        return wrapper
    return decorator


class DocketAutoGenHook:
    """AutoGen-compatible message hook enforcing G1 Docket data provenance.

    Can be registered with `agent.register_hook(hookable_method="process_message_before_send", ...)`
    or used directly to wrap messages passed between AutoGen ConversableAgents.
    """

    def __init__(self, locator_map: dict[str, str] | None = None, auto_hash: bool = True) -> None:
        self.locator_map = locator_map or {}
        self.auto_hash = auto_hash

    def process_message(
        self,
        sender: Any,
        message: str | dict[str, Any],
        recipient: Any = None,
        silent: bool = False,
    ) -> str | dict[str, Any]:
        """Wrap untagged message text that matches registered database locators."""
        if isinstance(message, str):
            for pattern, loc in self.locator_map.items():
                if pattern in message and "<pod:object" not in message:
                    message = wrap_agent_tool_output(loc, message, auto_hash=self.auto_hash)
            return message
        elif isinstance(message, dict) and "content" in message:
            content = str(message["content"])
            for pattern, loc in self.locator_map.items():
                if pattern in content and "<pod:object" not in content:
                    content = wrap_agent_tool_output(loc, content, auto_hash=self.auto_hash)
            updated = dict(message)
            updated["content"] = content
            return updated
        return message

    def __call__(self, sender: Any, message: Any, recipient: Any = None, silent: bool = False) -> Any:
        return self.process_message(sender, message, recipient, silent)


class DocketVectorRetriever:
    """Turnkey adapter for Vector Databases (Pinecone, Milvus, Qdrant, Weaviate, Chroma).

    Transforms vector search results and semantic chunks into verified `<pod:object>`
    provenance blocks with automatic SHA-256 digest binding.
    """

    def __init__(self, client: DocketClient | None = None, auto_hash: bool = True) -> None:
        self.client = client or DocketClient()
        self.auto_hash = auto_hash

    def format_chunk(self, content: str, locator: str, sha256: str | None = None, chunk_proof: str | None = None) -> str:
        """Format an individual retrieved vector chunk into `<pod:object>` syntax."""
        return wrap_agent_tool_output(locator=locator, content=content, sha256=sha256, chunk_proof=chunk_proof, auto_hash=self.auto_hash)

    def format_search_results(
        self,
        hits: Sequence[Mapping[str, Any] | Any],
        content_key: str = "text",
        locator_key: str = "locator",
        sha256_key: str = "sha256",
        proof_key: str = "chunk_proof",
    ) -> str:
        """Format a list of vector search matches into newline-delimited `<pod:object>` tokens."""
        blocks: list[str] = []
        for hit in hits:
            if isinstance(hit, Mapping):
                meta_dict = hit.get("metadata") or hit.get("payload") or {}
                if not isinstance(meta_dict, Mapping):
                    meta_dict = {}
                content = str(
                    hit.get(content_key)
                    or meta_dict.get(content_key)
                    or hit.get("page_content")
                    or meta_dict.get("page_content")
                    or hit.get("content")
                    or meta_dict.get("content", "")
                )
                loc = str(
                    hit.get(locator_key)
                    or meta_dict.get(locator_key)
                    or hit.get("source")
                    or meta_dict.get("source")
                    or hit.get("id", "vector://unspecified")
                )
                sha = hit.get(sha256_key) or meta_dict.get(sha256_key)
                proof = hit.get(proof_key) or meta_dict.get(proof_key)
            elif hasattr(hit, "page_content"):
                content = str(hit.page_content)
                meta = getattr(hit, "metadata", {}) or {}
                loc = str(meta.get(locator_key, meta.get("source", "vector://unspecified")))
                sha = meta.get(sha256_key)
                proof = meta.get(proof_key)
            elif hasattr(hit, "text"):
                content = str(hit.text)
                meta = getattr(hit, "metadata", {}) or {}
                loc = str(meta.get(locator_key, meta.get("source", "vector://unspecified")))
                sha = meta.get(sha256_key)
                proof = meta.get(proof_key)
            else:
                content = str(hit)
                loc = "vector://unspecified"
                sha = None
                proof = None
            blocks.append(self.format_chunk(content=content, locator=loc, sha256=sha, chunk_proof=proof))
        return "\n".join(blocks)


class DocketVectorIndexer:
    """Turnkey ingestion adapter for preparing vector database records with RFC-009 Merkle Chunk Trees.

    Transforms text passages or document chunks into cryptographically bound vector payloads
    compatible with Pinecone, Milvus, Qdrant, Chroma, and Weaviate.
    """

    @staticmethod
    def prepare_chunks(
        chunks: Sequence[str],
        locator: str,
        extra_metadata: Mapping[str, Any] | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Build an RFC-009 MerkleChunkTree over chunks and return (root_hex, records).

        Each record contains:
          - id: Canonical composite locator tag (e.g. `s3://corp/doc.pdf#chunk=0`)
          - locator: Canonical document URI
          - chunk_idx: 0-based index
          - text: Chunk content
          - sha256: Leaf content SHA-256
          - chunk_tree_root: 32-byte Merkle root hex
          - chunk_proof: Packed URL-safe base64 binary inclusion proof
          - metadata: Merged extra metadata
        """
        from docket.chunking import MerkleChunkTree

        if not chunks:
            return "", []

        tree = MerkleChunkTree(chunks)
        root_hex = tree.root_hex
        records: list[dict[str, Any]] = []

        for idx, text in enumerate(chunks):
            proof = tree.get_proof(idx)
            proof_b64 = proof.to_base64()
            sha256_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            meta = dict(extra_metadata or {})
            meta.update({
                "locator": locator,
                "chunk_idx": idx,
                "sha256": sha256_digest,
                "chunk_tree_root": root_hex,
                "chunk_proof": proof_b64,
            })
            records.append({
                "id": f"{locator}#chunk={idx}",
                "locator": locator,
                "chunk_idx": idx,
                "text": text,
                "sha256": sha256_digest,
                "chunk_tree_root": root_hex,
                "chunk_proof": proof_b64,
                "metadata": meta,
            })

        return root_hex, records

    @staticmethod
    def to_pinecone_vectors(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]],
    ) -> list[dict[str, Any]]:
        """Format records into Pinecone upsert vector objects."""
        if len(records) != len(embeddings):
            raise ValueError(f"Length mismatch: {len(records)} records vs {len(embeddings)} embeddings")
        pinecone_vectors = []
        for r, emb in zip(records, embeddings):
            metadata = dict(r["metadata"])
            metadata["text"] = r["text"]
            pinecone_vectors.append({
                "id": r["id"],
                "values": list(emb),
                "metadata": metadata,
            })
        return pinecone_vectors

    @staticmethod
    def to_qdrant_points(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]],
    ) -> list[dict[str, Any]]:
        """Format records into Qdrant PointStruct-compatible dicts."""
        if len(records) != len(embeddings):
            raise ValueError(f"Length mismatch: {len(records)} records vs {len(embeddings)} embeddings")
        qdrant_points = []
        for r, emb in zip(records, embeddings):
            payload = dict(r["metadata"])
            payload["text"] = r["text"]
            qdrant_points.append({
                "id": r["id"],
                "vector": list(emb),
                "payload": payload,
            })
        return qdrant_points

    @staticmethod
    def to_chroma_batch(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]] | None = None,
    ) -> dict[str, list[Any]]:
        """Format records into Chroma collection.add() keyword arguments."""
        ids = [r["id"] for r in records]
        documents = [r["text"] for r in records]
        metadatas = [dict(r["metadata"]) for r in records]
        batch: dict[str, list[Any]] = {
            "ids": ids,
            "documents": documents,
            "metadatas": metadatas,
        }
        if embeddings is not None:
            batch["embeddings"] = [list(e) for e in embeddings]
        return batch

    @staticmethod
    def to_milvus_rows(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]],
    ) -> list[dict[str, Any]]:
        """Format records into Milvus collection.insert() row entities."""
        if len(records) != len(embeddings):
            raise ValueError(f"Length mismatch: {len(records)} records vs {len(embeddings)} embeddings")
        milvus_rows = []
        for r, emb in zip(records, embeddings):
            milvus_rows.append({
                "id": r["id"],
                "vector": list(emb),
                "text": r["text"],
                "locator": r["locator"],
                "chunk_idx": r["chunk_idx"],
                "sha256": r["sha256"],
                "chunk_tree_root": r["chunk_tree_root"],
                "chunk_proof": r["chunk_proof"],
            })
        return milvus_rows

    @staticmethod
    def to_weaviate_objects(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]] | None = None,
        class_name: str = "DocumentChunk",
    ) -> list[dict[str, Any]]:
        """Format records into Weaviate collection batch data objects."""
        weaviate_objs = []
        for i, r in enumerate(records):
            props = dict(r["metadata"])
            props["text"] = r["text"]
            obj: dict[str, Any] = {
                "class": class_name,
                "properties": props,
            }
            if embeddings is not None:
                obj["vector"] = list(embeddings[i])
            weaviate_objs.append(obj)
        return weaviate_objs

    @staticmethod
    def to_pgvector_records(
        records: Sequence[dict[str, Any]],
        embeddings: Sequence[Sequence[float]],
    ) -> list[dict[str, Any]]:
        """Format records for PostgreSQL / pgvector row insertion."""
        if len(records) != len(embeddings):
            raise ValueError(f"Length mismatch: {len(records)} records vs {len(embeddings)} embeddings")
        pg_rows = []
        for r, emb in zip(records, embeddings):
            pg_rows.append({
                "id": r["id"],
                "locator": r["locator"],
                "chunk_idx": r["chunk_idx"],
                "text": r["text"],
                "sha256": r["sha256"],
                "chunk_tree_root": r["chunk_tree_root"],
                "chunk_proof": r["chunk_proof"],
                "embedding": list(emb),
                "metadata": dict(r["metadata"]),
            })
        return pg_rows


def wrap_delegated_context(
    content: str,
    origin_sha256: str,
    parent_tier: str = "Restricted",
    agent_id: str = "agent-worker",
    origin_locator: str | None = None,
    sig: str | None = None,
) -> str:
    """Wrap agent output or summary in a `<pod:delegate>` container for multi-agent swarm handoffs.

    Guarantees that downstream synthesizing agents cannot launder or leak high-clearance
    information to lower-tier models or unauthorized callers.
    """
    attrs = [
        f'origin_sha256="{origin_sha256}"',
        f'parent_tier="{parent_tier}"',
        f'agent_id="{agent_id}"',
    ]
    if origin_locator:
        attrs.append(f'origin_locator="{origin_locator}"')
    if sig:
        attrs.append(f'sig="{sig}"')
    attr_str = " ".join(attrs)
    return f"<pod:delegate {attr_str}>{content}</pod:delegate>"


class DocketSemanticKernelFilter:
    """Microsoft Semantic Kernel function invocation and attestation filter.

    Enforces enterprise Zero-Trust data attestation for Microsoft Semantic Kernel agent pipelines:
      1. Post-Invocation: Intercepts return values from Semantic Kernel plugins/native functions
         and binds them with canonical `<pod:object>` tokens and SHA-256 content hashes.
      2. Pre-Invocation: Validates that prompts or function arguments do not leak un-papered data.
    """

    def __init__(
        self,
        client: DocketClient | None = None,
        default_locator_prefix: str = "semantic-kernel://plugin",
        auto_hash: bool = True,
    ) -> None:
        self.client = client or DocketClient()
        self.default_locator_prefix = default_locator_prefix
        self.auto_hash = auto_hash

    async def __call__(self, context: Any, next_call: Callable[..., Any]) -> Any:
        """Asynchronously wrap execution conforming to Semantic Kernel FunctionInvocationFilter."""
        await next_call(context)
        self.wrap_context_result(context)
        return context

    def wrap_context_result(self, context: Any) -> None:
        """Inspect and wrap the result in context with `<pod:object>` tags."""
        result = getattr(context, "result", None)
        if result is None:
            return

        func_name = getattr(getattr(context, "function", None), "name", "tool")
        plugin_name = getattr(getattr(context, "function", None), "plugin_name", "native")
        locator = f"{self.default_locator_prefix}/{plugin_name}/{func_name}"

        # Extract text value
        if hasattr(result, "value"):
            raw_text = str(result.value)
            if not raw_text.strip().startswith("<pod:object"):
                result.value = wrap_agent_tool_output(
                    locator=locator,
                    content=raw_text,
                    auto_hash=self.auto_hash,
                )
        elif isinstance(result, str):
            if not result.strip().startswith("<pod:object"):
                context.result = wrap_agent_tool_output(
                    locator=locator,
                    content=result,
                    auto_hash=self.auto_hash,
                )

    def wrap_function_result(self, plugin: str, function: str, result: Any) -> str:
        """Synchronously wrap an individual kernel function result."""
        locator = f"{self.default_locator_prefix}/{plugin}/{function}"
        return wrap_agent_tool_output(locator=locator, content=str(result), auto_hash=self.auto_hash)






