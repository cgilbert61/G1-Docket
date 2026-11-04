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
    title: str | None = None
    metadata: dict[str, Any] | None = None

    def to_pod_tag(self) -> str:
        """Convert document into canonical `<pod:object>` format."""
        return DocketClient.wrap_object(
            locator=self.locator,
            content=self.content,
            sha256=self.sha256,
        )


def wrap_agent_tool_output(
    locator: str,
    content: Any,
    sha256: str | None = None,
    auto_hash: bool = False,
) -> str:
    """Wrap output returned by an agent tool (e.g. database query, web search, doc retrieval) into `<pod:object>`.

    If `auto_hash=True` and `sha256` is omitted, computes the SHA-256 digest of the UTF-8 content.
    """
    text = str(content)
    if auto_hash and not sha256:
        sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return DocketClient.wrap_object(locator=locator, content=text, sha256=sha256)


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
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(doc.page_content), sha256=sha))
        elif hasattr(doc, "node") and hasattr(getattr(doc, "node"), "text"):
            # LlamaIndex NodeWithScore duck typing
            node = getattr(doc, "node")
            meta = getattr(node, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get("file_path") or meta.get("source") or "urn:doc:llamaindex")
            sha = meta.get("sha256")
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(node.text), sha256=sha))
        elif hasattr(doc, "text") and hasattr(doc, "metadata"):
            # LlamaIndex BaseNode duck typing
            meta = getattr(doc, "metadata", {}) or {}
            loc = str(meta.get("locator") or meta.get("file_path") or meta.get("source") or "urn:doc:llamaindex")
            sha = meta.get("sha256")
            blocks.append(DocketClient.wrap_object(locator=loc, content=str(doc.text), sha256=sha))
        elif isinstance(doc, Mapping):
            loc = str(doc.get("locator") or doc.get("source") or doc.get("uri") or "urn:doc:unknown")
            content = str(doc.get("content") or doc.get("text") or doc.get("page_content") or "")
            sha = doc.get("sha256")
            blocks.append(DocketClient.wrap_object(locator=loc, content=content, sha256=sha))
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
                if self.auto_hash and not sha:
                    sha = hashlib.sha256(str(doc.page_content).encode("utf-8")).hexdigest()
                wrapped = DocketClient.wrap_object(locator=loc, content=str(doc.page_content), sha256=sha)

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
            text = getattr(node, "text", "")
            if self.auto_hash and not sha:
                sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            wrapped = DocketClient.wrap_object(locator=loc, content=text, sha256=sha)
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
            text = getattr(node, "text", "")
            if self.auto_hash and not sha:
                sha = hashlib.sha256(str(text).encode("utf-8")).hexdigest()
            wrapped = DocketClient.wrap_object(locator=loc, content=str(text), sha256=sha)
            if hasattr(node, "text"):
                node.text = wrapped
        return nodes


# Backward-compatible alias
DocketLlamaIndexTransformComponent = DocketTransformComponent


