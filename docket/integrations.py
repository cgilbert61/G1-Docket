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

from docket.client import DocketClient

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
