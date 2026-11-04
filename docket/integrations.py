"""G1 Docket AI Agent & RAG Framework Integrations.

Provides helpers, document wrappers, and prompt formatters for integrating
G1 Docket zero-trust attestation into LangChain, LlamaIndex, AutoGen, and custom AI agent workflows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

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


def wrap_rag_documents(
    documents: Sequence[DocketRAGDocument | Mapping[str, Any] | tuple[str, str]],
) -> str:
    """Wrap a sequence of retrieved documents or chunk mappings into newline-separated `<pod:object>` blocks.

    Accepts:
      - `DocketRAGDocument` instances
      - Mappings with `'locator'` and `'content'` keys (e.g. LangChain or LlamaIndex chunks)
      - Tuples of `(locator, content)`
    """
    blocks: list[str] = []
    for doc in documents:
        if isinstance(doc, DocketRAGDocument):
            blocks.append(doc.to_pod_tag())
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
    documents: Sequence[DocketRAGDocument | Mapping[str, Any] | tuple[str, str]],
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
