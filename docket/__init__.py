"""G1 Docket Python SDK.

Provides typed synchronous and asynchronous client interfaces for the G1 Docket
Data Attestation Framework, Prevalidator Proxy, Authoritative Registry,
and Signed Snapshot Publisher.
"""

from docket.client import AsyncDocketClient, DocketClient, DocketError, PolicyDenialError
from docket.integrations import (
    DocketDocumentTransformer,
    DocketLlamaIndexPostprocessor,
    DocketRAGDocument,
    attested_tool,
    extract_prompt_locators,
    format_rag_prompt,
    wrap_agent_tool_output,
    wrap_rag_documents,
)

__all__ = [
    "DocketClient",
    "AsyncDocketClient",
    "DocketError",
    "PolicyDenialError",
    "DocketRAGDocument",
    "DocketDocumentTransformer",
    "DocketLlamaIndexPostprocessor",
    "attested_tool",
    "wrap_agent_tool_output",
    "wrap_rag_documents",
    "format_rag_prompt",
    "extract_prompt_locators",
]
