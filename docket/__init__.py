"""G1 Docket Python SDK.

Provides typed synchronous and asynchronous client interfaces for the G1 Docket
Data Attestation Framework, Prevalidator Proxy, Authoritative Registry,
and Signed Snapshot Publisher.
"""

from docket.client import AsyncDocketClient, DocketClient, DocketError, PolicyDenialError
from docket.integrations import (
    DocketAutoGenHook,
    DocketCrewAITool,
    DocketDocumentTransformer,
    DocketLangChainCallbackHandler,
    DocketLlamaIndexPostprocessor,
    DocketLlamaIndexTransformComponent,
    DocketRAGDocument,
    DocketTransformComponent,
    attested_tool,
    docket_langgraph_node,
    extract_prompt_locators,
    format_rag_prompt,
    wrap_agent_tool_output,
    wrap_rag_documents,
)

from docket.watermark import (
    WatermarkPayload,
    embed_invisible_watermark,
    extract_invisible_watermark,
    format_structural_watermark,
    has_invisible_watermark,
)

__all__ = [
    "DocketClient",
    "AsyncDocketClient",
    "DocketError",
    "PolicyDenialError",
    "DocketRAGDocument",
    "DocketDocumentTransformer",
    "DocketLlamaIndexPostprocessor",
    "DocketTransformComponent",
    "DocketLlamaIndexTransformComponent",
    "DocketLangChainCallbackHandler",
    "DocketCrewAITool",
    "DocketAutoGenHook",
    "docket_langgraph_node",
    "attested_tool",
    "wrap_agent_tool_output",
    "wrap_rag_documents",
    "format_rag_prompt",
    "extract_prompt_locators",
    "WatermarkPayload",
    "embed_invisible_watermark",
    "extract_invisible_watermark",
    "has_invisible_watermark",
    "format_structural_watermark",
]
