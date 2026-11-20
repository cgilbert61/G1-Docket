"""G1 Docket SDK (Alias Package).

Exposes `DocketClient`, `AsyncDocketClient`, `DocketError`, and `PolicyDenialError`.
"""

from docket import AsyncDocketClient, DocketClient, DocketError, PolicyDenialError

__version__ = "1.0.1"

__all__ = [
    "__version__",
    "DocketClient",
    "AsyncDocketClient",
    "DocketError",
    "PolicyDenialError",
]
