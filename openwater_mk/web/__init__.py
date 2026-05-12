"""openwater-mk web service.

Exposes the openwater pipeline as a FastAPI app served by uvicorn. Targets
the V1 "hosted verifier at openwater.mk" line item from the implementation-
time-estimates doc (Slice B / serious public alpha). Per-job state is
local-disk only; no database, no auth, no rate limiting yet.
"""
from .server import UnsafeBindError, build_app, run

__all__ = ["build_app", "run", "UnsafeBindError"]
