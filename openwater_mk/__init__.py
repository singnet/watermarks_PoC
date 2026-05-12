"""openwater-mk — minimal orchestration on top of the oprow Version 0 SDK.

The actual cryptography, watermarking, essence hashing, and verification all
live in the upstream ``oprow`` package. This package is just the glue that
makes a runnable end-to-end demo, plus the ``openwater`` CLI entrypoint.
"""
from .pipeline import (
    SignEmbedResult,
    VerifyResult,
    embed_only,
    inspect_only,
    run_demo,
    sign_and_embed,
    verify,
)
from .transforms import TRANSFORMS

__all__ = [
    "SignEmbedResult",
    "VerifyResult",
    "TRANSFORMS",
    "run_demo",
    "sign_and_embed",
    "embed_only",
    "verify",
    "inspect_only",
]
