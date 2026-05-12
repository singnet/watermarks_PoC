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
from .storage import (
    BACKEND_NAMES,
    FakeArweaveStore,
    FakeIPFSStore,
    LocalFileStore,
    ManifestStore,
    detect_backend,
    store_from_spec,
)
from .transforms import TRANSFORMS

__all__ = [
    "SignEmbedResult",
    "VerifyResult",
    "TRANSFORMS",
    "BACKEND_NAMES",
    "ManifestStore",
    "LocalFileStore",
    "FakeArweaveStore",
    "FakeIPFSStore",
    "store_from_spec",
    "detect_backend",
    "run_demo",
    "sign_and_embed",
    "embed_only",
    "verify",
    "inspect_only",
]
