"""openwater-mk — minimal orchestration on top of the oprow Version 0 SDK.

The actual cryptography, watermarking, essence hashing, and verification all
live in the upstream ``oprow`` package. This package is just the glue that
makes a runnable end-to-end demo, plus the ``openwater`` CLI entrypoint.
"""
from .cardano import (
    OPENWATER_CARDANO_METADATA_LABEL,
    AnchorRecord,
    AnchorReceipt,
    AnchorResult,
    AnchorVerification,
    MockCardanoBackend,
    anchor_record_hash,
    build_metadata_payload,
    publish_anchor,
    verify_anchor,
)
from .pipeline import (
    DEFAULT_PROFILE,
    PROFILE_NAMES,
    SignEmbedResult,
    VerifyResult,
    anchor_sign_embed_output,
    embed_only,
    inspect_only,
    register_profile,
    run_demo,
    sign_and_embed,
    verify,
    verify_anchor_dir,
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
    # Cardano anchoring
    "OPENWATER_CARDANO_METADATA_LABEL",
    "AnchorRecord",
    "AnchorReceipt",
    "AnchorResult",
    "AnchorVerification",
    "MockCardanoBackend",
    "anchor_record_hash",
    "build_metadata_payload",
    "publish_anchor",
    "verify_anchor",
    "anchor_sign_embed_output",
    "verify_anchor_dir",
]
