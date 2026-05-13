"""Manifest signing, verification, and wire-codec layer.

Step 2 added signatures over ``ManifestCore``. Step 4 adds a resolver-facing
codec so canonical manifest bytes fetched from storage can be parsed back into
``SignedManifest`` / ``ManifestEnvelope`` objects before locator checks.
"""

from .keys import (
    FunctionKeyResolver,
    KeyResolver,
    MemoryKeyRegistry,
    PrivateKeyEncoding,
    PrivateKeyRecord,
    PublicKeyEncoding,
    PublicKeyRecord,
    SignatureAlgorithm,
    derive_reference_key_id,
    generate_ed25519_keypair,
    generate_p256_keypair,
)
from .signatures import (
    OProWSigner,
    SignatureCheck,
    SignatureProtectedHeader,
    add_signature,
    create_signed_manifest,
    signature_preimage,
    sort_signature_records,
    verify_signature_record,
)
from .verification import (
    ManifestSignatureReport,
    require_locator_self_consistency,
    valid_signature_records_for_roles,
    verify_locator_self_consistency,
    verify_manifest_signatures,
)
from .codec import (
    ManifestCodecError,
    assert_round_trip_envelope,
    assert_round_trip_signed_manifest,
    decode_manifest_document,
    envelope_from_bytes,
    envelope_to_bytes,
    signed_manifest_from_bytes,
    signed_manifest_to_bytes,
)

__all__ = [
    "FunctionKeyResolver",
    "KeyResolver",
    "ManifestCodecError",
    "ManifestSignatureReport",
    "MemoryKeyRegistry",
    "OProWSigner",
    "PrivateKeyEncoding",
    "PrivateKeyRecord",
    "PublicKeyEncoding",
    "PublicKeyRecord",
    "SignatureAlgorithm",
    "SignatureCheck",
    "SignatureProtectedHeader",
    "add_signature",
    "assert_round_trip_envelope",
    "assert_round_trip_signed_manifest",
    "create_signed_manifest",
    "decode_manifest_document",
    "derive_reference_key_id",
    "envelope_from_bytes",
    "envelope_to_bytes",
    "generate_ed25519_keypair",
    "generate_p256_keypair",
    "require_locator_self_consistency",
    "signature_preimage",
    "signed_manifest_from_bytes",
    "signed_manifest_to_bytes",
    "sort_signature_records",
    "valid_signature_records_for_roles",
    "verify_locator_self_consistency",
    "verify_manifest_signatures",
    "verify_signature_record",
]
