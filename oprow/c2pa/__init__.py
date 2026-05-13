"""C2PA / Durable Content Credentials adapter skeleton for OProW Step 6."""

from .adapter import (
    C2PAAdapter,
    C2PAAdapterOptions,
    c2pa_instance_id_for_signed_manifest,
    c2pa_manifest_id_for_signed_manifest,
    c2pa_manifest_to_debug_dict,
    make_actions_assertion,
    make_essence_assertion,
    make_locator_assertion,
    make_oprow_manifest_assertion,
    make_signature_summary_assertion,
    make_trust_evidence_assertion,
    parse_embedded_oprow_manifest_assertion_bytes,
)
from .bridge import C2PASDKBridge, NullC2PASDKBridge
from .models import (
    C2PA_ACTIONS_LABEL,
    C2PA_METADATA_LABEL,
    C2PA_SOFT_BINDING_LABEL,
    C2PAAdapterResult,
    C2PAAssertion,
    C2PAClaim,
    C2PAManifest,
    C2PAManifestStore,
    C2PAMappingNote,
    OPROW_ESSENCE_ASSERTION_LABEL,
    OPROW_LOCATOR_ASSERTION_LABEL,
    OPROW_MANIFEST_ASSERTION_LABEL,
    OPROW_SIGNATURE_SUMMARY_ASSERTION_LABEL,
    OPROW_TRUST_EVIDENCE_ASSERTION_LABEL,
)
from .repository import (
    SoftBindingMatch,
    SoftBindingMatchRequest,
    SoftBindingMatchResponse,
    build_match_response_for_store,
)
from .soft_binding import (
    OPROW_SOFT_BINDING_FULL160_ALG,
    OPROW_SOFT_BINDING_FULL160_RATELESS_ALG,
    OPROW_SOFT_BINDING_SHORT64_ALG,
    OPROW_SOFT_BINDING_SHORT64_HV_ALG,
    SoftBindingOptions,
    extract_oprow_locator_from_soft_binding,
    locator_from_soft_binding_value,
    locator_to_soft_binding_value,
    make_oprow_soft_binding_assertion,
    soft_binding_alg_for_locator,
)

__all__ = [name for name in globals() if not name.startswith("_")]
