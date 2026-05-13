"""OProW Python reference draft — Step 14.

This package currently contains Step 1 core models, Step 2 signatures, Step 3
PED-IMG-1 essence hashing, Step 4 resolution/storage abstractions, Step 5
verification orchestration with rich statuses, a C2PA Durable Content Credentials
adapter skeleton, Step 7 plain SHORT64 indexing/resolution, Step 8
SHORT64-HV hyperdimensional routing, Step 9 authenticated-map proofs, Step 10 privacy profiles P0/P1/P2, Step 11 modular trust backends with an ASI:chain adapter, Step 12 reference watermark payload/carrier implementations, Step 13 rateless FULL160 experiments, and Step 14 transform/adversarial benchmark harnesses.
"""

from .core.canonical import canonical_cbor_dumps, canonical_cbor_loads, canonical_json_dumps
from .core.enums import HashAlgorithm, PointerMode
from .core.hashes import h160, h256, hash_framed, trunc64
from .core.identifiers import Hash256, KeyId, ManifestKey, NamespaceId, ShortId
from .core.policy import CreationPolicy, ResolutionLimits, TrustPolicyStub
from .core.models import (
    Artifact, ArtifactBinding, CaptureClaim, Claim, EditClaim, GenerationClaim,
    ManifestCore, ManifestEnvelope, ManifestLocator, NotaryClaim,
    SignatureRecord, SignedManifest, StorageHint, TrustEvidence,
)
from .manifest import (
    FunctionKeyResolver, KeyResolver, ManifestCodecError, ManifestSignatureReport,
    MemoryKeyRegistry, OProWSigner, PrivateKeyEncoding, PrivateKeyRecord,
    PublicKeyEncoding, PublicKeyRecord, SignatureAlgorithm, SignatureCheck,
    SignatureProtectedHeader, add_signature, assert_round_trip_envelope,
    assert_round_trip_signed_manifest, create_signed_manifest,
    decode_manifest_document, derive_reference_key_id, envelope_from_bytes,
    envelope_to_bytes, generate_ed25519_keypair, generate_p256_keypair,
    require_locator_self_consistency, signature_preimage,
    signed_manifest_from_bytes, signed_manifest_to_bytes, sort_signature_records,
    valid_signature_records_for_roles, verify_locator_self_consistency,
    verify_manifest_signatures, verify_signature_record,
)
from .essence import (
    BaseEssenceProfile, DEFAULT_ESSENCE_REGISTRY, EssenceComputation,
    EssenceProfile, EssenceRegistry, ImagePED1, ImagePED1Components,
    ImagePED1Distance, PED_IMG_1_ALG_ID, PED_IMG_1_LENGTH,
    block_means_32x32, build_artifact_binding, compare_ped_img1,
    compute_essence_hash, compute_essence_hash_img1, compute_essence_img1,
    compute_ped_img1, compute_strict_byte_hash, compute_strict_decode_rgb_hash,
    decode_image_to_rgb, default_essence_registry, dct_sign_sketch_255,
    parse_ped_img1, ped_hash, resize_bilinear_u8, rgb_image_to_luminance_u8,
)
from .resolution import (
    CASResolver, CASStore, CandidateValidationStatus, CompositeResolver,
    EmbeddedManifestResolver, FileCAS, HTTPGatewayResolver, LocalPathResolver,
    MemoryCAS, ResolutionCandidate, ResolutionRequest, ResolutionResult,
    ResolutionStatus, Resolver, ResolverDiagnosticEvent, ResolverError,
    Short64IndexResolver, Short64HVRouteResolver, AuthenticatedShort64HVRouteResolver,
    PrivacyPreservingAuthenticatedShort64HVResolver, PrivacyAwareAuthenticatedShort64HVRouteResolver,
    candidate_from_document_bytes, deduplicate_candidates,
    filter_matching_candidates, result_from_candidates,
)
from .short64 import (
    HASH_TRUNCATED_DERIVATION, NAMESPACED_REGISTRY_DERIVATION,
    SUPPORTED_SHORT64_DERIVATIONS, FileShort64Index, MemoryShort64Index,
    Short64Index, Short64IndexReference, Short64IndexSnapshot,
    Short64LookupResult, build_hash_truncated_short64_index,
    make_namespaced_short_id, short64_reference_from_primitive,
    short64_snapshot_from_bytes,
)
from .hdc import (
    DEFAULT_HDC_PROFILE_ID, DEFAULT_HDC_SEED, DEFAULT_ROUTE_EPOCH,
    HDCComputation, HDCEncoder, HDCProfile, HDCRouter, HyperVector,
    MemoryShort64HVIndex, RoutePrecision, RouteToken, Short64HVIndex,
    SparseTernaryHDCEncoder, SymbolicBundlingHDCEncoder, RandomProjectionHDCEncoder, band_bit_positions, build_short64_hv_index,
    default_hdc_profile, encode_artifact_to_hypervector, encode_ped_to_hypervector,
    extract_band_code, route_key_for_band, short_id_prefix_bytes,
)

from .authmap import (
    SMT_ALG_ID, SMT_DEPTH, AuthenticatedMapCommitment,
    AuthenticatedMapOpening, SparseMerkleMap, SparseMerkleProof,
    AuthenticatedIndexRootRecord, AuthenticatedShort64HVIndex,
    AuthenticatedShort64HVLookupResult, RouteCandidateSet,
    RouteCandidateSetOpening, build_authenticated_short64_hv_index,
    sparse_leaf_hash, sparse_node_hash, default_hash_for_level,
)

from .privacy import (
    Short64HVPrivacyProfile, Short64HVPrivacyPolicy,
    default_short64_hv_privacy_policy, public_fast_policy,
    k_anonymous_bucket_policy, relay_cover_policy,
    BucketEstimate, CoverRouteSampler, NullCoverRouteSampler,
    PlannedRouteQuery, RouteQueryKind, RouteStatsProvider,
    Short64HVPrivacyPlanner, Short64HVQueryPlan, StaticCoverRouteSampler,
    RelayQueryBatch, PrivacyIndexedReference,
    add_manifest_for_privacy_policies, precisions_for_policies,
    precision_to_diagnostics, precision_fingerprint, unique_precisions,
)

from .trust import (
    AnchorObjectType, AnchorRecord, AnchorReceipt, KeyEvent, KeyEventType,
    KeyStatus, KeyStatusValue, MemoryTrustBackend, MultiTrustBackend,
    NamespaceRecord, RevocationRootRecord, TransparencyRootRecord,
    TrustBackend, TrustBundleDescriptor, VerificationCheck,
    domain_hash_for_test_anchor, index_root_to_anchor_record,
)

from .asi_chain import (
    ASI_BACKEND_ID, ANCHOR_CONTRACT_LABEL, ASIAnchorPayload,
    ASIChainClient, ASIChainDeployResult, ASIChainExternalCLIClient,
    ASIChainHTTPClient, ASIChainHTTPError, ASIChainNetworkConfig,
    ASIChainReceipt, ASIChainTrustBackend, MockASIChainClient,
    default_devnet_backend_stub, devnet_cli_client_from_env,
    render_anchor_source_term, render_registry_insert_term,
)


from .rateless import (
    GF2SolveResult, RATELESS_FULL160_EQUATION_ALG_ID,
    RATELESS_FULL160_KEY_BYTES, RATELESS_FULL160_WIDTH, RATELESS_RECORD_BITS,
    RATELESS_RECORD_CRC_BITS, RATELESS_RECORD_ID_BITS, RATELESS_RECORD_VERSION,
    RATELESS_TILE_PREAMBLE_BITS, RATELESS_TILE_PREAMBLE_BYTES,
    IMG_ALPHA_LSB_RATELESS_FULL160_EXP_ALG_ID,
    IMG_ALPHA_LSB_RATELESS_FULL160_EXP_NUMERIC_ID,
    RatelessAlphaLSBFull160Profile, RatelessDecodeResult, RatelessEquation,
    RatelessEquationProfile, RatelessTileRecord, RepeatedRecordDecode,
    bit_list_to_int, bytes_to_int_be, deduplicate_equations,
    encode_repeated_record, equation_for_key, equation_rhs_for_key,
    generate_equations_for_key, gf2_rank, int_to_bit_list,
    int_to_fixed_bytes_be, majority_decode_repeated_record, manifest_key_to_int,
    parity_int, solve_gf2, solve_manifest_key_from_equations,
    sparse_mask_for_equation,
)


from .watermark import (
    DEFAULT_WATERMARK_REGISTRY, FRAME_LENGTH_BITS, FRAME_PREAMBLE_BITS,
    IMG_ALPHA_LSB_REF_ALG_ID, IMG_ALPHA_LSB_REF_NUMERIC_ID,
    IMG_DCT_QIM_REF_ALG_ID, IMG_DCT_QIM_REF_NUMERIC_ID,
    POINTER_MODE_FLAG_MASK, WATERMARK_PAYLOAD_VERSION,
    AlphaLSBImageWatermarkProfile, DCTQIMImageWatermarkProfile,
    RepetitionCode, RepetitionDecodeReport, WatermarkCapacityError,
    WatermarkEmbedResult, WatermarkError, WatermarkExtraction,
    WatermarkExtractionStatus, WatermarkFrameCodec, WatermarkFrameDecodeReport,
    WatermarkPayload, WatermarkProfile, WatermarkRegistry, WatermarkStrength,
    WatermarkVerificationReport, bits_to_bytes, bits_to_int, bytes_to_bits,
    crc16_ccitt_false, default_watermark_registry, embed_manifest_locator,
    extract_locator, int_to_bits, normalize_bits, payload_bit_length_for_mode,
    payload_for_manifest, verify_artifact_from_watermark, xor_bits,
)


from .benchmark import (
    AdversarialVerificationCase, AlphaLSBStripTransform, ArtifactTransform,
    BenchmarkCase, BenchmarkHarness, BenchmarkReport, BrightnessContrastTransform,
    CenterCropTransform, ConfusionCounts, EssenceTrialResult, GaussianBlurTransform,
    GaussianNoiseTransform, HDCTrialResult, IdentityTransform, JPEGRecompressTransform,
    MetricSample, PNGRoundTripTransform, PayloadFactory, RandomRectangleOcclusionTransform,
    ResizeTransform, ScreenshotSimulationTransform, SocialPipelineTransform,
    TileAlphaErasureTransform, TransformApplication, TransformSuite, WatermarkTrialResult,
    adversarial_image_transform_suite, benchmark_essence_profile,
    benchmark_essence_separation, benchmark_hdc_separation, benchmark_hdc_stability,
    benchmark_watermark_profile, byte_difference_fraction, checker_sample,
    constant_payload_factory, copy_alpha_lsb_carrier, decode_rgb_array,
    default_synthetic_image_corpus, finite_psnr_rgb, gradient_sample,
    hamming_fraction_bits, hostile_image_transform_suite, mse_rgb, psnr_rgb,
    quick_image_transform_suite, run_essence_trial, run_hdc_trial,
    run_watermark_trial, safe_apply_transform, solid_with_stripe_sample,
    summarize_boolean_outcomes, to_jsonable, utc_now_iso,
)

from .verification import (
    CandidateVerification, EssenceCheck, ProvenanceVerifier, SimpleTrustEvaluator,
    TrustDecision, VerificationContext, VerificationInput, VerificationResult,
    VerificationStatus, trust_any_valid_signature_policy, verify_artifact_with_locator,
)
from .c2pa import (
    C2PAAdapter, C2PAAdapterOptions, C2PAAdapterResult, C2PAAssertion,
    C2PAClaim, C2PAManifest, C2PAManifestStore, C2PAMappingNote,
    C2PA_SOFT_BINDING_LABEL, OPROW_MANIFEST_ASSERTION_LABEL,
    OPROW_LOCATOR_ASSERTION_LABEL, OPROW_ESSENCE_ASSERTION_LABEL,
    SoftBindingOptions, SoftBindingMatchRequest, SoftBindingMatchResponse,
    build_match_response_for_store, c2pa_manifest_to_debug_dict,
    extract_oprow_locator_from_soft_binding, make_oprow_soft_binding_assertion,
)

__all__ = [name for name in globals() if not name.startswith("_")]
__version__ = "0.14.0-step14"
