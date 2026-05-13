"""Small string enums shared by the Step 1 core layer.

Enum values, not Python enum names, are serialized into canonical CBOR.  This
keeps protocol bytes stable even if the internal Python names are later changed.
"""

from __future__ import annotations

from enum import Enum


class PointerMode(str, Enum):
    """How a watermark pointer locates provenance data."""
    FULL160 = "full160"
    SHORT64 = "short64"
    SHORT64_HV = "short64_hv"
    FULL160_RATELESS = "full160_rateless"


class HashAlgorithm(str, Enum):
    """Core hash algorithms.  SHA-256 is mandatory; BLAKE3 is optional."""
    SHA256 = "sha256"
    BLAKE3_256 = "blake3-256"


class ClaimType(str, Enum):
    """Standard claim type labels."""
    CAPTURE = "capture"
    GENERATION = "generation"
    EDIT = "edit"
    NOTARY = "notary"


class SignatureRole(str, Enum):
    """Informational signer roles; trust policy interprets their meaning."""
    CREATOR = "creator"
    DEVICE = "device"
    TOOL = "tool"
    NOTARY = "notary"
    BUNDLE_ISSUER = "bundle_issuer"
    LOG_OPERATOR = "log_operator"


class StorageHintType(str, Enum):
    """Non-authoritative places a resolver may look for a manifest."""
    EMBEDDED = "embedded"
    SIDECAR = "sidecar"
    LOCAL_PATH = "local_path"
    HTTP = "http"
    IPFS = "ipfs"
    CAS = "cas"


class TrustEvidenceType(str, Enum):
    """Evidence kept outside SignedManifest so locators remain stable."""
    C2PA_EVIDENCE = "c2pa_evidence"
    ASI_CHAIN_RECEIPT = "asi_chain_receipt"
    BLOCKCHAIN_ANCHOR_RECEIPT = "blockchain_anchor_receipt"
    TRANSPARENCY_INCLUSION = "transparency_inclusion"
    TRANSPARENCY_CONSISTENCY = "transparency_consistency"
    AUTHENTICATED_INDEX_PROOF = "authenticated_index_proof"
