"""Authenticated map package for OProW Step 9.

The public surface exports two layers:

* Generic sparse Merkle map primitives (``SparseMerkleMap`` and proofs).
* SHORT64-HV-specific authenticated candidate-set indexing.

The generic layer can also be reused later for key-transparency logs, trust
bundle snapshots, revocation sets, and ASI:chain-anchored index roots.
"""

from .sparse_merkle import (
    SMT_ALG_ID,
    SMT_DEPTH,
    AuthenticatedMapCommitment,
    AuthenticatedMapOpening,
    SparseMerkleMap,
    SparseMerkleProof,
    default_hash_for_level,
    key_bit,
    sparse_leaf_hash,
    sparse_merkle_proof_from_primitive,
    sparse_node_hash,
)
from .short64_hv import (
    AuthenticatedIndexRootRecord,
    AuthenticatedShort64HVIndex,
    AuthenticatedShort64HVLookupResult,
    RouteCandidateSet,
    RouteCandidateSetOpening,
    build_authenticated_short64_hv_index,
    route_candidate_set_from_primitive,
)

__all__ = [name for name in globals() if not name.startswith("_")]
