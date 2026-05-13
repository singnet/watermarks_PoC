"""Authenticated map primitives for OProW Step 9.

This module implements a small, deliberately explicit **sparse Merkle map**.
It is the first draft of the proof system that later resolvers, indexers, and
ASI:chain anchors can share.

Why an authenticated map?
=========================

The Step 8 SHORT64-HV index is useful but unauthenticated: a resolver can return
candidate manifests for a route key, but it cannot prove that the list is the
complete list for that route key.  That matters for both safety and debugging:

* If a resolver can silently omit candidates, it can bias the verifier toward a
  convenient result.
* If a resolver can silently truncate a large bucket, the verifier may not know
  that it is looking at a candidate-flood / ambiguity condition.
* If the index root can be anchored by a trust backend, such as ASI:chain in a
  later step, clients need a deterministic map proof to connect an off-chain
  answer to the anchored commitment.

A sparse Merkle tree gives each possible 256-bit key a conceptual leaf.  Most
leaves are empty.  A proof for key ``k`` shows either:

    * inclusion: this exact value is stored at k; or
    * non-inclusion: the leaf at k is empty.

For OProW, the key is normally an opaque ``Hash256`` route key derived from
SHORT64-HV routing.  The value is a canonical byte string, often an encoded
candidate set.  The verifier checks the proof against a root hash that can be
cached locally or anchored by a future trust backend.

Security boundaries and implementation choices
==============================================

This is a reference implementation, not a high-throughput production SMT.  It
intentionally favors clarity over asymptotic optimization:

* Keys are fixed 32-byte values, represented by ``Hash256``.
* Proofs are uncompressed: one sibling hash per tree level, i.e. 256 sibling
  hashes.  That is about 8 KiB per opening, which is fine for a first draft and
  easy to audit.  Later production code can add Patricia compression or vector
  commitments without changing higher-level OProW semantics.
* Hashing is domain-separated using the core ``hash_framed`` helper.  Leaves,
  internal nodes, and empty leaves use different domains, preventing accidental
  cross-type collisions.
* The map proves only key/value membership or absence.  It does not say that a
  candidate manifest is valid provenance.  Final verification still requires
  locator self-consistency, signatures, essence matching, and trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable, Mapping

from oprow.core.canonical import canonical_cbor_dumps, canonical_cbor_loads
from oprow.core.errors import ValidationError
from oprow.core.hashes import hash_framed
from oprow.core.identifiers import Hash256

SMT_ALG_ID = "OPROW-SMT-SHA256-V1"
SMT_DEPTH = 256


def _u16(n: int) -> bytes:
    if n < 0 or n >= 2**16:
        raise ValidationError("integer out of u16 range")
    return n.to_bytes(2, "big")


def _u32(n: int) -> bytes:
    if n < 0 or n >= 2**32:
        raise ValidationError("integer out of u32 range")
    return n.to_bytes(4, "big")


def _key_to_int(key: Hash256) -> int:
    return int.from_bytes(key.value, "big")


def key_bit(key: Hash256, level: int, *, depth: int = SMT_DEPTH) -> int:
    """Return the MSB-first path bit for ``key`` at tree ``level``.

    Level 0 is the decision immediately under the root.  Level 255 is the last
    decision before the leaf.  This MSB-first convention matches how route keys
    are normally written and avoids the common mistake of traversing a Merkle
    tree in little-endian bit order.
    """
    if level < 0 or level >= depth:
        raise ValidationError(f"level must be 0..{depth - 1}")
    shift = depth - 1 - level
    return (_key_to_int(key) >> shift) & 1


def sparse_leaf_hash(key: Hash256, value: bytes | bytearray | memoryview) -> Hash256:
    """Hash an occupied sparse-tree leaf.

    The value itself may be large, so the leaf commits to ``H256(value)`` rather
    than inlining the value into every parent hash.  The key is included in the
    leaf hash because a sparse Merkle leaf is a statement about an exact map
    slot, not merely about a value appearing somewhere in the tree.
    """
    value_hash = Hash256.from_data(bytes(value))
    return Hash256(hash_framed("oprow-smt-leaf-v1", SMT_ALG_ID.encode(), key.value, value_hash.value))


def sparse_node_hash(left: Hash256, right: Hash256) -> Hash256:
    """Hash an internal sparse-tree node with explicit left/right ordering."""
    return Hash256(hash_framed("oprow-smt-node-v1", SMT_ALG_ID.encode(), left.value, right.value))


@lru_cache(maxsize=None)
def default_hash_for_level(level: int, depth: int = SMT_DEPTH) -> Hash256:
    """Return the hash of an empty subtree rooted at ``level``.

    ``level == depth`` is an empty leaf.  Higher levels recursively hash two
    empty children.  Caching matters because every proof and root build touches
    the same default subtrees many times.
    """
    if depth != SMT_DEPTH:
        # The implementation is written for a 256-bit key space.  The parameter
        # is retained so the recurrence is self-documenting and testable.
        raise ValidationError("this draft supports only 256-bit sparse maps")
    if level < 0 or level > depth:
        raise ValidationError(f"level must be 0..{depth}")
    if level == depth:
        return Hash256(hash_framed("oprow-smt-empty-leaf-v1", SMT_ALG_ID.encode(), _u16(depth)))
    child = default_hash_for_level(level + 1, depth)
    return sparse_node_hash(child, child)


@dataclass(frozen=True)
class SparseMerkleProof:
    """Opening proof for one sparse-map key.

    ``siblings`` are ordered **top-down**: ``siblings[0]`` is the sibling of the
    child immediately under the root, and ``siblings[255]`` is the sibling leaf.
    This is the most intuitive order when serializing the proof.  Verification
    walks the list in reverse to recompute the root from the leaf upward.

    ``exists`` is a convenience flag.  It is not trusted by itself; verification
    also checks whether the caller supplied a value.  For an inclusion proof,
    call ``verify(root, value_bytes)``.  For a non-inclusion proof, call
    ``verify(root, None)``.
    """

    key: Hash256
    siblings: tuple[Hash256, ...]
    exists: bool
    alg_id: str = SMT_ALG_ID
    depth: int = SMT_DEPTH

    def __post_init__(self) -> None:
        if self.alg_id != SMT_ALG_ID:
            raise ValidationError(f"unsupported sparse Merkle proof algorithm: {self.alg_id!r}")
        if self.depth != SMT_DEPTH:
            raise ValidationError("this draft supports only depth-256 sparse Merkle proofs")
        if len(self.siblings) != self.depth:
            raise ValidationError(f"proof requires {self.depth} sibling hashes, got {len(self.siblings)}")

    def compute_root(self, value: bytes | bytearray | memoryview | None) -> Hash256:
        """Recompute the root implied by this proof and ``value``.

        Supplying ``None`` means "the map leaf is empty."  Supplying bytes means
        "the map leaf is occupied by exactly these canonical bytes."  This
        method does not compare against an expected root; it only performs the
        deterministic hash walk.
        """
        if value is None:
            if self.exists:
                # Do not silently treat an inclusion proof as an absence proof.
                # This catches API misuse early.
                raise ValidationError("proof is marked exists=True but no value was supplied")
            node = default_hash_for_level(self.depth, self.depth)
        else:
            if not self.exists:
                raise ValidationError("proof is marked exists=False but a value was supplied")
            node = sparse_leaf_hash(self.key, bytes(value))

        for level in range(self.depth - 1, -1, -1):
            sibling = self.siblings[level]
            bit = key_bit(self.key, level, depth=self.depth)
            if bit == 0:
                node = sparse_node_hash(node, sibling)
            else:
                node = sparse_node_hash(sibling, node)
        return node

    def verify(self, root: Hash256, value: bytes | bytearray | memoryview | None) -> bool:
        """Return True iff this proof opens ``value`` at ``key`` under ``root``."""
        try:
            return self.compute_root(value) == root
        except ValidationError:
            return False

    def to_canonical(self) -> dict[str, Any]:
        return {
            "alg_id": self.alg_id,
            "depth": self.depth,
            "key": self.key,
            "exists": self.exists,
            "siblings": list(self.siblings),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)


@dataclass(frozen=True)
class AuthenticatedMapOpening:
    """A value/absence proof bundled with the map root it claims to open.

    Higher-level code often wants to pass around a complete opening as one
    object.  For example, a SHORT64-HV resolver can return a route key, its
    candidate-set bytes, a sparse Merkle proof, and the anchored root record.
    This class provides the generic root/proof/value part; domain-specific
    wrappers add typed candidate-set parsing.
    """

    key: Hash256
    value: bytes | None
    proof: SparseMerkleProof
    root_hash: Hash256
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        return self.value is not None

    def verify(self) -> bool:
        return self.proof.key == self.key and self.proof.verify(self.root_hash, self.value)

    def value_hash(self) -> Hash256 | None:
        return Hash256.from_data(self.value) if self.value is not None else None

    def to_canonical(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "proof": self.proof,
            "root_hash": self.root_hash,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class AuthenticatedMapCommitment:
    """Compact commitment to a sparse map snapshot.

    This is the object later trust backends should anchor.  It intentionally
    contains only compact, public commitment metadata.  It does not contain raw
    candidate sets, media descriptors, route tokens, query logs, or manifests.
    """

    root_hash: Hash256
    alg_id: str = SMT_ALG_ID
    depth: int = SMT_DEPTH
    entry_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "root_hash": self.root_hash,
            "alg_id": self.alg_id,
            "depth": self.depth,
            "entry_count": self.entry_count,
            "metadata": self.metadata,
        }


class SparseMerkleMap:
    """Mutable reference sparse Merkle map.

    The map stores ``Hash256 -> bytes`` entries.  It lazily rebuilds its internal
    node cache whenever entries change.  For small reference tests this is more
    than adequate and keeps the algorithm readable.  Production resolvers can
    replace it with an incremental or database-backed SMT while retaining the
    same proof format.
    """

    def __init__(self, entries: Mapping[Hash256, bytes] | None = None):
        self._entries: dict[Hash256, bytes] = {k: bytes(v) for k, v in dict(entries or {}).items()}
        self._nodes_by_level: dict[int, dict[int, Hash256]] | None = None
        self._root_hash: Hash256 | None = None

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def keys(self) -> list[Hash256]:
        return sorted(self._entries, key=lambda k: k.value)

    def get(self, key: Hash256) -> bytes | None:
        value = self._entries.get(key)
        return None if value is None else bytes(value)

    def set(self, key: Hash256, value: bytes | bytearray | memoryview) -> None:
        self._entries[key] = bytes(value)
        self._mark_dirty()

    def delete(self, key: Hash256) -> None:
        if key in self._entries:
            del self._entries[key]
            self._mark_dirty()

    def _mark_dirty(self) -> None:
        self._nodes_by_level = None
        self._root_hash = None

    def root_hash(self) -> Hash256:
        self._ensure_built()
        assert self._root_hash is not None
        return self._root_hash

    def commitment(self, *, metadata: Mapping[str, Any] | None = None) -> AuthenticatedMapCommitment:
        return AuthenticatedMapCommitment(root_hash=self.root_hash(), entry_count=self.entry_count, metadata=dict(metadata or {}))

    def open(self, key: Hash256) -> AuthenticatedMapOpening:
        """Return an inclusion or non-inclusion opening for ``key``."""
        self._ensure_built()
        assert self._nodes_by_level is not None and self._root_hash is not None
        key_int = _key_to_int(key)
        siblings: list[Hash256] = []
        for level in range(0, SMT_DEPTH):
            # Node indices are prefixes.  At level+1 the child index is the top
            # level+1 bits of the key.  Flipping the last bit gives the sibling
            # on the path to the same parent.
            child_index = key_int >> (SMT_DEPTH - (level + 1))
            sibling_index = child_index ^ 1
            sibling = self._nodes_by_level[level + 1].get(sibling_index, default_hash_for_level(level + 1))
            siblings.append(sibling)
        value = self.get(key)
        proof = SparseMerkleProof(key=key, siblings=tuple(siblings), exists=value is not None)
        return AuthenticatedMapOpening(key=key, value=value, proof=proof, root_hash=self._root_hash)

    def verify_opening(self, opening: AuthenticatedMapOpening) -> bool:
        return opening.verify() and opening.root_hash == self.root_hash()

    def _ensure_built(self) -> None:
        if self._nodes_by_level is not None and self._root_hash is not None:
            return
        leaves: dict[int, Hash256] = {}
        for key, value in self._entries.items():
            leaves[_key_to_int(key)] = sparse_leaf_hash(key, value)

        nodes_by_level: dict[int, dict[int, Hash256]] = {SMT_DEPTH: leaves}
        for level in range(SMT_DEPTH - 1, -1, -1):
            child_map = nodes_by_level[level + 1]
            parent_indices = {child_index >> 1 for child_index in child_map}
            parent_map: dict[int, Hash256] = {}
            child_default = default_hash_for_level(level + 1)
            parent_default = default_hash_for_level(level)
            for parent_index in parent_indices:
                left = child_map.get(parent_index << 1, child_default)
                right = child_map.get((parent_index << 1) | 1, child_default)
                parent_hash = sparse_node_hash(left, right)
                # Do not store default subtrees; keeping only non-default nodes is
                # what makes the structure sparse.
                if parent_hash != parent_default:
                    parent_map[parent_index] = parent_hash
            nodes_by_level[level] = parent_map

        self._nodes_by_level = nodes_by_level
        self._root_hash = nodes_by_level[0].get(0, default_hash_for_level(0))

    def to_canonical(self) -> dict[str, Any]:
        """Serialize the full map snapshot for tests/debugging.

        This is not usually sent to verifiers.  Verifiers should see only roots
        and openings.  The snapshot is useful for deterministic test vectors.
        """
        return {
            "alg_id": SMT_ALG_ID,
            "entries": [{"key": k, "value": self._entries[k]} for k in self.keys()],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    @classmethod
    def from_canonical_bytes(cls, data: bytes | bytearray | memoryview) -> "SparseMerkleMap":
        value = canonical_cbor_loads(bytes(data))
        if not isinstance(value, Mapping) or value.get("alg_id") != SMT_ALG_ID:
            raise ValidationError("not an OProW sparse Merkle map snapshot")
        entries_raw = value.get("entries", [])
        if not isinstance(entries_raw, list):
            raise ValidationError("sparse map entries must be a list")
        entries: dict[Hash256, bytes] = {}
        for row in entries_raw:
            if not isinstance(row, Mapping) or not isinstance(row.get("key"), bytes) or not isinstance(row.get("value"), bytes):
                raise ValidationError("invalid sparse map entry")
            entries[Hash256(row["key"])] = row["value"]
        return cls(entries)


def sparse_merkle_proof_from_primitive(value: Any) -> SparseMerkleProof:
    """Parse a proof from canonical primitive form.

    This helper is intentionally small; it is here so tests and later network
    APIs can round-trip proofs without relying on Python pickles or object
    identity.
    """
    if not isinstance(value, Mapping):
        raise ValidationError("SparseMerkleProof primitive must be a map")
    raw_key = value.get("key")
    raw_siblings = value.get("siblings")
    if not isinstance(raw_key, bytes):
        raise ValidationError("proof key must be bytes")
    if not isinstance(raw_siblings, list) or not all(isinstance(x, bytes) for x in raw_siblings):
        raise ValidationError("proof siblings must be a list of bytes")
    return SparseMerkleProof(
        key=Hash256(raw_key),
        siblings=tuple(Hash256(x) for x in raw_siblings),
        exists=bool(value.get("exists")),
        alg_id=str(value.get("alg_id", SMT_ALG_ID)),
        depth=int(value.get("depth", SMT_DEPTH)),
    )


__all__ = [
    "SMT_ALG_ID",
    "SMT_DEPTH",
    "SparseMerkleMap",
    "SparseMerkleProof",
    "AuthenticatedMapOpening",
    "AuthenticatedMapCommitment",
    "default_hash_for_level",
    "key_bit",
    "sparse_leaf_hash",
    "sparse_node_hash",
    "sparse_merkle_proof_from_primitive",
]
