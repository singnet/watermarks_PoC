"""Optional strict essence commitments.

OProW's interoperable path uses PED-based perceptual commitments because media
is routinely resized, recompressed, and transcoded.  Some workflows, however,
operate in closed loops where exact bytes are preserved: archival systems,
forensic chain-of-custody tooling, or local regression tests.  In those cases a
strict hash is valuable as an additional signed field.

This file implements the simplest strict commitment:

    strict_byte_hash = H256(container bytes)

There is deliberately no attempt here to canonicalize metadata or normalize
container structure.  Byte hashing means exactly what it says: one bit changed
in the file means a different hash.  The image module also exposes
``compute_strict_decode_rgb_hash`` for normalized decoded pixels.
"""

from __future__ import annotations

from ..core.enums import HashAlgorithm
from ..core.identifiers import Hash256
from ..core.models import Artifact


def compute_strict_byte_hash(artifact: Artifact, *, hash_alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> Hash256:
    """Return H256 over the artifact's exact container bytes."""
    return Hash256.from_data(artifact.read_bytes(), alg=hash_alg)
