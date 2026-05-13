"""Rholang contract/deploy-term templates for OProW anchors.

This module intentionally starts with the simplest possible ASI:chain anchoring
pattern: deploy a Rholang term whose source contains a canonical OProW anchor
payload.  The deployed term is itself signed by the deployer and stored by the
chain, so the term can function as a compact public commitment even if it does
not mutate application state.

Why not write a full registry contract here?
===========================================

A production ASI:chain integration should likely deploy small registry contracts
such as:

* ``OProWAnchorRegistry`` for transparency/index roots;
* ``OProWTrustBundleRegistry`` for trust-bundle descriptors;
* ``OProWNamespaceRegistry`` for namespace-controller records;
* ``OProWRevocationRegistry`` for revocation roots.

However, contract ABIs and deployment conventions may evolve.  A source-term
anchor is a robust first draft because it only assumes that ASI:chain can deploy
Rholang and that deploys are inspectable later.  The backend API below is shaped
so a future coding agent can replace the source-term template with persistent
registry calls without changing the OProW trust-layer objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from oprow.core.canonical import canonical_json_dumps
from oprow.core.identifiers import Hash256
from oprow.trust.models import AnchorRecord


ANCHOR_CONTRACT_LABEL = "OProWAnchorRegistry.draft.source-term.v1"


@dataclass(frozen=True)
class ASIAnchorPayload:
    """JSON-friendly payload embedded in a Rholang deploy term.

    The payload includes both the raw object commitment and the anchor-record
    commitment.  The object commitment lets verifiers compare against the thing
    they care about (for example a Step 9 authenticated index root).  The record
    commitment binds public context such as object type, subject id, and epoch.
    """

    protocol: str
    contract_label: str
    object_type: str
    subject_id: str | None
    object_hash_hex: str
    record_hash_hex: str
    body_json: str
    version: int = 1

    @classmethod
    def from_anchor_record(cls, anchor: AnchorRecord) -> "ASIAnchorPayload":
        # Debug JSON is used here because Rholang source is text.  The canonical
        # security object remains CBOR in ``AnchorRecord.record_hash()``.
        body_json = canonical_json_dumps(anchor.body).decode("utf-8")
        return cls(
            protocol="oprow-asi-chain-anchor",
            contract_label=ANCHOR_CONTRACT_LABEL,
            object_type=anchor.object_type_value,
            subject_id=anchor.subject_id,
            object_hash_hex=anchor.object_hash.to_hex(),
            record_hash_hex=anchor.record_hash().to_hex(),
            body_json=body_json,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "protocol": self.protocol,
            "contract_label": self.contract_label,
            "object_type": self.object_type,
            "subject_id": self.subject_id,
            "object_hash_hex": self.object_hash_hex,
            "record_hash_hex": self.record_hash_hex,
            "body_json": self.body_json,
        }

    def canonical_json(self) -> str:
        # Sort keys and use compact separators so term hashes are stable.
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def term_hash(self) -> Hash256:
        return Hash256.from_data(render_anchor_source_term(self).encode("utf-8"))


def _rho_string(value: str) -> str:
    """Return a JSON-escaped string literal suitable for Rholang source."""
    return json.dumps(value, ensure_ascii=False)


def render_anchor_source_term(payload: ASIAnchorPayload) -> str:
    """Render a minimal Rholang term carrying the anchor payload.

    The term sends the payload JSON on a private channel and then terminates.  It
    is not intended to be queried as persistent state; the deploy source itself
    is the anchor.  A future registry contract can parse the same payload and
    insert it into an on-chain map.
    """
    payload_json = payload.canonical_json()
    return (
        "// OProW ASI:chain source-term anchor v1\n"
        "// The JSON literal below commits to an OProW AnchorRecord.\n"
        f"// record_hash={payload.record_hash_hex}\n"
        f"// object_hash={payload.object_hash_hex}\n"
        "new anchorPayload in {\n"
        f"  anchorPayload!({_rho_string(payload_json)})\n"
        "}\n"
    )


def render_registry_insert_term(payload: ASIAnchorPayload, *, registry_channel: str = "oprowAnchorRegistry") -> str:
    """Render a draft registry-insert term for future contract integration.

    This is not used by the tests because the exact registry ABI should be
    confirmed against the deployed ASI:chain contract.  It gives the next coding
    agent a concrete starting point while keeping Step 11 safe and deterministic.
    """
    payload_json = payload.canonical_json()
    return (
        "// OProW ASI:chain registry insert draft v1\n"
        f"new registry(`{registry_channel}`) in {{\n"
        f"  registry!({_rho_string(payload_json)})\n"
        "}\n"
    )
