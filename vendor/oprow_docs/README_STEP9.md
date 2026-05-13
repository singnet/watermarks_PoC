# OProW Python reference draft — Step 9

Step 9 adds an authenticated-map proof system on top of the Step 8 SHORT64-HV route index.

The new theory implemented here is:

```text
route_key -> complete candidate set -> sparse Merkle proof -> index root
```

The index root is compact and public. It is the object future trust backends, including ASI:chain, can anchor. The candidate sets remain off-chain. Raw PEDs, raw HDC hypervectors, route-query logs, and media fingerprints are not placed on-chain.

New files:

```text
oprow/authmap/
  sparse_merkle.py   # generic depth-256 sparse Merkle map and proofs
  short64_hv.py      # authenticated SHORT64-HV candidate-set index
  __init__.py

oprow/resolution/
  authenticated_short64_hv.py  # resolver that requires proof-verified route openings

examples/
  step9_authenticated_map.py

tests/
  test_step9_authmap.py
```

Important security rule:

```text
An authenticated index proof proves that a candidate set came from a committed index snapshot.
It does not prove provenance.
```

The verifier still requires locator self-consistency, valid signatures, matching essence commitment, and local trust policy before returning `VERIFIED`.

The sparse Merkle implementation is deliberately uncompressed and literate. Each opening contains 256 sibling hashes. This is acceptable for a first reference implementation and makes the proof format easy to audit. Later production implementations can add compressed Patricia proofs or vector commitments while keeping the higher-level API stable.
