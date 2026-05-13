# OProW Python Reference Draft — Step 7

This step adds the first non-HDC SHORT64 index and resolver.

A FULL160 watermark carries a 20-byte content-addressed manifest key. A SHORT64
watermark carries only an 8-byte identifier, which can be more robust in hostile
watermark channels but is collision-prone at web scale. The Step 7 index is
therefore **candidate discovery**, not trust.

Implemented default derivation:

```text
short_id = Trunc64(H256(canonical_cbor(SignedManifest)))
```

New files:

```text
oprow/short64/models.py      # references, snapshots, derivation labels
oprow/short64/index.py       # MemoryShort64Index and FileShort64Index
oprow/resolution/short64.py  # Short64IndexResolver
examples/step7_short64_index.py
tests/test_step7_short64.py
```

The resolver can return candidates from inline index bytes or by using an
optional backing FULL160 resolver such as CASResolver. The Step 5 verifier then
checks locator self-consistency, signatures, essence/content binding, and local
trust policy.

Not implemented yet:

* HDC/hypervector route buckets — Step 8.
* Authenticated completeness proofs — Step 9.
* Privacy-preserving lookup profiles — Step 10.
* ASI:chain trust/backend adapter — Step 11.

Run tests:

```bash
python -m pytest
```
