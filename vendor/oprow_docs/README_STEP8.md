# OProW Step 8 — HDC encoder and SHORT64-HV route tokens

This package carries forward Steps 1–7 and adds a first-draft implementation of
SHORT64-HV routing.

The goal of Step 8 is not to make HDC into a cryptographic verifier.  The goal
is to make this lookup path concrete:

```text
watermark SHORT64 value + media-derived HDC route tokens -> candidate manifests
```

The verifier still returns `VERIFIED` only after the Step 5 checks pass:

```text
locator self-consistency
+ valid manifest signatures
+ essence/content binding
+ local trust policy
```

## New modules

```text
oprow/hdc/profiles.py
  HyperVector, HDCProfile, RoutePrecision, RouteToken.

oprow/hdc/encoders.py
  SymbolicBundlingHDCEncoder and compatibility wrappers.  The encoder converts a PED
  into a packed binary hypervector by binding PED byte positions to quantized
  values and bundling the resulting symbols by majority vote.

oprow/hdc/routing.py
  HDCRouter and route-token derivation.  Raw PEDs and raw hypervectors are not
  sent to resolvers.  Route keys are domain-separated hashes of profile, epoch,
  namespace, short-ID prefix, band ID, and coarse HDC band code.

oprow/hdc/index.py
  MemoryShort64HVIndex.  This is an unauthenticated prototype index mapping
  route keys to candidate Short64IndexReference records.

oprow/resolution/short64_hv.py
  Short64HVRouteResolver, which computes HDC route tokens from the artifact,
  queries the route index, and returns candidate manifests for final verification.
```

## Theory implemented

SHORT64 is useful because a 64-bit pointer is easier to embed robustly than a
160-bit locator under aggressive compression, crop, screenshot, or messaging-app
pipelines.  The problem is ambiguity: a 64-bit key is too small to be treated as
a global proof of identity.  HDC helps operationally by using the media itself as
an additional fuzzy routing signal.

The implementation follows this separation:

```text
HDC/PED layer:
  approximate retrieval and candidate reduction

Manifest/signature/essence layer:
  cryptographic provenance verification
```

The Step 8 HDC encoder is intentionally simple.  It uses PED-IMG-1 bytes as
features.  Each PED byte position gets a deterministic public random slot
hypervector; each quantized byte value gets a deterministic public random value
hypervector.  The encoder XOR-binds slot and value vectors, then majority-bundles
all bound symbols into one media route hypervector.  This is a classic
vector-symbolic/HDC pattern adapted to provenance routing.  It is useful for
route-token experiments and benchmarking, but future implementations may replace
it with stronger media-specific HDC profiles.

## Privacy note

Route tokens are safer than raw hypervectors, but they are not a full privacy
solution.  A precise route token can still reveal that someone is checking a
specific or visually similar artifact.  Step 10 will add P0/P1/P2 privacy
profiles, k-anonymous bucket selection, relays, cover queries, and response
padding.  Step 8 exposes the precision knobs (`short_prefix_bits` and
`hv_band_bits`) so those policies can be layered in later.

## Limitations

The Step 8 route index is unauthenticated and can omit or flood candidates.  Step
9 will add authenticated-map proofs so resolvers can prove candidate-set
completeness.  Until then, route-index results are local/prototype retrieval
hints only.

## Quick test

```bash
python -m pytest
python examples/step8_short64_hv.py
```
