# OProW Python Reference Draft — Step 10

Step 10 adds privacy profiles for `SHORT64-HV` resolution on top of the Step 8 HDC routing layer and the Step 9 authenticated-map proof system.

The privacy problem is that an HDC-derived route token can become a media fingerprint. Even though the resolver never receives the raw PED or raw hypervector, a very precise route key may still let a public resolver infer that a verifier is checking one particular artifact or something visually similar.

This step implements three profiles:

| Profile | Meaning | Intended use |
|---|---|---|
| `P0_PUBLIC_FAST` | Precise route tokens, fastest lookup, weakest lookup privacy | Public social content where privacy is not important |
| `P1_K_ANON_BUCKET` | Coarser short-ID and HDC route buckets, exact filtering done locally | Default consumer verification |
| `P2_RELAY_COVER` | P1 plus plausible cover route keys, suitable for relay/batch lookup | Sensitive verification where resolver-side surveillance is a concern |

The core security rule remains unchanged:

```text
HDC route match != provenance verification
```

HDC and privacy planning only retrieve candidates. Final verification still requires locator self-consistency, manifest signatures, essence/content binding, and local trust policy.

## New modules

```text
oprow/privacy/
  profiles.py      # P0/P1/P2 policy objects and precision ladders
  planning.py      # query planner, redacted public query shape, cover sampler
  indexing.py      # helper to publish route entries for policy precisions
  relay.py         # public relay batch request shape

oprow/resolution/privacy_short64_hv.py
  PrivacyPreservingAuthenticatedShort64HVResolver
```

The authenticated and unauthenticated SHORT64-HV resolvers also accept optional `privacy_policy`, `privacy_planner`, `cover_sampler`, and `stats_provider` fields.

## Important implementation choices

1. Raw PEDs and raw HDC hypervectors stay client-side.
2. Public query objects contain opaque `route_key` hashes and precision metadata only.
3. P1 broadens route precision and locally filters returned candidates by exact `ShortId`.
4. P2 adds cover route keys, preferably sampled from plausible public index buckets.
5. Authenticated-map openings are still verified for every queried route key.
6. The resolver may return candidate references, but the Step 5 verifier makes the final decision.

## Try it

```bash
python examples/step10_privacy_profiles.py
python -m pytest -q
```
