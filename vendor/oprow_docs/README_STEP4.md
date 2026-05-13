# OProW Python Reference Draft — Step 4: Resolution and Storage

This step adds the first resolver layer to the Step 1–3 package.

The theory implemented here is the OProW separation between **finding** and **verifying**:

```text
watermark / metadata pointer  ->  resolver  ->  candidate signed manifests
candidate signed manifests    ->  verifier  ->  signatures + essence + trust policy
```

A resolver is not a trust oracle. A manifest fetched from embedded metadata, a sidecar file, a local content-addressed store, or an HTTP gateway is accepted as a *candidate* only after the resolver parses canonical CBOR and checks that the candidate `SignedManifest` matches the requested locator.

## New / changed modules

```text
oprow/core/canonical.py
  Adds canonical_cbor_loads(...), a restricted decoder for the same deterministic
  CBOR subset that Step 1 signs and hashes.

oprow/manifest/codec.py
  Converts canonical resolver bytes into SignedManifest / ManifestEnvelope
  objects and round-trips them without changing canonical bytes.

oprow/resolution/base.py
  Resolver protocol, ResolutionRequest, ResolutionResult, ResolutionCandidate,
  locator-check helper, deduplication, and size guards.

oprow/resolution/embedded.py
  Prototype embedded resolver using Artifact.metadata fields. Real EXIF/XMP/
  JUMBF/C2PA parsing is intentionally deferred.

oprow/resolution/local.py
  Local path and sidecar resolver. Finds explicit local-path hints, sidecars next
  to an artifact, and locator-named files in configured search directories.

oprow/resolution/cas.py
  MemoryCAS, FileCAS, and CASResolver for FULL160 content-addressed lookup.

oprow/resolution/http.py
  HTTPGatewayResolver using URL templates and HTTP storage hints. HTTP is a
  mirror/convenience path, not an authority.

oprow/resolution/composite.py
  Tries multiple resolver backends in a caller-defined order.
```

## Important implementation choices

### Canonical bytes are still the addressed object

`SignedManifest.canonical_bytes()` remains the object named by FULL160 and default hash-truncated SHORT64 locators. The resolver codec accepts canonical CBOR, not arbitrary Python objects or pickle.

### Envelopes are transport wrappers

`ManifestEnvelope` can carry storage hints and future trust evidence, but the locator still points to the canonical `SignedManifest` bytes. This preserves the algorithm-framework fix: ASI:chain receipts, C2PA evidence, and resolver proofs do not create self-referential manifest keys.

### Storage is availability, not integrity

Local files, CAS stores, and HTTP gateways are all untrusted. Integrity comes from:

```text
candidate bytes -> SignedManifest -> canonical bytes -> locator self-consistency
```

Final acceptance still requires signatures, essence/content binding, and trust policy.

### SHORT64 is only minimally supported here

Step 4 can parse and self-check hash-truncated SHORT64 candidates if they are supplied by an embedded/local source. The real SHORT64 index arrives in Step 7, and SHORT64-HV/HDC routing arrives in Step 8.

## Example

Run:

```bash
python examples/step4_resolve_manifest.py
```

The example creates a signed manifest, writes a local sidecar, stores the manifest in an in-memory CAS, resolves through a `CompositeResolver`, and then separately verifies the manifest signature.

## Tests

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```

The plugin-disabling environment variable is not required in ordinary environments, but it avoids unrelated test-runner plugin shutdown delays in this sandbox.
