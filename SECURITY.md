# Security posture, known gaps, and what to audit

openwater-mk is a **reference / demo implementation** of the V1 surface
of the OpenWater provenance stack. It is *not* a production system. This
file exists so that a security reviewer does not waste time re-deriving
the gaps that we already know about.

If you find an issue not in this list, please open a private issue or
email `alexander.krone@singularitynet.io`.

## What this codebase is for

| Scope | OK | Audit Recommended | Audit Mandatory |
| --- | --- | --- | --- |
| Local demo on `127.0.0.1` | ✓ | | |
| Private alpha to ≤5 trusted reviewers | ✓ | | |
| Anything bound to `0.0.0.0` or a public address | | ✓ | |
| Public alpha / openwater.mk URL | | | ✓ |
| Press-release-grade claims of trustworthiness | | | ✓ |

The `openwater serve` command refuses to bind to anything other than
loopback unless you pass `--unsafe-public`, by design.

## Threat model summary

This system has three kinds of secret material:

1. **Operator Ed25519 private keys** — currently stored as plaintext hex
   in `key.json`. Reference-grade only. Production must use HSM/KMS or
   remote-signer.
2. **Signed manifests + anchor records** — public by design. Their
   integrity is enforced by Ed25519 signatures + canonical CBOR + the
   PED-IMG-1 essence binding (all in upstream `oprow`).
3. **Off-chain storage URIs (`ar://`, `ipfs://`)** — public; pointers
   only. The `fake-*` backends do not make network calls.

Trust does **not** flow from a successful watermark extraction:

- A locator may be recovered from a copy/paste / tamper attack.
- A signature may be valid for an attacker-controlled artifact.
- The OpenWater verifier MUST reject when essence binding fails, even
  if extraction and signature both succeeded. The `--tamper` flag and
  `test_tamper_rejected_with_content_mismatch` enforce this.

## Known gaps (we already know, please confirm during audit)

### High

1. **Plaintext private keys.** `openwater_mk.pipeline._key_to_envelope`
   serializes the raw 32-byte Ed25519 private key as hex in
   `key.json`. Anyone with read access to a job directory can sign
   manifests as that operator. Reference-grade only; production must
   move to HSM/KMS/secure-enclave/remote-signer. (Upstream oprow's
   `PrivateKeyRecord` docstring says the same.)

2. **Web service has no authentication.** Every endpoint is open by
   default. Mitigated by refusing non-loopback binds. Before any
   non-loopback deployment, add an auth layer — at minimum
   `OPENWATER_ADMIN_TOKEN` for the listing endpoint (already
   implemented for `/jobs`), at full scope an OAuth2 / JWT layer
   for `/sign-embed`, `/verify`, `/anchor`.

### Medium

3. **Upload size cap is enforced at the HTTP layer only.** The current
   default is 1 MB (set in `MAX_UPLOAD_BYTES`, configurable via the
   `OPENWATER_MAX_UPLOAD_BYTES` env var or `--max-upload-bytes`). A
   client that lies about `Content-Length` and streams a larger body
   will be cut off at read time; PIL is also resilient to most
   oversized PNGs. No streaming-decode protection beyond Pillow's
   built-in checks.

4. **Pillow attack surface.** `verify_uploaded` decodes arbitrary
   user-supplied PNG bytes with Pillow. Pillow 12.x is current and
   patched but image decoders have a long CVE history; do not run the
   service as root and prefer running it in a container with no
   network egress.

5. **No CORS / rate limiting / structured logging.** Demo-grade.

### Low

6. **`/jobs` listing leaks every job_id.** Now gated behind
   `OPENWATER_ADMIN_TOKEN`; with no token configured the endpoint
   returns `403`.

7. **Path traversal.** `job_id` comes from server-side `uuid4().hex`
   and is validated against a 32-hex-char pattern before any filesystem
   access. Direct user-supplied paths are not accepted by any endpoint.

8. **HTML escaping.** `web/templates.py` uses `html.escape()` on all
   user-controlled fields. No user-supplied HTML reaches the response.

9. **Mock Cardano backend.** Receipts label backend as `mock_cardano`
   verbatim. A reader who skips that line could mistake it for real;
   the HTML report and JSON receipts both name the backend explicitly.

### Out of scope here (upstream-`oprow` audit territory)

10. **CBOR canonicalization, signature scheme, PED-IMG-1 essence,
    watermark profiles.** All implemented in `oprow_step14_benchmarks`.
    Bugs there would propagate through this codebase; an audit of
    openwater-mk should not re-verify those primitives but should
    confirm that *our* reconstructions (key envelope decode, anchor
    record CBOR encoding, manifest store round-trip) match the upstream
    canonical bytes.

## What an audit should focus on

In rough priority order:

1. **Key management.** Confirm the plaintext key envelope is never the
   intended production storage path. Confirm the reconstruction in
   `_public_from_envelope` and `_key_from_envelope` round-trips
   correctly through `signed_manifest_from_bytes`. There was already
   one regression here (kid string vs `KeyId` wrapper) — re-check
   every reconstruction.
2. **Web service hardening.** Confirm size limits actually cut off
   reads, not just response headers. Add WAF / reverse proxy guidance.
   Decide whether `/sign-embed` should be authed before any public
   deployment.
3. **Cardano metadata anchor schema vs §16.6.4.** Confirm the bytes
   sent to `MockCardanoBackend.submit()` would also be accepted by a
   real Cardano node — no oversized strings, no non-CBOR-encodable
   types, label `40961` is still acceptable.
4. **Storage backend identifiers.** Confirm that fake Arweave txids
   and fake IPFS CIDs cannot be mistaken for real ones by downstream
   consumers (label `backend=fake_*` in the receipt; documented; URI
   scheme is identical to production by design).
5. **Dependency review.** `oprow`, `cryptography`, `pillow`, `fastapi`,
   `uvicorn`, `python-multipart`. All current as of writing; pin in
   `requirements.txt`.

## Reporting

Private repo; please email `alexander.krone@singularitynet.io` for
vulnerabilities. Public issues are fine for documentation / typo /
ergonomic feedback.
