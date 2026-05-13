# OProW Python Reference Draft — Step 5

This package carries forward Steps 1–4 and adds the **verification orchestrator**:

```text
artifact + recovered locator
  -> resolver candidates
  -> locator self-consistency
  -> manifest signature verification
  -> essence/content binding check
  -> local trust policy
  -> rich VerificationResult
```

The verifier is intentionally not Boolean.  It returns statuses such as
`VERIFIED`, `SIGNED_BUT_UNTRUSTED`, `CONTENT_MISMATCH`, `MANIFEST_NOT_FOUND`,
`NO_VALID_SIGNATURES`, and `RESOLUTION_CANDIDATE_FLOOD`.  This matches the OProW
security model: storage and resolver systems help find candidate manifests, but
only signatures, essence matching, and local trust policy can produce verified
provenance.

## New files

```text
oprow/verification/
  result.py          # rich statuses and report dataclasses
  trust.py           # minimal local key/role trust evaluator
  orchestrator.py    # end-to-end verification pipeline
  __init__.py
examples/
  step5_verify_artifact.py
tests/
  test_step5_verification.py
```

## Why Step 5 starts from a locator

Real watermark extraction arrives later in Step 12.  Step 5 therefore accepts an
explicit `ManifestLocator`, as if a watermark extractor had already recovered it.
This keeps the core verifier independent of any particular watermark algorithm.
A future extractor can simply call:

```python
verify_artifact_with_locator(artifact, recovered_locator, resolver=..., key_resolver=...)
```

## Trust behavior

A valid signature is not automatically trusted.  The default `TrustPolicyStub`
has no trusted keys, so a correctly signed and essence-matching manifest becomes
`SIGNED_BUT_UNTRUSTED`.  To get `VERIFIED`, pass a policy naming the signer key
and accepted role:

```python
TrustPolicyStub(
    trusted_key_ids={str(key.kid)},
    accepted_roles={"tool"},
)
```

For examples and early experiments, `trust_any_valid_signature_policy()` enables
a wildcard trust policy.  It is intentionally documented as non-production.

## Run

```bash
python examples/step5_verify_artifact.py
pytest -q
```
