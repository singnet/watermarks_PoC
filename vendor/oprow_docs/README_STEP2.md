# OProW Python Reference Draft — Step 2

This package is the second incremental draft of a Python reference
implementation for **Open Provenance Watermarking (OProW)**.

Step 1 implemented the core object model, deterministic canonical CBOR, typed
identifiers, and the corrected non-self-referential manifest/envelope layering.
Step 2 adds **real manifest signing and signature verification**.

The design follows the OProW architecture in which the manifest layer is a
structured, signed data object containing provenance claims and a cryptographic
commitment to media essence. The watermark/resolution/trust layers are still
separate; signature verification alone does not prove that media bytes match the
manifest, nor that the key is trusted. The specification's reference pseudocode
places signature verification after manifest resolution and before essence/trust
checks; this package implements that cryptographic signature stage.

## What is included

```text
oprow/
  core/                  # Step 1 core dataclasses and canonical CBOR
  manifest/
    keys.py              # Key records, key generation, in-memory key resolver
    signatures.py        # Protected signature headers, signing, low-level checks
    verification.py      # ManifestSignatureReport and locator self-consistency
examples/
  step2_sign_and_verify.py
  step2_tamper_detection.py
tests/
  test_step1_core.py
  test_step2_signatures.py
```

## Core theory implemented in Step 2

### 1. Sign the ManifestCore, not the envelope

OProW separates:

```text
ManifestCore     = semantic object signers attest to
SignedManifest   = ManifestCore + signatures; addressed by FULL160/SHORT64
ManifestEnvelope = SignedManifest + storage hints + trust evidence
```

Signatures cover `ManifestCore` and a protected signature header. They do **not**
cover `ManifestEnvelope`, because an envelope may acquire ASI:chain receipts,
C2PA evidence, resolver proofs, or storage hints after signing.

### 2. Protect signature metadata

A naive scheme signs only the manifest core. That leaves fields like `role` and
`signed_at` mutable. Step 2 instead signs:

```text
frame("oprow-signature-preimage-v1",
      canonical_cbor(SignatureProtectedHeader),
      canonical_cbor(ManifestCore))
```

The protected header binds:

```text
profile, kid, alg, role, signed_at, hash_alg
```

If an attacker changes `role="tool"` to `role="notary"`, verification fails.
Trust policy must still decide whether the key is actually authorized for a role;
Step 2 only prevents post-signature mutation of the role label.

### 3. Keep trust separate from cryptographic validity

A valid signature means:

```text
public key K verified signature S over ManifestCore C and protected header H
```

It does **not** mean:

```text
K is trusted
K was not revoked
K is authorized as a notary
The media artifact matches the essence hash
The manifest was found through a private resolver
```

Those checks arrive in later steps.

## Try it

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e . pytest
pytest
python examples/step2_sign_and_verify.py
python examples/step2_tamper_detection.py
```
