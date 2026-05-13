# OProW Step 11 — Modular trust backend and ASI:chain adapter

Step 11 adds the trust-layer code that was intentionally left as a future extension in the earlier steps.

The design keeps OProW chain-agnostic while providing a first-class ASI:chain adapter:

```text
OProW trust layer
  AnchorRecord
  AnchorReceipt
  TrustBackend protocol
  MemoryTrustBackend
  MultiTrustBackend

ASI:chain adapter
  ASIChainTrustBackend
  MockASIChainClient
  ASIChainHTTPClient
  ASIChainExternalCLIClient
  Rholang source-term anchor templates
```

## Security boundary

The trust backend anchors compact commitments only. It should not publish raw media, raw PEDs, raw HDC hypervectors, live route-query buckets, query logs, encrypted private claims, or full manifests.

The ASI:chain backend can anchor:

- authenticated SHORT64-HV index root records;
- key-transparency log checkpoints;
- trust-bundle descriptors;
- namespace-controller records;
- revocation-map roots;
- generic commitments.

The receipt is **external evidence**. It lives in `ManifestEnvelope.trust_evidence` or verification diagnostics. It is not inserted into `SignedManifest` and does not change the watermark locator.

## DevNet adapter status

This package includes both a safe no-network mock and a first draft real adapter boundary.

- `MockASIChainClient` is deterministic and used by tests/examples.
- `ASIChainHTTPClient` can call status, blocks, explore-deploy, and submit already-signed deploy JSON to a configured node API.
- `ASIChainExternalCLIClient` wraps an external CLI for signing and deployment, matching the current ASI DevNet pattern of using wallet/CLI tooling for contract deploys.

A production ASI integration should eventually replace the source-term anchor with deployed Rholang registry contracts such as `OProWAnchorRegistry`, `OProWTrustBundleRegistry`, `OProWNamespaceRegistry`, and `OProWRevocationRegistry`.

## Example

```bash
python examples/step11_asi_chain_backend.py
```

Expected output includes a mock transaction id and a verified ASI-chain-style receipt.

## Tests

```bash
python -m pytest -q
```

The Step 11 tests check:

- generic memory backend anchoring;
- anchoring Step 9 authenticated index roots;
- mock ASI:chain publication and verification;
- rendered Rholang source-term anchors;
- namespace and trust-bundle registry records;
- final OProW media verification with an externally anchored index root.
