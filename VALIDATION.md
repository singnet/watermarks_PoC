# Validation How-To

This document validates the private-alpha OpenWater POC: watermarking,
manifest verification, fake decentralized storage, mock Cardano anchoring, and
the offline seams for real IPFS/Arweave/Cardano backends. Live network
validation requires the credentials and services listed below.

## Environment

Use Python 3.11-3.13. Python 3.14 is intentionally excluded until the
FastAPI/TestClient stack is verified there.

```bash
./scripts/setup.sh
```

The setup script creates `.venv/`, installs pinned dependencies, and runs the
vendored upstream OProW smoke suite.

## Manual Acceptance Checks

Run these from `openwater-demo/`.

```bash
./scripts/demo.sh --profile alpha_lsb --out /tmp/openwater-alpha
```

Expected: `verified=True`, `extraction=extracted`, `verification=verified`.

```bash
./scripts/demo.sh --out /tmp/openwater-dct
```

Expected: `profile=dct_qim`, `extraction=extracted`, and
`verification=content_mismatch`. This is expected for V0 because DCT-QIM
survives as a locator watermark but perturbs the exact-hash essence.

```bash
.venv/bin/python -m openwater_mk.cli poc --out /tmp/openwater-poc-ar
.venv/bin/python -m openwater_mk.cli poc --storage fake-ipfs --out /tmp/openwater-poc-ipfs
```

Expected for both: `verified=True` and `anchor_ok=True`.

Inspect either POC report:

```bash
cat /tmp/openwater-poc-ar/poc_report.json
```

Required report markers:

- `real_network: false`
- `storage_is_fake: true`
- `cardano_backend: "mock_cardano"`
- `cardano_is_mock: true`
- `verified: true`
- `anchor_ok: true`

These markers are mandatory so private-alpha reports are not confused with
real chain evidence.

## Real Network Checks

IPFS daemon:

```bash
export OPENWATER_IPFS_API_URL=http://127.0.0.1:5001
export OPENWATER_IPFS_GATEWAY_URL=http://127.0.0.1:8080/ipfs
openwater sign-embed --profile alpha_lsb --storage ipfs-daemon --out /tmp/openwater-ipfs-real
openwater verify /tmp/openwater-ipfs-real/watermarked.png \
  --profile alpha_lsb \
  --manifest-store /tmp/openwater-ipfs-real/manifests \
  --key /tmp/openwater-ipfs-real/key.json
```

Arweave gateway/upload command:

```bash
export OPENWATER_ARWEAVE_GATEWAY_URL=https://arweave.net
export OPENWATER_ARWEAVE_UPLOAD_COMMAND='your-uploader {path}'
openwater sign-embed --profile alpha_lsb --storage arweave-gateway --out /tmp/openwater-ar-real
```

The uploader must print `ar://<txid>`, a gateway URL, or a bare 43-character
txid. Arweave does not have a standard public testnet; use the uploader's
devnet/test wallet flow if available.

Cardano preprod via Blockfrost:

```bash
export BLOCKFROST_PROJECT_ID=preprod...
export OPENWATER_CARDANO_NETWORK=preprod
export OPENWATER_CARDANO_PAYMENT_SKEY=/secure/path/payment.skey
export OPENWATER_CARDANO_PAYMENT_ADDRESS=addr_test...
openwater anchor /tmp/openwater-ipfs-real --out /tmp/openwater-cardano-real \
  --cardano-backend blockfrost --cardano-network preprod
openwater verify-anchor /tmp/openwater-cardano-real \
  --cardano-backend blockfrost --cardano-network preprod
```

Expected live-report markers: `real_network: true` when the POC is run with
real storage or `--cardano-backend blockfrost`; `cardano_backend:
"blockfrost_cardano"` for real Cardano receipts.

## Automated Checks

```bash
bash -n scripts/setup.sh scripts/demo.sh
.venv/bin/python -m py_compile openwater_mk/storage.py openwater_mk/cardano.py openwater_mk/pipeline.py openwater_mk/cli.py
.venv/bin/python -m pytest tests/test_demo.py tests/test_cli.py tests/test_storage.py tests/test_cardano.py tests/test_watermark_robust.py -q
.venv/bin/python -m pytest tests/oprow_upstream -q
```

Current expected results:

- local non-web suite: 85 passing
- vendored upstream suite: 85 passing

## Latest Branch Run

Captured on branch `real-testnet-backends` after adding the real-network
backend seams:

```bash
.venv/bin/python -m py_compile openwater_mk/storage.py openwater_mk/cardano.py openwater_mk/pipeline.py openwater_mk/cli.py openwater_mk/web/server.py openwater_mk/web/templates.py tests/test_storage.py tests/test_cardano.py
.venv/bin/python -m pytest tests/test_demo.py tests/test_cli.py tests/test_storage.py tests/test_cardano.py tests/test_watermark_robust.py -q
.venv/bin/python -m pytest tests/oprow_upstream -q
.venv/bin/python -m openwater_mk.cli poc --out /tmp/openwater-real-backend-smoke
```

Observed results:

- local non-web suite: `85 passed`
- vendored upstream suite: `85 passed`
- default POC smoke: `verified=True`, `extraction=extracted`,
  `verification=verified`, `anchor_ok=True`
- smoke report markers: `real_network=false`, `storage_is_fake=true`,
  `storage_is_real=false`, `cardano_backend="mock_cardano"`,
  `cardano_is_mock=true`

If `shellcheck` is installed, also run:

```bash
shellcheck scripts/*.sh
```

## Web Tests

Run web tests only on Python 3.11-3.13:

```bash
.venv/bin/python -m pytest tests/test_web.py -v
```

Do not treat a Python 3.14 FastAPI/TestClient failure as a POC regression;
3.14 is outside the supported matrix for this branch.

In the latest branch run, `timeout 60s .venv/bin/python -m pytest
tests/test_web.py -q` exited with code `124` under Python 3.14.4, matching the
unsupported-matrix caveat above.
