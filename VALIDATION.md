# Validation How-To

This document validates the private-alpha OpenWater POC: watermarking,
manifest verification, fake decentralized storage, and mock Cardano anchoring.
It does not validate real Arweave/IPFS/Cardano network submission.

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

## Automated Checks

```bash
bash -n scripts/setup.sh scripts/demo.sh
.venv/bin/python -m py_compile openwater_mk/pipeline.py openwater_mk/cli.py
.venv/bin/python -m pytest tests/test_demo.py tests/test_cli.py tests/test_storage.py tests/test_cardano.py tests/test_watermark_robust.py -q
.venv/bin/python -m pytest tests/oprow_upstream -q
```

Current expected results:

- local non-web suite: 79 passing
- vendored upstream suite: 85 passing

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
