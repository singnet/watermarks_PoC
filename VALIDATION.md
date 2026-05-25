# Validation How-To

This document validates the `main` OpenWater demo path: setup, watermark
verification, fake decentralized storage, and mock Cardano anchoring. Run all
commands from the repository root.

## Environment

Use Python 3.11-3.13. Python 3.14 is outside the supported FastAPI/TestClient
matrix for this branch.

```bash
./scripts/setup.sh
```

Setup creates `.venv/`, installs the local package, and runs the vendored
OProW smoke suite. A final line like `85 passed` means setup completed.

## Main Demo Checks

Prefer the direct module form when validating a fresh checkout:

```bash
.venv/bin/python -m openwater_mk.cli demo --profile alpha_lsb --out /tmp/openwater-main-alpha
```

Expected: `profile=alpha_lsb`, `verified=True`, `extraction=extracted`, and
`verification=verified`.

Run the default DCT-QIM locator demo:

```bash
.venv/bin/python -m openwater_mk.cli demo --out /tmp/openwater-main-dct
```

Expected: `profile=dct_qim`, `extraction=extracted`, and
`verification=content_mismatch`. This is expected because V0 DCT-QIM perturbs
the exact-hash essence while preserving locator extraction.

The wrapper should also work:

```bash
./scripts/demo.sh --profile alpha_lsb --out /tmp/openwater-main-alpha
```

If it reports `openwater: error: unrecognized arguments: --profile alpha_lsb`,
inspect `scripts/demo.sh`; its final line must include the `demo` subcommand:

```bash
exec .venv/bin/python -m openwater_mk.cli demo "$@"
```

## Ben POC Check

Remove old output first so you do not inspect a stale report from an earlier
checkout:

```bash
rm -rf /tmp/openwater-main-poc-ar /tmp/openwater-main-poc-ipfs
```

```bash
.venv/bin/python -m openwater_mk.cli poc --out /tmp/openwater-main-poc-ar
.venv/bin/python -m openwater_mk.cli poc --storage fake-ipfs --out /tmp/openwater-main-poc-ipfs
```

Expected for both: `verified=True` and `anchor_ok=True`.

Inspect the report:

```bash
python -m json.tool /tmp/openwater-main-poc-ar/poc_report.json
```

Required acceptance fields:

- `verified: true`
- `extraction_status: "extracted"`
- `verification_status: "verified"`
- `anchor_ok: true`
- `metadata_label: 40961`
- `confirmations: 1`

Some newer report-marker builds also include explicit demo-scope fields such
as `real_network: false`, `storage_is_fake: true`, `cardano_backend:
"mock_cardano"`, and `cardano_is_mock: true`. If those fields are absent but
the required acceptance fields above are present, the main POC still validated.
To check whether your checkout has the newer marker fields:

```bash
grep -n "real_network" openwater_mk/pipeline.py
.venv/bin/python -m openwater_mk.cli --help
```

## Automated Checks

```bash
.venv/bin/python -m py_compile openwater_mk/pipeline.py openwater_mk/cli.py
.venv/bin/python -m pytest tests/test_demo.py tests/test_cli.py tests/test_storage.py tests/test_cardano.py tests/test_watermark_robust.py -q
.venv/bin/python -m pytest tests/oprow_upstream -q
```

Expected on `main`:

- local non-web suite: `78 passed`
- vendored upstream suite: `85 passed`

Optional shell lint:

```bash
bash -n scripts/setup.sh scripts/demo.sh
```

This only checks shell syntax. No output is expected, and it does not run
setup, tests, or the demo.

## Troubleshooting

Confirm you are validating the expected branch and commit:

```bash
git branch --show-current
git rev-parse --short HEAD
.venv/bin/python -m openwater_mk.cli --help
sed -n '1,40p' scripts/demo.sh
```

On the expected `main`, CLI help includes the `poc` subcommand. If `poc` is
missing, the checkout or installed venv is stale. Run:

```bash
git checkout main
./scripts/setup.sh
.venv/bin/python -m openwater_mk.cli --help
```

Use `bash scripts/setup.sh` or `bash scripts/demo.sh ...` only if the scripts
are not executable on the target machine.

## Web Tests

Run web tests only on Python 3.11-3.13:

```bash
.venv/bin/python -m pytest tests/test_web.py -v
```

Do not treat a Python 3.14 FastAPI/TestClient failure as a main-branch POC
regression; Python 3.14 is outside the supported matrix here.
