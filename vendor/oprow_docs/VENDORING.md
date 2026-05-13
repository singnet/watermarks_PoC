# Vendored oprow Version 0 SDK

The `oprow/` package at the root of this repository is a verbatim copy of
the upstream `oprow_step14_benchmarks` reference SDK authored by Ben
Goertzel. It is the Version 0 substrate the openwater-mk demo is built
on (manifests, signatures, PED-IMG-1 essence, resolution, verification,
watermark profiles, benchmark harness).

## Source provenance

| Field | Value |
|------|-------|
| Source archive | `oprow_step14_benchmarks-20260512T133940Z-3-001.zip` |
| Archive SHA-256 | `229834ae590250b88c021fbe2989f7cf11567f39087e3b055e8230a6dda5253e` |
| Upstream package version (from `pyproject.toml`) | `oprow-step14 0.14.0` |
| Vendored at | `2026-05-13` |
| Vendored by | Alex / @a-k-l-sdao |
| Provenance contact | Ben Goertzel |

The upstream `pyproject.toml` is preserved alongside this file as
`upstream_pyproject.toml` so the original dependency set and package
metadata stay visible.

## What was copied

- `oprow/` Python package → in-tree as `./oprow/` (zero edits to source).
- `tests/` test suite → in-tree as `./tests/oprow_upstream/` (run as a
  smoke check by `scripts/setup.sh` and CI).
- `README_STEP*.md` (14 stepwise design notes) → preserved here under
  `vendor/oprow_docs/`.
- `pyproject.toml` → preserved here as `upstream_pyproject.toml`.

Caches and build artifacts (`__pycache__/`, `*.egg-info/`,
`.pytest_cache/`, `*.pyc`) were stripped before commit.

## License

**Pending confirmation from Ben Goertzel.** The upstream archive does not
include a `LICENSE`, `NOTICE`, or `AUTHORS` file. The vendored copy is
included here on the working assumption that the SingularityNET /
OpenWater team has Ben's permission to ship it under the repo's
Apache-2.0 license while a formal license note is settled. **Do not
distribute the `oprow/` tree outside of this private repo** until that
note is in place. When Ben confirms the desired license, add it as
`LICENSE-OPROW` at the repo root and update this file.

## Updating the vendored copy

When a newer oprow snapshot arrives:

```bash
# from /home/ok/projects/asi-chain/snet/openwater/
unzip oprow_step14_benchmarks-<new-stamp>-N-NNN.zip -d oprow_step14_benchmarks
cd openwater-demo/
rm -rf oprow tests/oprow_upstream vendor/oprow_docs/README_STEP*.md vendor/oprow_docs/upstream_pyproject.toml
cp -a ../oprow_step14_benchmarks/oprow ./oprow
mkdir -p tests/oprow_upstream
cp -a ../oprow_step14_benchmarks/tests/. tests/oprow_upstream/
cp ../oprow_step14_benchmarks/README_STEP*.md vendor/oprow_docs/
cp ../oprow_step14_benchmarks/pyproject.toml vendor/oprow_docs/upstream_pyproject.toml
find oprow tests/oprow_upstream -type d \( -name __pycache__ -o -name .pytest_cache -o -name '*.egg-info' \) -prune -exec rm -rf {} +
find oprow tests/oprow_upstream -name '*.pyc' -delete
# update the "Source provenance" table above, then commit on main.
```

Do **not** edit files under `oprow/` directly. New behaviour goes into
`openwater_mk/` (orchestration) or as a new sibling module that imports
from `oprow`. The robust DCT/QIM profile shipped in
`openwater_mk/watermark_robust.py` is the reference pattern for adding
demo-level extensions on top of the vendored SDK.
