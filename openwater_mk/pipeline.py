"""Pipeline operations exposed via the openwater CLI.

Composable on-disk operations:

- ``sign_and_embed`` writes a watermarked PNG + a persistent FileCAS-backed
  manifest store + a JSON key envelope.
- ``verify`` consumes those artifacts and returns a verification report.
- ``inspect_only`` extracts the locator from a watermarked PNG without
  attempting to resolve or verify.
- ``run_demo`` is the original in-process one-shot used by the test suite
  and the ``openwater demo`` subcommand.

The cryptography, essence hashing, and watermark all live in the upstream
oprow package. This module is glue.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, is_dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from PIL import Image

from oprow import (
    AlphaLSBImageWatermarkProfile,
    Artifact,
    CASResolver,
    DCTQIMImageWatermarkProfile,
    GenerationClaim,
    ManifestCore,
    ManifestKey,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    TrustPolicyStub,
    WatermarkProfile,
    WatermarkStrength,
    build_artifact_binding,
    create_signed_manifest,
    default_synthetic_image_corpus,
    embed_manifest_locator,
    extract_locator,
    generate_ed25519_keypair,
    verify_artifact_from_watermark,
)
from oprow.core.enums import SignatureRole
from oprow.core.identifiers import KeyId
from oprow.manifest.codec import (
    signed_manifest_from_bytes,
    signed_manifest_to_bytes,
)
from oprow.manifest.keys import (
    PrivateKeyRecord,
    PublicKeyRecord,
)
from oprow.resolution.cas import FileCAS

from .cardano import (
    AnchorRecord,
    AnchorReceipt,
    AnchorResult,
    AnchorVerification,
    MockCardanoBackend,
    _anchor_from_json,
    _anchor_to_json,
    publish_anchor,
    verify_anchor,
)
from .storage import (
    ManifestStore,
    detect_backend,
    store_from_spec,
)
from .transforms import TRANSFORMS


# ---------------------------------------------------------------------------
# Watermark profile selection
# ---------------------------------------------------------------------------


# Mapping of CLI-facing profile names to constructors. Tier 2's
# "dct_qim_robust" profile is registered from openwater_mk.watermark_robust
# at import time so this dict stays the single source of truth.
_PROFILE_FACTORIES: dict[str, Any] = {
    "alpha_lsb": AlphaLSBImageWatermarkProfile,
    "dct_qim":   DCTQIMImageWatermarkProfile,
}

DEFAULT_PROFILE = "dct_qim"
PROFILE_NAMES: tuple[str, ...] = ("alpha_lsb", "dct_qim", "dct_qim_robust")


def register_profile(name: str, factory: Any) -> None:
    """Register a watermark profile constructor under ``name``.

    Used by openwater_mk.watermark_robust to plug its profile in without a
    circular import.
    """
    _PROFILE_FACTORIES[name] = factory


def _resolve_profile(name: str) -> WatermarkProfile:
    try:
        return _PROFILE_FACTORIES[name]()
    except KeyError as exc:
        raise ValueError(
            f"unknown profile {name!r}; expected one of {sorted(_PROFILE_FACTORIES)}"
        ) from exc


def _default_strength(name: str, repetitions: int) -> WatermarkStrength:
    """Pick sensible per-profile defaults.

    Alpha-LSB has plenty of capacity (one bit per pixel) so a 3x repetition
    code is cheap. DCT-QIM only has one bit per 8x8 block; a 192x192 demo
    image is just 576 blocks, which is below the 744-bit framed payload at
    reps=3, so we run reps=1 there and lean on a larger qim_delta + (for
    the robust variant) spectral spreading.
    """
    if name == "alpha_lsb":
        return WatermarkStrength(name="demo-alpha-lsb", repetitions=repetitions)
    if name == "dct_qim":
        return WatermarkStrength(name="demo-dct-qim", repetitions=1, qim_delta=64.0)
    if name == "dct_qim_robust":
        return WatermarkStrength(name="demo-dct-qim-robust", repetitions=1, qim_delta=56.0)
    raise ValueError(f"unknown profile {name!r}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if is_dataclass(obj):
        return _to_jsonable(asdict(obj))
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def _load_artifact(path: Path | None) -> Artifact:
    if path is None:
        return default_synthetic_image_corpus()[0]
    media_type = "image/jpeg" if path.suffix.lower() in {".jpg", ".jpeg"} else "image/png"
    return Artifact.from_bytes(path.read_bytes(), media_type=media_type)


def _tamper_rgb(png_bytes: bytes) -> bytes:
    """Mutate the visible RGB content while leaving the alpha channel intact.

    Used by ``run_demo(tamper=True)`` to demonstrate the security boundary:
    the alpha-channel locator survives, but the manifest's PED-IMG-1 essence
    binding rejects the modified RGB content.
    """
    img = Image.open(BytesIO(png_bytes)).convert("RGBA")
    w, h = img.size
    pixels = img.load()
    cx0, cy0 = w // 4, h // 4
    cx1, cy1 = (3 * w) // 4, (3 * h) // 4
    for x in range(cx0, cx1):
        for y in range(cy0, cy1):
            r, g, b, a = pixels[x, y]
            pixels[x, y] = (255 - r, 255 - g, 255 - b, a)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Key serialization (reference format; not a production storage recommendation)
# ---------------------------------------------------------------------------


def _key_to_envelope(key: PrivateKeyRecord) -> dict[str, Any]:
    return {
        "schema": "openwater-mk/key-envelope/v0",
        "kid": str(key.kid),
        "alg": key.alg,
        "private_key_hex": key.private_key_bytes.hex(),
        "private_key_encoding": key.private_key_encoding,
        "public_key_hex": key.public.public_key_bytes.hex(),
        "public_key_encoding": key.public.encoding,
        "roles": list(key.public.roles),
        "created_at": (key.created_at or datetime.now(timezone.utc)).isoformat(),
    }


def _key_from_envelope(env: dict[str, Any]) -> PrivateKeyRecord:
    if env.get("schema") != "openwater-mk/key-envelope/v0":
        raise ValueError(f"unrecognized key envelope schema: {env.get('schema')!r}")
    return PrivateKeyRecord(
        public=_public_from_envelope(env),
        private_key_bytes=bytes.fromhex(env["private_key_hex"]),
        private_key_encoding=env["private_key_encoding"],
    )


def _public_from_envelope(env: dict[str, Any]) -> PublicKeyRecord:
    return PublicKeyRecord(
        kid=KeyId(env["kid"]),
        alg=env["alg"],
        public_key_bytes=bytes.fromhex(env["public_key_hex"]),
        encoding=env["public_key_encoding"],
        roles=tuple(env.get("roles", ())),
    )


# ---------------------------------------------------------------------------
# Result envelopes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignEmbedResult:
    watermarked_path: Path
    manifest_store: Path
    manifest_store_backend: str
    manifest_key_hex: str
    storage_uri: str
    key_path: Path
    diagnostics: dict[str, Any]


@dataclass(frozen=True)
class VerifyResult:
    verified: bool
    extraction_status: str
    verification_status: str | None
    locator_mode: str | None
    report: dict[str, Any]


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def sign_and_embed(
    *,
    input_path: Path | None,
    out_dir: Path,
    storage_backend: str = "local",
    pointer_mode: PointerMode = PointerMode.FULL160,
    model_id: str = "openwater-demo",
    repetitions: int = 3,
    profile: str = DEFAULT_PROFILE,
) -> SignEmbedResult:
    """Sign a manifest, embed the locator, persist key + manifest + image.

    Outputs under ``out_dir``:

    - ``watermarked.png``       — embedded artifact
    - ``key.json``              — Ed25519 keypair envelope (private + public)
    - ``manifests/``            — manifest store (backend-specific layout)
    - ``manifest_key.txt``      — hex of the manifest's ManifestKey
    - ``storage_uri.txt``       — backend-specific URI (file://, ar://, ipfs://)

    ``storage_backend`` may be ``"local"`` (default), ``"fake-arweave"``, or
    ``"fake-ipfs"``. See :mod:`openwater_mk.storage`.

    ``profile`` selects the watermark carrier; see ``PROFILE_NAMES``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    artifact = _load_artifact(input_path)
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    wm_profile = _resolve_profile(profile)

    binding = build_artifact_binding(artifact, wm_alg_id=wm_profile.alg_id)
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id=model_id)],
        created_at=datetime.now(timezone.utc),
    )
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)])

    strength = _default_strength(profile, repetitions)
    embedded = embed_manifest_locator(
        artifact, signed,
        pointer_mode=pointer_mode,
        watermark_profile=wm_profile,
        strength=strength,
    )

    watermarked_path = out_dir / "watermarked.png"
    watermarked_path.write_bytes(embedded.artifact.read_bytes())

    cas_root = out_dir / "manifests"
    store = store_from_spec(storage_backend, root=cas_root)
    manifest_key = store.put_bytes(signed_manifest_to_bytes(signed))
    storage_uri = store.storage_uri(manifest_key)

    (out_dir / "manifest_key.txt").write_text(manifest_key.to_hex() + "\n")
    (out_dir / "storage_uri.txt").write_text(storage_uri + "\n")

    key_envelope = _key_to_envelope(key)
    key_path = out_dir / "key.json"
    key_path.write_text(json.dumps(key_envelope, indent=2))

    return SignEmbedResult(
        watermarked_path=watermarked_path,
        manifest_store=cas_root,
        manifest_store_backend=storage_backend,
        manifest_key_hex=manifest_key.to_hex(),
        storage_uri=storage_uri,
        key_path=key_path,
        diagnostics=_to_jsonable(embedded.diagnostics),
    )


def embed_only(
    *,
    input_path: Path,
    manifest_store: Path,
    manifest_key_hex: str,
    out_dir: Path,
    storage_backend: str | None = None,
    pointer_mode: PointerMode = PointerMode.FULL160,
    repetitions: int = 3,
    profile: str = DEFAULT_PROFILE,
) -> Path:
    """Embed a pre-existing signed manifest's locator into a new artifact.

    Useful when the manifest store already holds the signed manifest (for
    example because ``sign_and_embed`` was run earlier or a manifest was
    fetched from Arweave) and the caller only wants to mark another image
    with the same locator.

    Returns the path of the watermarked PNG.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    backend = storage_backend or detect_backend(Path(manifest_store))
    store = store_from_spec(backend, root=Path(manifest_store))
    key = ManifestKey.from_hex(manifest_key_hex)
    data = store.get_bytes(key)
    if data is None:
        raise FileNotFoundError(f"manifest {manifest_key_hex} not in {manifest_store}")
    signed = signed_manifest_from_bytes(data)

    artifact = _load_artifact(input_path)
    wm_profile = _resolve_profile(profile)
    strength = _default_strength(profile, repetitions)
    embedded = embed_manifest_locator(
        artifact, signed,
        pointer_mode=pointer_mode,
        watermark_profile=wm_profile,
        strength=strength,
    )
    out = out_dir / "watermarked.png"
    out.write_bytes(embedded.artifact.read_bytes())
    return out


def verify(
    *,
    watermarked_path: Path,
    manifest_stores: list[Path | tuple[str, Path]] | Path,
    key_envelope_path: Path,
    accepted_roles: tuple[str, ...] = ("tool",),
    profile: str = DEFAULT_PROFILE,
) -> VerifyResult:
    """Verify a watermarked PNG against one or more persistent manifest stores.

    ``manifest_stores`` accepts:

    - a single ``Path`` (backend auto-detected),
    - a list of ``Path`` (each backend auto-detected),
    - a list of ``(backend_name, Path)`` tuples for explicit control.

    ``profile`` selects the watermark carrier used at extraction; must match
    the profile used at embed time.
    """
    media_type = "image/jpeg" if watermarked_path.suffix.lower() in {".jpg", ".jpeg"} else "image/png"
    artifact = Artifact.from_bytes(watermarked_path.read_bytes(), media_type=media_type)

    envelope = json.loads(key_envelope_path.read_text())
    public = _public_from_envelope(envelope)

    wm_profile = _resolve_profile(profile)
    strength = _default_strength(profile, repetitions=3)

    if isinstance(manifest_stores, (str, Path)):
        items: list[Path | tuple[str, Path]] = [Path(manifest_stores)]
    else:
        items = list(manifest_stores)

    stores: list[ManifestStore] = []
    descriptors: list[dict[str, str]] = []
    for item in items:
        if isinstance(item, tuple):
            backend, root = item
        else:
            root = Path(item)
            backend = detect_backend(root)
        store = store_from_spec(backend, root=Path(root))
        stores.append(store)
        descriptors.append({"backend": backend, "root": str(root), "name": store.name})

    report = verify_artifact_from_watermark(
        artifact,
        watermark_profile=wm_profile,
        strength=strength,
        resolver=CASResolver(stores),
        key_resolver=MemoryKeyRegistry.from_public_keys([public]),
        trust_policy=TrustPolicyStub(
            trusted_key_ids={str(public.kid)},
            accepted_roles=set(accepted_roles),
        ),
    )

    return VerifyResult(
        verified=report.verified,
        extraction_status=report.extraction.status.value,
        verification_status=(
            report.verification.status.value if report.verification else None
        ),
        locator_mode=(
            report.extraction.locator.mode.value
            if report.extraction.locator else None
        ),
        report={
            "watermarked_path": str(watermarked_path),
            "manifest_stores": descriptors,
            "key_id": str(public.kid),
            "extraction_status": report.extraction.status.value,
            "verification_status": (
                report.verification.status.value if report.verification else None
            ),
            "locator_mode": (
                report.extraction.locator.mode.value
                if report.extraction.locator else None
            ),
            "verified": report.verified,
        },
    )


def anchor_sign_embed_output(
    *,
    sign_embed_dir: Path,
    cardano_dir: Path,
    epoch: int = 0,
    record_type: str = "manifest_root",
) -> AnchorResult:
    """Anchor a ``sign-embed`` output directory on the (mock) Cardano backend.

    Reads:
      ``sign_embed_dir/manifest_key.txt``   subject id + root hash
      ``sign_embed_dir/storage_uri.txt``    off-chain storage reference
      ``sign_embed_dir/key.json``           operator kid

    Writes under ``cardano_dir``:
      ``ledger.json``           the mock Cardano ledger (append-only)
      ``anchor_record.json``    canonical anchor record
      ``receipt.json``          chain-agnostic anchor receipt
      ``metadata.json``         CBOR-friendly metadata payload as submitted
    """
    cardano_dir.mkdir(parents=True, exist_ok=True)

    manifest_key_hex = (sign_embed_dir / "manifest_key.txt").read_text().strip()
    subject_id = bytes.fromhex(manifest_key_hex)
    root_hash = hashlib_sha256_of_hex(manifest_key_hex)

    storage_uri = (sign_embed_dir / "storage_uri.txt").read_text().strip()
    ar_ref = storage_uri if storage_uri.startswith("ar://") else None
    ip_ref = storage_uri if storage_uri.startswith("ipfs://") else None

    key_env = json.loads((sign_embed_dir / "key.json").read_text())
    operator_kid = str(key_env["kid"])

    record = AnchorRecord(
        record_type=record_type,
        subject_id=subject_id,
        epoch=epoch,
        root_hash=root_hash,
        operator_kid=operator_kid,
        ar_ref=ar_ref,
        ip_ref=ip_ref,
    )

    backend = MockCardanoBackend(ledger_path=cardano_dir / "ledger.json")
    return publish_anchor(record=record, backend=backend, out_dir=cardano_dir)


def verify_anchor_dir(
    *,
    cardano_dir: Path,
    min_confirmations: int = 1,
) -> AnchorVerification:
    """Re-verify an anchor by reading the artifacts produced above."""
    record = _anchor_from_json(json.loads((cardano_dir / "anchor_record.json").read_text()))
    receipt = AnchorReceipt.from_json(json.loads((cardano_dir / "receipt.json").read_text()))
    backend = MockCardanoBackend(ledger_path=cardano_dir / "ledger.json")
    return verify_anchor(
        record=record,
        receipt=receipt,
        backend=backend,
        min_confirmations=min_confirmations,
    )


def hashlib_sha256_of_hex(hex_str: str) -> bytes:
    import hashlib
    return hashlib.sha256(hex_str.encode("ascii")).digest()


def inspect_only(*, watermarked_path: Path, profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
    """Extract the locator from a watermarked image without verifying.

    Useful for debugging carriers and for showing that locator recovery
    alone is not proof of provenance. ``profile`` must match the profile
    used at embed time.
    """
    media_type = "image/jpeg" if watermarked_path.suffix.lower() in {".jpg", ".jpeg"} else "image/png"
    artifact = Artifact.from_bytes(watermarked_path.read_bytes(), media_type=media_type)
    wm_profile = _resolve_profile(profile)
    strength = _default_strength(profile, repetitions=3)
    result = extract_locator(
        artifact, watermark_profile=wm_profile, strength=strength,
    )
    return {
        "watermarked_path": str(watermarked_path),
        "status": result.status.value,
        "locator_mode": result.locator.mode.value if result.locator else None,
        "locator_hex": (
            result.locator.value.to_hex()
            if result.locator and hasattr(result.locator.value, "to_hex")
            else (str(result.locator.value) if result.locator else None)
        ),
    }


def run_demo(
    *,
    input_path: Path | None = None,
    out_dir: Path = Path("out"),
    tamper: bool = False,
    transform: str | None = None,
    profile: str = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """In-process one-shot pipeline used by ``openwater demo`` and tests.

    See :func:`sign_and_embed` + :func:`verify` for the cross-process
    equivalent that goes through disk.
    """
    if tamper and transform:
        raise ValueError("tamper and transform are mutually exclusive")
    out_dir.mkdir(parents=True, exist_ok=True)

    artifact = _load_artifact(input_path)
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    wm_profile = _resolve_profile(profile)

    binding = build_artifact_binding(artifact, wm_alg_id=wm_profile.alg_id)
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="openwater-demo")],
        created_at=datetime.now(timezone.utc),
    )
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)])

    strength = _default_strength(profile, repetitions=3)
    embedded = embed_manifest_locator(
        artifact, signed,
        pointer_mode=PointerMode.FULL160,
        watermark_profile=wm_profile,
        strength=strength,
    )

    watermarked_path = out_dir / "watermarked.png"
    watermarked_path.write_bytes(embedded.artifact.read_bytes())

    verify_input = embedded.artifact
    tampered_path: Path | None = None
    transformed_path: Path | None = None
    if tamper:
        tampered_bytes = _tamper_rgb(embedded.artifact.read_bytes())
        tampered_path = out_dir / "tampered.png"
        tampered_path.write_bytes(tampered_bytes)
        verify_input = Artifact.from_bytes(tampered_bytes, media_type="image/png")
    elif transform:
        tx = TRANSFORMS[transform]
        verify_input = tx.apply(embedded.artifact)
        ext = "jpg" if verify_input.media_type == "image/jpeg" else "png"
        transformed_path = out_dir / f"transformed_{transform}.{ext}"
        transformed_path.write_bytes(verify_input.read_bytes())

    cas = MemoryCAS()
    cas.put_manifest(signed)
    report = verify_artifact_from_watermark(
        verify_input,
        watermark_profile=wm_profile,
        strength=strength,
        resolver=CASResolver([cas]),
        key_resolver=MemoryKeyRegistry.from_public_keys([key.public]),
        trust_policy=TrustPolicyStub(
            trusted_key_ids={str(key.kid)},
            accepted_roles={"tool"},
        ),
    )

    out = {
        "input": str(input_path) if input_path else "synthetic",
        "tampered": tamper,
        "transform": transform,
        "profile": profile,
        "watermarked_path": str(watermarked_path),
        "tampered_path": str(tampered_path) if tampered_path else None,
        "transformed_path": str(transformed_path) if transformed_path else None,
        "key_id": str(key.kid),
        "pointer_mode": PointerMode.FULL160.value,
        "watermark_alg_id": wm_profile.alg_id,
        "extraction_status": report.extraction.status.value,
        "locator_mode": (
            report.extraction.locator.mode.value
            if report.extraction.locator else None
        ),
        "verification_status": (
            report.verification.status.value if report.verification else None
        ),
        "verified": report.verified,
        "embed_diagnostics": _to_jsonable(embedded.diagnostics),
    }
    (out_dir / "verify_report.json").write_text(json.dumps(out, indent=2, default=str))
    return out
