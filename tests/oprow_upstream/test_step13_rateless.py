from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

import numpy as np
from PIL import Image

from oprow import (
    Artifact,
    CASResolver,
    GenerationClaim,
    ManifestCore,
    ManifestLocator,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    RatelessAlphaLSBFull160Profile,
    RatelessEquationProfile,
    TrustPolicyStub,
    VerificationStatus,
    WatermarkPayload,
    WatermarkStrength,
    build_artifact_binding,
    create_signed_manifest,
    embed_manifest_locator,
    generate_ed25519_keypair,
    generate_equations_for_key,
    solve_gf2,
    solve_manifest_key_from_equations,
    verify_artifact_from_watermark,
)
from oprow.core.enums import SignatureRole
from oprow.rateless.gf2 import bytes_to_int_be
from oprow.rateless.records import RatelessTileRecord, encode_repeated_record, majority_decode_repeated_record

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_png(size=(256, 256), color=(82, 118, 180), stripe=(245, 230, 70)) -> bytes:
    img = Image.new("RGB", size, color=color)
    for x in range(size[0] // 8, size[0] - size[0] // 8):
        for y in range(size[1] // 2 - 10, size[1] // 2 + 10):
            img.putpixel((x, y), stripe)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class BuiltArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str
    profile: RatelessAlphaLSBFull160Profile


def build_signed_image(size=(256, 256)) -> BuiltArtifact:
    profile = RatelessAlphaLSBFull160Profile()
    artifact = Artifact.from_bytes(make_png(size=size), media_type="image/png")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id=profile.alg_id)
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id="step13-model")], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160_RATELESS)
    return BuiltArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid), profile)


def erase_first_n_tiles(artifact: Artifact, *, tile_size: int, n: int) -> Artifact:
    """Destroy alpha-LSB records in the first n tiles without changing RGB."""

    with Image.open(BytesIO(artifact.read_bytes())) as img:
        rgba = img.convert("RGBA")
    arr = np.asarray(rgba, dtype=np.uint8).copy()
    width, height = rgba.size
    erased = 0
    for ty in range(height // tile_size):
        for tx in range(width // tile_size):
            if erased >= n:
                break
            x0, y0 = tx * tile_size, ty * tile_size
            alpha = arr[y0 : y0 + tile_size, x0 : x0 + tile_size, 3]
            # Make the local carrier a constant all-zero LSB stream.  The tile
            # preamble and CRC will fail, so extraction treats it as an erasure.
            alpha[:] = alpha & 0xFE
            erased += 1
        if erased >= n:
            break
    out = Image.fromarray(arr, mode="RGBA")
    buf = BytesIO()
    out.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata=dict(artifact.metadata))


def test_gf2_solver_recovers_known_vector_from_identity_rows():
    value = 0b101101
    rows = [((1 << i), (value >> i) & 1) for i in range(6)]
    report = solve_gf2(rows, width=6)
    assert report.solved
    assert report.solution == value


def test_rateless_equations_recover_manifest_key_after_erasures():
    built = build_signed_image()
    profile = RatelessEquationProfile(equation_weight=41)
    key = built.signed.manifest_key()

    equations = generate_equations_for_key(key, count=360, profile=profile)
    # Simulate erasures: keep a deterministic subset rather than all generated
    # equations.  The decoder should still solve because more than 160
    # independent equations survive.
    survivors = [eq for i, eq in enumerate(equations) if i % 3 != 0]
    result = solve_manifest_key_from_equations(survivors, profile=profile)

    assert result.solved
    assert result.recovered_key == key
    assert result.solve_report.rank == 160
    assert result.equations_seen < len(equations)


def test_repeated_tile_record_corrects_one_bit_per_repetition_group():
    record = RatelessTileRecord(equation_id=123, rhs=1)
    bits = encode_repeated_record(record, repetitions=3)
    # Flip one copy of two different logical bits.  Majority decoding should
    # recover the record and report non-zero disagreements.
    bits[0] ^= 1
    bits[56 + 10] ^= 1
    decoded = majority_decode_repeated_record(bits, repetitions=3)
    assert decoded.record.equation_id == 123
    assert decoded.record.rhs == 1
    assert decoded.bit_disagreements == 2


def test_rateless_alpha_profile_embeds_and_extracts_full160_locator():
    built = build_signed_image(size=(256, 256))
    strength = WatermarkStrength(name="test-rateless", repetitions=3)

    embedded = embed_manifest_locator(
        built.artifact,
        built.signed,
        pointer_mode=PointerMode.FULL160_RATELESS,
        watermark_profile=built.profile,
        strength=strength,
    )
    extraction = built.profile.extract(embedded.artifact, strength=strength)

    assert extraction.extracted, extraction.error
    assert extraction.locator == built.locator
    assert extraction.diagnostics["rank"] == 160
    assert embedded.diagnostics["equations_embedded"] == 256


def test_rateless_alpha_profile_survives_tile_erasures_and_verifies():
    built = build_signed_image(size=(384, 384))
    strength = WatermarkStrength(name="test-rateless-erasure", repetitions=3)
    embedded = embed_manifest_locator(
        built.artifact,
        built.signed,
        pointer_mode=PointerMode.FULL160_RATELESS,
        watermark_profile=built.profile,
        strength=strength,
    )

    damaged = erase_first_n_tiles(embedded.artifact, tile_size=built.profile.tile_size, n=220)
    extraction = built.profile.extract(damaged, strength=strength)
    assert extraction.extracted, extraction.error
    assert extraction.locator == built.locator
    assert extraction.diagnostics["decode_failures"] >= 220
    assert extraction.diagnostics["rank"] == 160

    cas = MemoryCAS()
    cas.put_manifest(built.signed)
    report = verify_artifact_from_watermark(
        damaged,
        watermark_profile=built.profile,
        strength=strength,
        resolver=CASResolver([cas]),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert report.extraction.extracted
    assert report.verification is not None
    assert report.verification.status == VerificationStatus.VERIFIED
    assert report.verified
