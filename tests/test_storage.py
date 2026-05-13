"""Tests for the pluggable manifest-store backends."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from openwater_mk import (
    FakeArweaveStore,
    FakeIPFSStore,
    LocalFileStore,
    detect_backend,
    store_from_spec,
)
from openwater_mk.cli import main as cli_main


# ---------------------------------------------------------------------------
# Unit-ish tests of each backend
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["local", "fake-arweave", "fake-ipfs"])
def test_backend_roundtrips_payload(tmp_path: Path, backend: str) -> None:
    store = store_from_spec(backend, root=tmp_path / "store")
    data = b"hello openwater " * 32
    key = store.put_bytes(data)
    fetched = store.get_bytes(key)
    assert fetched == data
    uri = store.storage_uri(key)
    assert "://" in uri


def test_fake_arweave_emits_43char_txid(tmp_path: Path) -> None:
    s = FakeArweaveStore(root=tmp_path)
    key = s.put_bytes(b"manifest-bytes")
    uri = s.storage_uri(key)
    scheme, _, txid = uri.partition("://")
    assert scheme == "ar"
    assert len(txid) == 43  # 32-byte sha256 -> base64url no padding


def test_fake_arweave_txid_is_deterministic(tmp_path: Path) -> None:
    """Same payload bytes always produce the same Arweave-shaped txid."""
    data = b"deterministic-manifest-bytes"
    s1 = FakeArweaveStore(root=tmp_path / "a")
    s2 = FakeArweaveStore(root=tmp_path / "b")
    s1.put_bytes(data)
    s2.put_bytes(data)
    k = s1.put_bytes(data)
    # Both stores compute the same txid because txid = base64url(sha256(data))
    assert s1.storage_uri(k).split("://", 1)[1] == s2.storage_uri(k).split("://", 1)[1]


def test_fake_ipfs_emits_cidv1_shape(tmp_path: Path) -> None:
    s = FakeIPFSStore(root=tmp_path)
    key = s.put_bytes(b"manifest-bytes")
    uri = s.storage_uri(key)
    scheme, _, cid = uri.partition("://")
    assert scheme == "ipfs"
    assert cid.startswith("b")  # multibase base32 prefix


def test_store_persists_across_instances(tmp_path: Path) -> None:
    """Writing with one instance, then re-opening, must keep the manifest readable."""
    data = b"persist-me " * 16
    s1 = FakeArweaveStore(root=tmp_path / "a")
    key = s1.put_bytes(data)
    s2 = FakeArweaveStore(root=tmp_path / "a")
    assert s2.get_bytes(key) == data
    assert s2.storage_uri(key) == s1.storage_uri(key)


def test_detect_backend(tmp_path: Path) -> None:
    LocalFileStore(root=tmp_path / "lf").put_bytes(b"x")
    FakeArweaveStore(root=tmp_path / "ar").put_bytes(b"x")
    FakeIPFSStore(root=tmp_path / "ip").put_bytes(b"x")
    assert detect_backend(tmp_path / "lf") == "local"
    assert detect_backend(tmp_path / "ar") == "fake-arweave"
    assert detect_backend(tmp_path / "ip") == "fake-ipfs"


# ---------------------------------------------------------------------------
# CLI-level end-to-end: sign-embed with each backend, verify against it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["local", "fake-arweave", "fake-ipfs"])
def test_sign_embed_then_verify_with_backend(tmp_path: Path, backend: str) -> None:
    """Storage-backend round-trip uses ``alpha_lsb`` so the full
    extraction+essence verification path is exercised. DCT-QIM profiles
    intentionally fail PED-IMG-1 binding under V0 exact-hash essence
    (see test_demo.py)."""
    workdir = tmp_path / backend.replace("-", "_")
    rc = cli_main(["sign-embed", "--profile", "alpha_lsb", "--storage", backend, "--out", str(workdir)])
    assert rc == 0
    assert (workdir / "storage_uri.txt").exists()
    uri = (workdir / "storage_uri.txt").read_text().strip()
    if backend == "local":
        assert uri.startswith("file://")
    elif backend == "fake-arweave":
        assert uri.startswith("ar://")
    elif backend == "fake-ipfs":
        assert uri.startswith("ipfs://")

    rc = cli_main([
        "verify",
        str(workdir / "watermarked.png"),
        "--profile", "alpha_lsb",
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
    ])
    assert rc == 0


def test_verify_walks_multiple_stores(tmp_path: Path) -> None:
    """Verify should resolve from a later store when the first store is empty.

    Models the production case where Arweave is the durable storage but
    IPFS is checked first as a cache.
    """
    # Sign+embed with fake-arweave only.
    workdir = tmp_path / "primary"
    cli_main(["sign-embed", "--profile", "alpha_lsb", "--storage", "fake-arweave", "--out", str(workdir)])

    # An empty IPFS store first, then the populated Arweave store.
    empty_ipfs = tmp_path / "empty_ipfs"
    FakeIPFSStore(root=empty_ipfs).put_bytes(b"unrelated")

    rc = cli_main([
        "verify",
        str(workdir / "watermarked.png"),
        "--profile", "alpha_lsb",
        "--manifest-store", str(empty_ipfs),
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
    ])
    assert rc == 0
