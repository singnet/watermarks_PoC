"""Tests for the pluggable manifest-store backends."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from openwater_mk import (
    ArweaveGatewayStore,
    FakeArweaveStore,
    FakeIPFSStore,
    IPFSDaemonStore,
    LocalFileStore,
    detect_backend,
    store_from_spec,
)
import openwater_mk.storage as storage_mod
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
    IPFSDaemonStore(root=tmp_path / "real_ip")
    ArweaveGatewayStore(root=tmp_path / "real_ar")
    assert detect_backend(tmp_path / "lf") == "local"
    assert detect_backend(tmp_path / "ar") == "fake-arweave"
    assert detect_backend(tmp_path / "ip") == "fake-ipfs"
    assert detect_backend(tmp_path / "real_ip") == "ipfs-daemon"
    assert detect_backend(tmp_path / "real_ar") == "arweave-gateway"


def test_ipfs_daemon_store_uses_api_and_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"manifest bytes from ipfs" * 8
    cid = "bafybeigdyrztfakecidopenwater"

    def fake_urlopen(request, *, timeout=60):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if "/api/v0/add" in url:
            assert b"manifest bytes from ipfs" in request.data
            return json_bytes({"Name": "manifest.cbor", "Hash": cid})
        if url.endswith(f"/ipfs/{cid}"):
            return data
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(storage_mod, "_urlopen_bytes", fake_urlopen)
    store = IPFSDaemonStore(
        root=tmp_path / "ipfs",
        api_url="http://127.0.0.1:5001",
        gateway_url="http://127.0.0.1:8080/ipfs",
    )
    key = store.put_bytes(data)
    assert store.storage_uri(key) == f"ipfs://{cid}"
    assert store.get_bytes(key) == data
    assert detect_backend(tmp_path / "ipfs") == "ipfs-daemon"


def test_arweave_gateway_store_uses_uploader_and_gateway(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"manifest bytes from arweave" * 8
    txid = "a" * 43

    class Proc:
        returncode = 0
        stdout = f"uploaded ar://{txid}\n"
        stderr = ""

    def fake_run(args, *, check, capture_output, text):
        assert check is False
        assert capture_output is True
        assert text is True
        payload_path = Path(args[-1])
        assert payload_path.read_bytes() == data
        return Proc()

    def fake_urlopen(request, *, timeout=60):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        assert url.endswith(f"/{txid}")
        return data

    monkeypatch.setattr(storage_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(storage_mod, "_urlopen_bytes", fake_urlopen)
    store = ArweaveGatewayStore(
        root=tmp_path / "ar",
        gateway_url="https://arweave.net",
        upload_command="fake-uploader {path}",
    )
    key = store.put_bytes(data)
    assert store.storage_uri(key) == f"ar://{txid}"
    assert store.get_bytes(key) == data
    assert detect_backend(tmp_path / "ar") == "arweave-gateway"


def test_arweave_gateway_requires_upload_command(tmp_path: Path) -> None:
    store = ArweaveGatewayStore(root=tmp_path / "ar", upload_command=None)
    with pytest.raises(RuntimeError, match="OPENWATER_ARWEAVE_UPLOAD_COMMAND"):
        store.put_bytes(b"manifest")


def json_bytes(value: dict[str, str]) -> bytes:
    import json
    return json.dumps(value).encode("utf-8")


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
