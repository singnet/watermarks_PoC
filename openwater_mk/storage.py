"""Pluggable manifest-store backends.

This module bridges OpenWater's V1 storage targets (Arweave, IPFS) to the
upstream oprow ``CASStore`` protocol. The backends here intentionally do
not make network calls in their default ("fake") mode — they emit
realistic identifier shapes (Arweave txid, IPFS CIDv1) and persist the
manifest bytes under a local fanout directory.

This is the storage layer the OpenWater implementation-time-estimates
document recommends for V1: "use managed gateways for MVP; use simple
local keys; abstract backend interface." Swapping the fakes for real
network clients (``arweave-python-client``, ``ipfshttpclient``,
``requests`` against Pinata/Infura) is a localized change.

Backends:

- :class:`LocalFileStore`  — thin wrapper over oprow's ``FileCAS``
- :class:`FakeArweaveStore` — disk-backed; reports ``ar://<sha256-44>``
- :class:`FakeIPFSStore`    — disk-backed; reports ``ipfs://bafy...`` (CIDv1)
- :func:`store_from_spec`   — factory that parses ``backend://path`` URIs

Real-network variants are stubbed at the bottom of the file with the
exact wiring needed once credentials are available; they raise
``NotImplementedError`` today and are intentionally not on the V0->V1
critical path.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey
from oprow.resolution.cas import FileCAS


class ManifestStore(Protocol):
    """Common surface for openwater-mk manifest backends.

    Compatible with oprow's ``CASStore`` protocol (``put_bytes`` +
    ``get_bytes``), plus extra introspection helpers used by the CLI.
    """

    name: str

    def put_bytes(self, data: bytes) -> ManifestKey: ...
    def get_bytes(self, key: ManifestKey) -> bytes | None: ...
    def storage_uri(self, key: ManifestKey) -> str: ...


# ---------------------------------------------------------------------------
# Local file-system store (real, default)
# ---------------------------------------------------------------------------


@dataclass
class LocalFileStore:
    """Disk-backed CASStore. Identifies manifests by ``file://`` URI.

    Wraps oprow's ``FileCAS``. Same on-disk layout (two-char fanout).
    """

    root: Path
    name: str = "local_file"
    _cas: FileCAS = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self._cas = FileCAS(root=self.root)

    def put_bytes(self, data: bytes) -> ManifestKey:
        return self._cas.put_bytes(data)

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        return self._cas.get_bytes(key)

    def storage_uri(self, key: ManifestKey) -> str:
        return f"file://{self._cas.path_for_key(key).resolve()}"


# ---------------------------------------------------------------------------
# Fake Arweave store
# ---------------------------------------------------------------------------


def _arweave_txid(data: bytes) -> str:
    """Mint a realistic-looking Arweave txid (43-char base64url, no padding)."""
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass
class FakeArweaveStore:
    """Local-disk store that emits Arweave-shaped txids.

    Layout under ``root``:
      manifests/<txid>.bin       raw manifest bytes
      index.json                 { txid -> manifest_key_hex }

    Real Arweave integration replaces ``put_bytes`` with an
    ``arweave-python-client`` upload (needs a wallet + AR) and
    ``get_bytes`` with an HTTP GET from ``https://arweave.net/<txid>``.
    """

    root: Path
    name: str = "fake_arweave"
    _index: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        (self.root / "manifests").mkdir(parents=True, exist_ok=True)
        index_path = self.root / "index.json"
        if index_path.exists():
            self._index = json.loads(index_path.read_text())

    def _flush_index(self) -> None:
        (self.root / "index.json").write_text(json.dumps(self._index, indent=2))

    def put_bytes(self, data: bytes) -> ManifestKey:
        key = ManifestKey.from_manifest_bytes(data)
        txid = _arweave_txid(data)
        (self.root / "manifests" / f"{txid}.bin").write_bytes(data)
        self._index[txid] = key.to_hex()
        self._flush_index()
        return key

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        target = key.to_hex()
        for txid, hex_key in self._index.items():
            if hex_key == target:
                path = self.root / "manifests" / f"{txid}.bin"
                if path.exists():
                    return path.read_bytes()
        return None

    def storage_uri(self, key: ManifestKey) -> str:
        target = key.to_hex()
        for txid, hex_key in self._index.items():
            if hex_key == target:
                return f"ar://{txid}"
        raise ValidationError(f"no Arweave txid recorded for manifest {target}")


# ---------------------------------------------------------------------------
# Fake IPFS store
# ---------------------------------------------------------------------------


def _ipfs_cid_v1(data: bytes) -> str:
    """Mint a deterministic CIDv1-shaped identifier for a payload.

    Real CIDv1 = multibase('base32') + multihash(sha256(data)). We build the
    multihash manually:
      0x12 0x20 || sha256(data)             # multihash header + 32-byte digest
      0x01 0x70                              # CID v1 + dag-pb codec
    Then prefix with the multibase 'b' (lowercase base32) marker.
    """
    digest = hashlib.sha256(data).digest()
    multihash = bytes([0x12, 0x20]) + digest      # sha2-256 multihash
    cid_bytes = bytes([0x01, 0x70]) + multihash   # CIDv1, dag-pb codec
    b32 = base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")
    return "b" + b32


@dataclass
class FakeIPFSStore:
    """Local-disk store that emits IPFS CIDv1 identifiers.

    Layout under ``root``:
      blocks/<cid>.bin           raw manifest bytes
      index.json                 { cid -> manifest_key_hex }
    """

    root: Path
    name: str = "fake_ipfs"
    _index: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        (self.root / "blocks").mkdir(parents=True, exist_ok=True)
        index_path = self.root / "index.json"
        if index_path.exists():
            self._index = json.loads(index_path.read_text())

    def _flush_index(self) -> None:
        (self.root / "index.json").write_text(json.dumps(self._index, indent=2))

    def put_bytes(self, data: bytes) -> ManifestKey:
        key = ManifestKey.from_manifest_bytes(data)
        cid = _ipfs_cid_v1(data)
        (self.root / "blocks" / f"{cid}.bin").write_bytes(data)
        self._index[cid] = key.to_hex()
        self._flush_index()
        return key

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        target = key.to_hex()
        for cid, hex_key in self._index.items():
            if hex_key == target:
                path = self.root / "blocks" / f"{cid}.bin"
                if path.exists():
                    return path.read_bytes()
        return None

    def storage_uri(self, key: ManifestKey) -> str:
        target = key.to_hex()
        for cid, hex_key in self._index.items():
            if hex_key == target:
                return f"ipfs://{cid}"
        raise ValidationError(f"no IPFS CID recorded for manifest {target}")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


BACKEND_NAMES = ("local", "fake-arweave", "fake-ipfs")


def store_from_spec(backend: str, root: Path) -> ManifestStore:
    """Build a store given the backend name and a root directory."""
    if backend == "local":
        return LocalFileStore(root=root)
    if backend == "fake-arweave":
        return FakeArweaveStore(root=root)
    if backend == "fake-ipfs":
        return FakeIPFSStore(root=root)
    raise ValueError(
        f"unknown storage backend {backend!r}; expected one of {BACKEND_NAMES}"
    )


def detect_backend(root: Path) -> str:
    """Best-effort identification of an existing store directory."""
    root = Path(root)
    if (root / "index.json").exists() and (root / "manifests").is_dir():
        # disambiguate by manifests/ vs blocks/
        return "fake-arweave"
    if (root / "index.json").exists() and (root / "blocks").is_dir():
        return "fake-ipfs"
    # FileCAS uses two-char fanout directories at the root.
    if root.is_dir():
        return "local"
    raise ValidationError(f"no store found at {root}")


# ---------------------------------------------------------------------------
# Real-network adapters (intentionally not wired today)
# ---------------------------------------------------------------------------


@dataclass
class ArweaveGatewayStore:
    """Real Arweave reads via public gateway (``https://arweave.net/<txid>``).

    Not enabled today. Wiring:

        import requests
        def get_bytes(self, key):
            for txid in self._candidates(key):
                r = requests.get(f"https://arweave.net/{txid}", timeout=30)
                if r.ok and ManifestKey.from_manifest_bytes(r.content) == key:
                    return r.content
            return None

    Real writes require ``arweave-python-client`` and a funded wallet.
    """

    name: str = "arweave_gateway"

    def put_bytes(self, data: bytes) -> ManifestKey:  # pragma: no cover
        raise NotImplementedError("Arweave uploads require a funded wallet; see V1 doc")

    def get_bytes(self, key: ManifestKey) -> bytes | None:  # pragma: no cover
        raise NotImplementedError("hook up requests against arweave.net here")

    def storage_uri(self, key: ManifestKey) -> str:  # pragma: no cover
        raise NotImplementedError


@dataclass
class IPFSDaemonStore:
    """Real IPFS reads/writes via local daemon HTTP API (5001/5002).

    Not enabled today. Wiring (``ipfshttpclient`` or ``requests``):

        r = requests.post("http://127.0.0.1:5001/api/v0/add", files={"file": data})
        cid = r.json()["Hash"]

    Production should also pin via Pinata/web3.storage and use the
    ``https://w3s.link/ipfs/<cid>`` gateway for reads.
    """

    name: str = "ipfs_daemon"

    def put_bytes(self, data: bytes) -> ManifestKey:  # pragma: no cover
        raise NotImplementedError("IPFS daemon integration is V1+ work")

    def get_bytes(self, key: ManifestKey) -> bytes | None:  # pragma: no cover
        raise NotImplementedError

    def storage_uri(self, key: ManifestKey) -> str:  # pragma: no cover
        raise NotImplementedError


__all__ = [
    "ManifestStore",
    "LocalFileStore",
    "FakeArweaveStore",
    "FakeIPFSStore",
    "ArweaveGatewayStore",
    "IPFSDaemonStore",
    "BACKEND_NAMES",
    "store_from_spec",
    "detect_backend",
]
