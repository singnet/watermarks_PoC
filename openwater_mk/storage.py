"""Pluggable manifest-store backends.

This module bridges OpenWater's V1 storage targets (Arweave, IPFS) to the
upstream oprow ``CASStore`` protocol. The default "fake" backends intentionally
do not make network calls: they emit realistic identifier shapes (Arweave txid,
IPFS CIDv1) and persist manifest bytes under a local fanout directory. Real
backends are opt-in and require local service/credential configuration.

This is the storage layer the OpenWater implementation-time-estimates
document recommends for V1: "use managed gateways for MVP; use simple
local keys; abstract backend interface." Swapping the fakes for real
network clients (``arweave-python-client``, ``ipfshttpclient``,
``requests`` against Pinata/Infura) is a localized change.

Backends:

- :class:`LocalFileStore`  — thin wrapper over oprow's ``FileCAS``
- :class:`FakeArweaveStore` — disk-backed; reports ``ar://<sha256-44>``
- :class:`FakeIPFSStore`    — disk-backed; reports ``ipfs://bafy...`` (CIDv1)
- :class:`ArweaveGatewayStore` — gateway read + external uploader command
- :class:`IPFSDaemonStore` — local IPFS daemon HTTP API
- :func:`store_from_spec`   — factory that parses ``backend://path`` URIs
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey
from oprow.resolution.cas import FileCAS


DEFAULT_HTTP_TIMEOUT_SECONDS = 60


def _urlopen_bytes(
    request: str | urllib.request.Request,
    *,
    timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> bytes:
    """Small urllib wrapper so tests can monkeypatch network calls cleanly."""
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _read_index(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValidationError(f"store index is not a JSON object: {path}")
    return {str(k): str(v) for k, v in raw.items()}


def _write_backend_marker(root: Path, backend: str) -> None:
    (root / "backend.json").write_text(json.dumps({"backend": backend}, indent=2))


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


BACKEND_NAMES = (
    "local",
    "fake-arweave",
    "fake-ipfs",
    "arweave-gateway",
    "ipfs-daemon",
)


def store_from_spec(backend: str, root: Path) -> ManifestStore:
    """Build a store given the backend name and a root directory."""
    if backend == "local":
        return LocalFileStore(root=root)
    if backend == "fake-arweave":
        return FakeArweaveStore(root=root)
    if backend == "fake-ipfs":
        return FakeIPFSStore(root=root)
    if backend == "arweave-gateway":
        return ArweaveGatewayStore(root=root)
    if backend == "ipfs-daemon":
        return IPFSDaemonStore(root=root)
    raise ValueError(
        f"unknown storage backend {backend!r}; expected one of {BACKEND_NAMES}"
    )


def detect_backend(root: Path) -> str:
    """Best-effort identification of an existing store directory."""
    root = Path(root)
    marker = root / "backend.json"
    if marker.exists():
        backend = str(json.loads(marker.read_text()).get("backend", ""))
        if backend in BACKEND_NAMES:
            return backend
        raise ValidationError(f"unknown backend marker {backend!r} at {marker}")
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
# Real-network adapters
# ---------------------------------------------------------------------------


ARWEAVE_TXID_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])")


def _extract_arweave_txid(text: str) -> str | None:
    """Extract an Arweave txid from uploader stdout/stderr."""
    for pattern in (
        r"ar://([A-Za-z0-9_-]{43})",
        r"https?://(?:www\.)?arweave\.net/([A-Za-z0-9_-]{43})",
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    match = ARWEAVE_TXID_RE.search(text)
    return match.group(1) if match else None


def _command_for_path(command: str, path: Path) -> list[str]:
    parts = shlex.split(command)
    if not parts:
        raise RuntimeError("OPENWATER_ARWEAVE_UPLOAD_COMMAND is empty")
    rendered = [part.replace("{path}", str(path)) for part in parts]
    if all("{path}" not in part for part in parts):
        rendered.append(str(path))
    return rendered


@dataclass
class ArweaveGatewayStore:
    """Real Arweave gateway-backed store.

    Reads use ``OPENWATER_ARWEAVE_GATEWAY_URL`` (default
    ``https://arweave.net``). Writes call ``OPENWATER_ARWEAVE_UPLOAD_COMMAND``;
    the command must print either ``ar://<txid>``, an Arweave gateway URL, or a
    bare 43-character txid. Use ``{path}`` in the command to control where the
    temporary manifest path is inserted; otherwise the path is appended.
    """

    root: Path
    gateway_url: str = field(default_factory=lambda: os.environ.get(
        "OPENWATER_ARWEAVE_GATEWAY_URL",
        "https://arweave.net",
    ))
    upload_command: str | None = field(default_factory=lambda: os.environ.get(
        "OPENWATER_ARWEAVE_UPLOAD_COMMAND"
    ))
    name: str = "arweave_gateway"
    _index: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "uploads").mkdir(parents=True, exist_ok=True)
        self._index = _read_index(self.root / "index.json")
        _write_backend_marker(self.root, "arweave-gateway")

    def _flush_index(self) -> None:
        (self.root / "index.json").write_text(json.dumps(self._index, indent=2))

    def put_bytes(self, data: bytes) -> ManifestKey:
        if not self.upload_command:
            raise RuntimeError(
                "Arweave upload requires OPENWATER_ARWEAVE_UPLOAD_COMMAND; "
                "set it to a funded uploader command that prints the txid"
            )
        key = ManifestKey.from_manifest_bytes(data)
        payload_path = self.root / "uploads" / f"{key.to_hex()}.cbor"
        payload_path.write_bytes(data)
        proc = subprocess.run(
            _command_for_path(self.upload_command, payload_path),
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "Arweave upload command failed "
                f"(rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
            )
        txid = _extract_arweave_txid(proc.stdout + "\n" + proc.stderr)
        if not txid:
            raise RuntimeError(
                "Arweave upload command did not print an ar:// URI, gateway URL, "
                "or bare 43-character txid"
            )
        self._index[txid] = key.to_hex()
        self._flush_index()
        return key

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        target = key.to_hex()
        for txid, hex_key in self._index.items():
            if hex_key != target:
                continue
            url = f"{self.gateway_url.rstrip('/')}/{urllib.parse.quote(txid)}"
            try:
                data = _urlopen_bytes(url)
            except urllib.error.URLError:
                return None
            if ManifestKey.from_manifest_bytes(data) == key:
                return data
        return None

    def storage_uri(self, key: ManifestKey) -> str:
        target = key.to_hex()
        for txid, hex_key in self._index.items():
            if hex_key == target:
                return f"ar://{txid}"
        raise ValidationError(f"no Arweave txid recorded for manifest {target}")


@dataclass
class IPFSDaemonStore:
    """Real IPFS reads/writes via a local daemon HTTP API.

    Writes call ``/api/v0/add?pin=true`` on ``OPENWATER_IPFS_API_URL``
    (default ``http://127.0.0.1:5001``). Reads use
    ``OPENWATER_IPFS_GATEWAY_URL`` first (default ``http://127.0.0.1:8080/ipfs``)
    and fall back to ``/api/v0/cat`` on the daemon.
    """

    root: Path
    api_url: str = field(default_factory=lambda: os.environ.get(
        "OPENWATER_IPFS_API_URL",
        "http://127.0.0.1:5001",
    ))
    gateway_url: str = field(default_factory=lambda: os.environ.get(
        "OPENWATER_IPFS_GATEWAY_URL",
        "http://127.0.0.1:8080/ipfs",
    ))
    name: str = "ipfs_daemon"
    _index: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._index = _read_index(self.root / "index.json")
        _write_backend_marker(self.root, "ipfs-daemon")

    def _flush_index(self) -> None:
        (self.root / "index.json").write_text(json.dumps(self._index, indent=2))

    def _api_endpoint(self, path: str, params: dict[str, str] | None = None) -> str:
        query = "" if not params else "?" + urllib.parse.urlencode(params)
        return f"{self.api_url.rstrip('/')}{path}{query}"

    def put_bytes(self, data: bytes) -> ManifestKey:
        key = ManifestKey.from_manifest_bytes(data)
        boundary = "----openwater-manifest-boundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="manifest.cbor"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("ascii") + data + f"\r\n--{boundary}--\r\n".encode("ascii")
        request = urllib.request.Request(
            self._api_endpoint("/api/v0/add", {"pin": "true"}),
            data=body,
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        raw = _urlopen_bytes(request)
        cid = _parse_ipfs_add_response(raw)
        self._index[cid] = key.to_hex()
        self._flush_index()
        return key

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        target = key.to_hex()
        for cid, hex_key in self._index.items():
            if hex_key != target:
                continue
            gateway_url = f"{self.gateway_url.rstrip('/')}/{urllib.parse.quote(cid)}"
            try:
                data = _urlopen_bytes(gateway_url)
            except urllib.error.URLError:
                cat_url = self._api_endpoint("/api/v0/cat", {"arg": cid})
                try:
                    data = _urlopen_bytes(cat_url)
                except urllib.error.URLError:
                    return None
            if ManifestKey.from_manifest_bytes(data) == key:
                return data
        return None

    def storage_uri(self, key: ManifestKey) -> str:
        target = key.to_hex()
        for cid, hex_key in self._index.items():
            if hex_key == target:
                return f"ipfs://{cid}"
        raise ValidationError(f"no IPFS CID recorded for manifest {target}")


def _parse_ipfs_add_response(raw: bytes) -> str:
    """Parse go-ipfs/kubo add JSON or NDJSON and return the final CID."""
    last: dict[str, Any] | None = None
    for line in raw.splitlines() or [raw]:
        if not line.strip():
            continue
        last = json.loads(line.decode("utf-8"))
    if not last or not last.get("Hash"):
        raise RuntimeError("IPFS add response did not include a Hash field")
    return str(last["Hash"])


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
