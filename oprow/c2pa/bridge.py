"""Placeholder for integration with official C2PA SDKs.

The previous files define a self-contained C2PA-like model so the OProW reference
implementation can be tested without depending on a particular C2PA package. In
production, however, packaging and signing Content Credentials should be handed
to a maintained C2PA SDK.

This bridge module makes that future dependency explicit. It provides a small
adapter interface and a deliberately non-functional default implementation. A
coding agent can later implement ``PythonC2PASDKBridge`` against c2pa-python or
another official binding while leaving the rest of OProW unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from oprow.core.errors import UnsupportedAlgorithmError

from .models import C2PAManifest, C2PAManifestStore


class C2PASDKBridge(Protocol):
    """Protocol for a real C2PA SDK backend."""

    def package_manifest_store(self, store: C2PAManifestStore) -> bytes:
        """Return official C2PA Manifest Store bytes, e.g. JUMBF/crJSON/other."""
        ...

    def parse_manifest_store(self, data: bytes) -> C2PAManifestStore:
        """Parse official C2PA bytes into the Step 6 adapter model."""
        ...

    def sign_manifest(self, manifest: C2PAManifest) -> C2PAManifest:
        """Return a C2PA-signed manifest/store representation."""
        ...


@dataclass
class NullC2PASDKBridge:
    """Explicit no-op bridge used until an official SDK backend is wired in."""

    reason: str = "No official C2PA SDK backend configured for this Step 6 skeleton."

    def package_manifest_store(self, store: C2PAManifestStore) -> bytes:
        raise UnsupportedAlgorithmError(self.reason)

    def parse_manifest_store(self, data: bytes) -> C2PAManifestStore:
        raise UnsupportedAlgorithmError(self.reason)

    def sign_manifest(self, manifest: C2PAManifest) -> C2PAManifest:
        raise UnsupportedAlgorithmError(self.reason)
