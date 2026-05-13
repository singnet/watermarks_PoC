"""OProW exception hierarchy.

A provenance verifier should eventually be able to map low-level failures to
clear statuses such as ``MANIFEST_KEY_MISMATCH`` or ``NO_VALID_SIGNATURES``.
Step 1 therefore defines semantic exceptions rather than letting incidental
``ValueError``/``KeyError`` exceptions leak across module boundaries.
"""

from __future__ import annotations


class OProWError(Exception):
    """Base class for OProW-specific errors."""


class CanonicalizationError(OProWError):
    """Raised when an object cannot be deterministically serialized."""


class IdentifierError(OProWError):
    """Raised when a typed identifier has invalid length or encoding."""


class UnsupportedAlgorithmError(OProWError):
    """Raised when an algorithm/profile ID is known but unavailable."""


class ValidationError(OProWError):
    """Raised when a protocol dataclass is structurally inconsistent."""
