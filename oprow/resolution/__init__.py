"""Resolution and storage layer for OProW.

The resolver API returns candidate manifests.  It intentionally stops short of
claiming final provenance verification; the verification orchestrator combines
watermark/locator recovery, resolver output, manifest signatures, essence
matching, and trust policy into rich verification statuses.
"""

from .base import (
    CandidateValidationStatus,
    ResolutionCandidate,
    ResolutionRequest,
    ResolutionResult,
    ResolutionStatus,
    Resolver,
    ResolverDiagnosticEvent,
    ResolverError,
    candidate_from_document_bytes,
    deduplicate_candidates,
    filter_matching_candidates,
    result_from_candidates,
)
from .cas import CASResolver, CASStore, FileCAS, MemoryCAS
from .composite import CompositeResolver
from .embedded import EmbeddedManifestResolver
from .http import HTTPGatewayResolver
from .local import LocalPathResolver
from .short64 import Short64IndexResolver
from .short64_hv import Short64HVRouteResolver
from .authenticated_short64_hv import AuthenticatedShort64HVRouteResolver
from .privacy_short64_hv import PrivacyPreservingAuthenticatedShort64HVResolver, PrivacyAwareAuthenticatedShort64HVRouteResolver

__all__ = [name for name in globals() if not name.startswith("_")]
