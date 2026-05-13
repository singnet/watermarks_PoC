"""ASI:chain client boundary for OProW Step 11.

This module separates three concerns that are often conflated in blockchain SDKs:

1. **Anchor semantics**: OProW wants to publish a compact commitment.
2. **Rholang rendering**: the commitment is represented as a Rholang term.
3. **Chain transport/signing**: the term must be signed and submitted to DevNet.

The reference implementation includes:

* ``MockASIChainClient`` — deterministic, no-network test client.
* ``ASIChainHTTPClient`` — low-level HTTP reader/explorer client with endpoints
  for status, blocks, explore-deploy, and submitting already-signed deploy JSON.
* ``ASIChainExternalCLIClient`` — a practical DevNet adapter that shells out to
  the official Rust client or a compatible command line tool for signing and
  deploying Rholang contracts.

The HTTP client deliberately does not try to invent private-key signing.  ASI's
current DevNet docs point developers to the wallet/IDE and Rust CLI for contract
submission.  A later coding agent can swap in a first-party Python signer once
ASI:chain publishes a stable Python SDK or exact signed-deploy JSON schema.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from oprow.core.errors import ValidationError
from oprow.core.hashes import hash_framed

from .contracts import ASIAnchorPayload, render_anchor_source_term
from .receipts import ASIChainReceipt


DEFAULT_DEVNET_API_BASE_URL = "http://34.196.119.4:40403"
DEFAULT_DEVNET_GRPC_HOST = "34.196.119.4"
DEFAULT_DEVNET_GRPC_PORT = 40402
DEFAULT_DEVNET_EXPLORER_URL = "https://explorer.dev.asichain.io"
DEFAULT_DEVNET_INDEXER_GRAPHQL_URL = "https://indexer.dev.asichain.io/v1/graphql"


@dataclass(frozen=True)
class ASIChainNetworkConfig:
    """Connection settings for an ASI:chain network.

    The default values target public DevNet as documented in the ASI:chain docs.
    They can be overridden by environment variables so tests never accidentally
    submit live transactions.
    """

    network: str = "devnet"
    api_base_url: str = field(default_factory=lambda: os.environ.get("ASI_CHAIN_API_BASE_URL", DEFAULT_DEVNET_API_BASE_URL))
    explorer_base_url: str = DEFAULT_DEVNET_EXPLORER_URL
    indexer_graphql_url: str = DEFAULT_DEVNET_INDEXER_GRAPHQL_URL
    grpc_host: str = field(default_factory=lambda: os.environ.get("ASI_CHAIN_GRPC_HOST", DEFAULT_DEVNET_GRPC_HOST))
    grpc_port: int = field(default_factory=lambda: int(os.environ.get("ASI_CHAIN_GRPC_PORT", str(DEFAULT_DEVNET_GRPC_PORT))))
    # The docs show both /api/explore-deploy and /explore-deploy in different
    # places.  Keep the prefix configurable; the default follows the quick
    # command examples that use /explore-deploy.
    rest_api_prefix: str = field(default_factory=lambda: os.environ.get("ASI_CHAIN_REST_API_PREFIX", ""))
    request_timeout_seconds: float = 10.0

    def endpoint(self, path: str) -> str:
        prefix = self.rest_api_prefix.strip("/")
        clean = path.strip("/")
        if prefix:
            clean = f"{prefix}/{clean}"
        return self.api_base_url.rstrip("/") + "/" + clean


@dataclass(frozen=True)
class ASIChainDeployResult:
    """Raw result returned by an ASI client after trying to publish a term."""

    deploy_id: str | None
    transaction_hash: str | None
    raw_response: dict[str, Any]
    block_hash: str | None = None
    block_height: int | None = None


@runtime_checkable
class ASIChainClient(Protocol):
    """Transport boundary used by ``ASIChainTrustBackend``."""

    config: ASIChainNetworkConfig

    def publish_anchor_payload(self, payload: ASIAnchorPayload) -> ASIChainDeployResult: ...

    def verify_deploy_contains_anchor(self, receipt: ASIChainReceipt, payload: ASIAnchorPayload) -> bool: ...


class ASIChainHTTPError(RuntimeError):
    """Raised when a low-level DevNet HTTP call fails."""


@dataclass
class ASIChainHTTPClient:
    """Low-level HTTP access to an ASI:chain node.

    This client is intentionally conservative.  It can query status/blocks and
    submit a *pre-signed* deploy JSON payload, but it does not perform private-key
    signing.  Contract deployment with signing is delegated to
    ``ASIChainExternalCLIClient`` or the ASI wallet until a stable Python signing
    API exists.
    """

    config: ASIChainNetworkConfig = field(default_factory=ASIChainNetworkConfig)

    def _json_request(self, method: str, url: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method.upper())
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout_seconds) as response:  # noqa: S310 - caller controls endpoint
                raw = response.read()
        except urllib.error.URLError as exc:  # pragma: no cover - network disabled in tests
            raise ASIChainHTTPError(f"ASI:chain HTTP request failed: {url}: {exc}") from exc
        if not raw:
            return {}
        try:
            decoded = json.loads(raw.decode("utf-8"))
            return decoded if isinstance(decoded, dict) else {"value": decoded}
        except json.JSONDecodeError:
            return {"raw_text": raw.decode("utf-8", errors="replace")}

    def status(self) -> dict[str, Any]:
        return self._json_request("GET", self.config.endpoint("status"))

    def blocks(self) -> dict[str, Any]:
        return self._json_request("GET", self.config.endpoint("blocks"))

    def explore_deploy(self, term: str) -> dict[str, Any]:
        return self._json_request("POST", self.config.endpoint("explore-deploy"), {"term": term})

    def submit_signed_deploy(self, signed_deploy_json: Mapping[str, Any]) -> dict[str, Any]:
        return self._json_request("POST", self.config.endpoint("deploy"), signed_deploy_json)

    def publish_anchor_payload(self, payload: ASIAnchorPayload) -> ASIChainDeployResult:
        raise ASIChainHTTPError(
            "ASIChainHTTPClient cannot sign deploys. Use submit_signed_deploy() with an already-signed payload, "
            "ASIChainExternalCLIClient, or MockASIChainClient for tests."
        )

    def verify_deploy_contains_anchor(self, receipt: ASIChainReceipt, payload: ASIAnchorPayload) -> bool:
        # Without a stable transaction lookup schema this method checks only the
        # receipt's self-consistency.  The backend will already compare hashes.
        return receipt.anchored_record_hash.to_hex() == payload.record_hash_hex and receipt.anchored_object_hash.to_hex() == payload.object_hash_hex


@dataclass
class MockASIChainClient:
    """No-network ASI client used by tests and examples.

    It stores rendered Rholang terms in memory and returns deterministic deploy
    identifiers.  The object behaves like a chain adapter from the trust backend's
    perspective, which is exactly what we need before integrating real DevNet
    signing.
    """

    config: ASIChainNetworkConfig = field(default_factory=lambda: ASIChainNetworkConfig(network="mock-devnet", api_base_url="mock://asi-chain"))
    deployed_terms: dict[str, tuple[ASIAnchorPayload, str]] = field(default_factory=dict)

    def publish_anchor_payload(self, payload: ASIAnchorPayload) -> ASIChainDeployResult:
        term = render_anchor_source_term(payload)
        deploy_hash = hash_framed("oprow-asi-mock-deploy-v1", term.encode("utf-8"))
        deploy_id = "mock-deploy:" + deploy_hash.hex()[:32]
        tx_hash = "mock-tx:" + deploy_hash.hex()[32:64]
        self.deployed_terms[deploy_id] = (payload, term)
        return ASIChainDeployResult(
            deploy_id=deploy_id,
            transaction_hash=tx_hash,
            block_hash="mock-block:" + deploy_hash.hex()[:16],
            block_height=len(self.deployed_terms),
            raw_response={"mock": True, "deploy_id": deploy_id, "transaction_hash": tx_hash, "term": term},
        )

    def verify_deploy_contains_anchor(self, receipt: ASIChainReceipt, payload: ASIAnchorPayload) -> bool:
        if receipt.deploy_id is None:
            return False
        stored = self.deployed_terms.get(receipt.deploy_id)
        if stored is None:
            return False
        stored_payload, term = stored
        return (
            stored_payload.record_hash_hex == payload.record_hash_hex
            and stored_payload.object_hash_hex == payload.object_hash_hex
            and payload.record_hash_hex in term
            and payload.object_hash_hex in term
        )


@dataclass
class ASIChainExternalCLIClient:
    """DevNet deploy adapter using an external CLI for signing.

    The ASI docs currently point to a Rust client command like:

        cargo run -- deploy -f ./contract.rho --private-key <key> -H 34.196.119.4 -p 40402

    This class wraps that pattern.  It is "real" in the sense that it can invoke
    an installed CLI against DevNet, while keeping private-key handling out of
    the OProW Python SDK.  Tests do not call it.
    """

    private_key: str
    cli_command: tuple[str, ...] = ("cargo", "run", "--")
    config: ASIChainNetworkConfig = field(default_factory=ASIChainNetworkConfig)
    cwd: Path | None = None
    extra_args: tuple[str, ...] = ()
    timeout_seconds: float = 60.0

    def publish_anchor_payload(self, payload: ASIAnchorPayload) -> ASIChainDeployResult:  # pragma: no cover - requires external DevNet tooling
        term = render_anchor_source_term(payload)
        with tempfile.NamedTemporaryFile("w", suffix=".rho", prefix="oprow_anchor_", delete=False, encoding="utf-8") as f:
            f.write(term)
            contract_path = Path(f.name)
        try:
            cmd = [
                *self.cli_command,
                "deploy",
                "-f",
                str(contract_path),
                "--private-key",
                self.private_key,
                "-H",
                self.config.grpc_host,
                "-p",
                str(self.config.grpc_port),
                *self.extra_args,
            ]
            completed = subprocess.run(cmd, cwd=self.cwd, text=True, capture_output=True, timeout=self.timeout_seconds, check=False)
            raw_response = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "cmd": [cmd[0], "...", "--private-key", "<redacted>", "-H", self.config.grpc_host, "-p", str(self.config.grpc_port)],
            }
            if completed.returncode != 0:
                raise ASIChainHTTPError(f"ASI CLI deploy failed with exit code {completed.returncode}: {completed.stderr}")
            # The CLI output format may change.  Derive a stable local deploy id
            # from the term and output so the OProW receipt remains useful even
            # before a block monitor extracts an official transaction hash.
            synthetic = hash_framed("oprow-asi-cli-deploy-output-v1", term.encode("utf-8"), completed.stdout.encode("utf-8"), completed.stderr.encode("utf-8"))
            return ASIChainDeployResult(
                deploy_id="cli-deploy:" + synthetic.hex()[:32],
                transaction_hash=None,
                raw_response=raw_response,
            )
        finally:
            try:
                contract_path.unlink()
            except OSError:
                pass

    def verify_deploy_contains_anchor(self, receipt: ASIChainReceipt, payload: ASIAnchorPayload) -> bool:  # pragma: no cover - requires chain lookup
        # Until transaction lookup is wired, verify receipt hash consistency.  A
        # later implementation can use the explorer/indexer to fetch deploy term
        # by deploy id or block reference and compare its embedded payload.
        return receipt.anchored_record_hash.to_hex() == payload.record_hash_hex and receipt.anchored_object_hash.to_hex() == payload.object_hash_hex


def devnet_cli_client_from_env() -> ASIChainExternalCLIClient:
    """Build a CLI deployer from environment variables.

    Required:
      * ``ASI_CHAIN_PRIVATE_KEY``

    Optional:
      * ``ASI_CHAIN_CLI`` — shell-like command string is intentionally not
        parsed here; use a single executable path or set up a wrapper script.
      * ``ASI_CHAIN_GRPC_HOST`` and ``ASI_CHAIN_GRPC_PORT``
    """
    private_key = os.environ.get("ASI_CHAIN_PRIVATE_KEY")
    if not private_key:
        raise ValidationError("ASI_CHAIN_PRIVATE_KEY is required for DevNet CLI deployment")
    cli = os.environ.get("ASI_CHAIN_CLI")
    cli_command = (cli,) if cli else ("cargo", "run", "--")
    return ASIChainExternalCLIClient(private_key=private_key, cli_command=cli_command)
