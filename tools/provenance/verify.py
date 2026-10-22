"""Typed wrapper around `gh attestation verify` for container images."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProvenanceError(RuntimeError):
    """Raised when an image has no valid attestation. The message carries the CLI's stderr."""


@dataclass(frozen=True)
class Verification:
    source_repository: str
    source_ref: str
    signer_workflow: str
    subject_digest: str
    repository_id: str


def verify_image(  # noqa: PLR0913
    ref: str,
    repo: str,
    *,
    signer_workflow: str | None = None,
    bundle: Path | None = None,
    trusted_root: Path | None = None,
    gh: str = "gh",
) -> Verification:
    """Verify the build provenance of `ref` against `repo`.

    Passing `bundle` and `trusted_root` together verifies offline.
    """
    if (bundle is None) != (trusted_root is None):
        raise ValueError("bundle and trusted_root must be given together")
    command = [gh, "attestation", "verify", ref, "-R", repo, "--format", "json"]
    if signer_workflow:
        command += ["--signer-workflow", signer_workflow]
    if bundle and trusted_root:
        command += ["--bundle", str(bundle), "--custom-trusted-root", str(trusted_root)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ProvenanceError(result.stderr.strip())
    return _parse(result.stdout)


def _parse(output: str) -> Verification:
    attestations: list[dict[str, Any]] = json.loads(output)
    if not attestations:
        raise ProvenanceError("no attestation returned")
    try:
        verification = attestations[0]["verificationResult"]
        certificate = verification["signature"]["certificate"]
        digest = verification["statement"]["subject"][0]["digest"]["sha256"]
        return Verification(
            source_repository=certificate["sourceRepositoryURI"],
            source_ref=certificate["sourceRepositoryRef"],
            signer_workflow=certificate["buildSignerURI"],
            subject_digest=f"sha256:{digest}",
            repository_id=certificate["sourceRepositoryIdentifier"],
        )
    except (KeyError, IndexError) as error:
        raise ProvenanceError(f"unexpected verification output: missing {error}") from error
