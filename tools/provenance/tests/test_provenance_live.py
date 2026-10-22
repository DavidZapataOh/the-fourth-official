import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "provenance_verify_live", ROOT / "tools" / "provenance" / "verify.py"
)
assert spec and spec.loader
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

IMAGE = os.environ.get("FOURTH_PROVENANCE_IMAGE", "")
UNATTESTED = os.environ.get("FOURTH_PROVENANCE_UNATTESTED", "")
REPO = os.environ.get("FOURTH_PROVENANCE_REPO", "")
ARTIFACT = ROOT / "tools" / "provenance" / "image" / "hello.txt"
WORKFLOW = f"{REPO}/.github/workflows/provenance.yml"

pytestmark = pytest.mark.skipif(os.environ.get("FOURTH_LIVE") != "1", reason="live GitHub run")


@pytest.fixture(scope="module")
def offline_inputs(tmp_path_factory):
    """Bundle and trusted root for the file artifact, fetched while online."""
    directory = tmp_path_factory.mktemp("offline")
    subprocess.run(
        ["gh", "attestation", "download", str(ARTIFACT), "-R", REPO],
        cwd=directory, check=True, capture_output=True,
    )  # fmt: skip
    [bundle] = directory.glob("*.jsonl")
    root = directory / "trusted_root.jsonl"
    with root.open("wb") as handle:
        subprocess.run(["gh", "attestation", "trusted-root"], check=True, stdout=handle)
    return bundle, root


def test_online_verification_passes():
    result = verify.verify_image(IMAGE, REPO, signer_workflow=WORKFLOW)
    assert result.source_repository == f"https://github.com/{REPO}"
    assert result.source_ref == "refs/heads/main"
    assert result.signer_workflow.endswith("/.github/workflows/provenance.yml@refs/heads/main")
    assert IMAGE.endswith(result.subject_digest)


def test_offline_verification_passes_with_network_blocked(monkeypatch, offline_inputs):
    bundle, root = offline_inputs
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    result = verify.verify_image(str(ARTIFACT), REPO, bundle=bundle, trusted_root=root)
    assert result.source_repository == f"https://github.com/{REPO}"


def test_different_digest_is_rejected():
    with pytest.raises(verify.ProvenanceError):
        verify.verify_image(UNATTESTED, REPO)


def test_other_repository_is_rejected():
    with pytest.raises(verify.ProvenanceError):
        verify.verify_image(IMAGE, "octocat/Hello-World")


def test_altered_bundle_is_rejected(offline_inputs, tmp_path):
    bundle, root = offline_inputs
    data = bytearray(bundle.read_bytes())
    data[len(data) // 2] ^= 1
    altered = tmp_path / "altered.jsonl"
    altered.write_bytes(data)
    with pytest.raises(verify.ProvenanceError):
        verify.verify_image(str(ARTIFACT), REPO, bundle=altered, trusted_root=root)


def test_signer_workflow_mismatch_is_rejected():
    with pytest.raises(verify.ProvenanceError):
        verify.verify_image(IMAGE, REPO, signer_workflow=f"{REPO}/.github/workflows/ci.yml")
