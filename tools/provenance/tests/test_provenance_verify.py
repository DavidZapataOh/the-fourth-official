import importlib.util
import json
import stat
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("provenance_verify", HERE.parent / "verify.py")
assert spec and spec.loader
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

DIGEST = "2f4d334c66e35b62d53f77ab8425dd94e21d082a90bd927f51aa1cd61ce2d851"
REF = "oci://ghcr.io/davidzapataoh/the-fourth-official/provenance-demo@sha256:" + DIGEST
REPO = "DavidZapataOh/the-fourth-official"


@pytest.fixture
def gh(tmp_path):
    """A stand-in `gh` that records its arguments and replays a fixture."""

    def make(stdout: str = "", stderr: str = "", code: int = 0) -> tuple[str, Path]:
        calls = tmp_path / "calls.json"
        script = tmp_path / "gh"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"json.dump(sys.argv[1:], open({str(calls)!r}, 'w'))\n"
            f"sys.stdout.write({stdout!r})\n"
            f"sys.stderr.write({stderr!r})\n"
            f"sys.exit({code})\n"
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return str(script), calls

    return make


def ok_output() -> str:
    return (HERE / "fixtures" / "verify-ok.json").read_text()


def test_parses_certificate_fields_from_json(gh):
    executable, _ = gh(stdout=ok_output())
    result = verify.verify_image(REF, REPO, gh=executable)
    assert result == verify.Verification(
        source_repository="https://github.com/DavidZapataOh/the-fourth-official",
        source_ref="refs/heads/main",
        signer_workflow=(
            "https://github.com/DavidZapataOh/the-fourth-official"
            "/.github/workflows/provenance.yml@refs/heads/main"
        ),
        subject_digest="sha256:" + DIGEST,
        repository_id="1427833177",
    )


def test_raises_provenance_error_with_stderr_on_failure(gh):
    stderr = (HERE / "fixtures" / "verify-wrong-digest.stderr").read_text()
    executable, _ = gh(stderr=stderr, code=1)
    with pytest.raises(verify.ProvenanceError) as error:
        verify.verify_image(REF, REPO, gh=executable)
    assert "does not match the attested subject" in str(error.value)


def test_builds_online_command(gh):
    executable, calls = gh(stdout=ok_output())
    verify.verify_image(REF, REPO, gh=executable)
    assert json.loads(calls.read_text()) == [
        "attestation", "verify", REF, "-R", REPO, "--format", "json",
    ]  # fmt: skip


def test_builds_offline_command_with_bundle_and_trusted_root(gh, tmp_path):
    executable, calls = gh(stdout=ok_output())
    bundle, root = tmp_path / "b.jsonl", tmp_path / "root.jsonl"
    verify.verify_image(REF, REPO, gh=executable, bundle=bundle, trusted_root=root)
    arguments = json.loads(calls.read_text())
    assert arguments[-4:] == ["--bundle", str(bundle), "--custom-trusted-root", str(root)]


def test_adds_signer_workflow_when_requested(gh):
    executable, calls = gh(stdout=ok_output())
    verify.verify_image(
        REF, REPO, gh=executable, signer_workflow="owner/repo/.github/workflows/p.yml"
    )
    arguments = json.loads(calls.read_text())
    assert (
        arguments[arguments.index("--signer-workflow") + 1] == "owner/repo/.github/workflows/p.yml"
    )


@pytest.mark.parametrize("only", ["bundle", "trusted_root"])
def test_rejects_offline_arguments_given_separately(gh, tmp_path, only):
    executable, _ = gh(stdout=ok_output())
    with pytest.raises(ValueError, match="together"):
        verify.verify_image(REF, REPO, gh=executable, **{only: tmp_path / "x"})


def test_empty_result_list_is_an_error(gh):
    executable, _ = gh(stdout="[]")
    with pytest.raises(verify.ProvenanceError):
        verify.verify_image(REF, REPO, gh=executable)


def test_missing_certificate_field_is_an_error(gh):
    document = json.loads(ok_output())
    del document[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryRef"]
    executable, _ = gh(stdout=json.dumps(document))
    with pytest.raises(verify.ProvenanceError, match="sourceRepositoryRef"):
        verify.verify_image(REF, REPO, gh=executable)
