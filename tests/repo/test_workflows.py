import re

import pytest
import yaml
from conftest import ROOT

WORKFLOWS = ROOT / ".github" / "workflows"
PINNED = re.compile(r"uses: [\w./-]+@[0-9a-f]{40}\s+# v\d+")


def workflow_files():
    return sorted(WORKFLOWS.glob("*.yml"))


def load(path):
    document = yaml.safe_load(path.read_text())
    document["on"] = document.pop(True, document.get("on"))  # YAML reads a bare `on` as True
    return document


@pytest.fixture(scope="module")
def provenance():
    return load(WORKFLOWS / "provenance.yml")


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_every_workflow_has_least_privilege_permissions(path):
    permissions = load(path).get("permissions")
    assert permissions is not None, "top-level permissions are required"
    assert set(permissions) <= {"contents"}
    assert permissions.get("contents", "read") == "read"


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_sha(path):
    uses = [line.strip() for line in path.read_text().splitlines() if "uses:" in line]
    assert uses
    for line in uses:
        assert PINNED.search(line), line


def test_provenance_workflow_permissions_are_exactly_the_documented_set(provenance):
    assert provenance["permissions"] == {}
    [job] = provenance["jobs"].values()
    assert job["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }


def test_provenance_workflow_is_manual_only(provenance):
    assert set(provenance["on"]) == {"workflow_dispatch"}


def test_provenance_job_is_named_build_and_attest(provenance):
    assert list(provenance["jobs"]) == ["build-and-attest"]


def test_dockerfile_has_no_latest_tag_and_a_non_root_user():
    text = (ROOT / "tools" / "provenance" / "image" / "Dockerfile").read_text()
    [base] = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert ":latest" not in base
    assert re.search(r"@sha256:[0-9a-f]{64}$", base)
    assert re.search(r"^USER (?!0\b|root\b)\S+", text, re.MULTILINE)
