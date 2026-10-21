import json
import re
import tomllib
from pathlib import Path

import yaml
from conftest import ROOT


def read(name: str) -> str:
    return (ROOT / name).read_text()


def test_license_is_apache_2():
    text = read("LICENSE")
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text


def test_required_files_exist():
    for name in ("NOTICE", "ASSETS.md", "README.md"):
        assert (ROOT / name).is_file(), name


def test_assets_table_header():
    assert "| Asset | Source | License | Attribution |" in read("ASSETS.md")


def test_gitignore_covers_secrets_and_artifacts():
    lines = {line.strip() for line in read(".gitignore").splitlines()}
    assert {".env", ".venv/", "node_modules/", ".azure/"} <= lines


def test_gitattributes_forces_lf():
    assert "* text=auto eol=lf" in read(".gitattributes")


def test_runtime_pins():
    assert read(".python-version").strip() == "3.13"
    assert read(".nvmrc").strip() == "24"


def test_no_env_file_present(repo_files: list[Path]):
    offenders = [
        p.name for p in repo_files if p.name.startswith(".env") and p.name != ".env.example"
    ]
    assert offenders == []


def test_python_workspace_layout():
    data = tomllib.loads(read("pyproject.toml"))
    assert data["tool"]["uv"]["workspace"]["members"] == ["libs/*/py"]
    assert data["project"]["requires-python"] == ">=3.13"
    assert data["tool"]["uv"]["package"] is False


def test_typescript_workspace_layout():
    workspace = yaml.safe_load(read("pnpm-workspace.yaml"))
    assert workspace["packages"] == ["libs/*/ts", "web/*"]
    package = json.loads(read("package.json"))
    assert package["private"] is True
    assert package["packageManager"].startswith("pnpm@")
    assert package["engines"]["node"] == ">=24"


MAKE_TARGETS = {
    "install", "check", "lint", "typecheck", "test",
    "install-py", "install-ts", "lint-py", "lint-ts",
    "typecheck-py", "typecheck-ts", "test-py", "test-ts",
}  # fmt: skip


def test_makefile_exposes_gates():
    targets = set(re.findall(r"^([a-z-]+):", read("Makefile"), re.MULTILINE))
    assert targets >= MAKE_TARGETS


def test_ci_is_least_privilege_and_pinned():
    workflow = yaml.safe_load(read(".github/workflows/ci.yml"))
    assert workflow["permissions"] == {"contents": "read"}
    uses = re.findall(r"uses:\s*(\S+)\s*(#.*)?$", read(".github/workflows/ci.yml"), re.MULTILINE)
    assert uses
    for ref, comment in uses:
        assert re.search(r"@[0-9a-f]{40}$", ref), ref
        assert re.match(r"# v\d+\.\d+\.\d+", comment), ref


def test_installs_use_frozen_lockfiles():
    makefile = read("Makefile")
    assert "uv sync --all-packages --frozen" in makefile
    assert "pnpm install --frozen-lockfile" in makefile


def test_dependabot_covers_ecosystems():
    config = yaml.safe_load(read(".github/dependabot.yml"))
    assert {u["package-ecosystem"] for u in config["updates"]} == {"github-actions", "uv", "npm"}


def test_adr_records_context_decision_consequences():
    text = read("docs/adr/0001-monorepo-with-two-toolchains.md")
    for heading in ("## Context", "## Decision", "## Consequences"):
        assert heading in text


def test_readme_quickstart_commands_exist_in_makefile():
    targets = set(re.findall(r"^([a-z-]+):", read("Makefile"), re.MULTILINE))
    used = set(re.findall(r"^make ([a-z-]+)$", read("README.md"), re.MULTILINE))
    assert used
    assert used <= targets
