import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    ".azure",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".pyright",
    "coverage",
}
_SKIP_FILES = {"uv.lock", "pnpm-lock.yaml", ".DS_Store"}


def list_repo_files() -> list[Path]:
    found: list[Path] = []
    for directory, subdirs, names in os.walk(ROOT):
        subdirs[:] = [d for d in subdirs if d not in _SKIP_DIRS]
        found.extend(Path(directory) / n for n in names if n not in _SKIP_FILES)
    return found


@pytest.fixture(scope="session")
def repo_files() -> list[Path]:
    return list_repo_files()
