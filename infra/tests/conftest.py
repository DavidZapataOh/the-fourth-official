import shutil
from typing import Any

import pytest
from infra_helpers import INFRA, bicep_build

if shutil.which("az") is None:
    collect_ignore_glob = ["test_*.py"]


@pytest.fixture(scope="session")
def compiled_template() -> dict[str, Any]:
    return bicep_build(INFRA / "main.bicep")
