import json
import re
import subprocess
from pathlib import Path
from typing import Any

INFRA = Path(__file__).resolve().parents[1]


def bicep_build(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["az", "bicep", "build", "--file", str(path), "--stdout"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def resources(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Resources keyed by symbolic name, for both ARM language versions."""
    found = template["resources"]
    if isinstance(found, dict):
        return found
    return {str(i): r for i, r in enumerate(found)}


def resources_of_type(template: dict[str, Any], type_name: str) -> list[dict[str, Any]]:
    return [r for r in resources(template).values() if r["type"] == type_name]


def module_params(template: dict[str, Any], symbolic_name: str) -> dict[str, Any]:
    """Module parameter values; ternary expressions come back as their expression string."""
    deployment = resources(template)[symbolic_name]
    parameters = deployment["properties"]["parameters"]
    return {k: v if isinstance(v, str) else v.get("value") for k, v in parameters.items()}


def resolve(template: dict[str, Any], value: Any) -> Any:
    """Resolve a plain `[variables('name')]` reference; return other values unchanged."""
    if isinstance(value, str):
        match = re.fullmatch(r"\[variables\('([^']+)'\)\]", value)
        if match:
            return template["variables"][match.group(1)]
    return value
