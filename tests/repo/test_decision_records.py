import re

import pytest
from conftest import ROOT

RECORDS = sorted((ROOT / "docs" / "adr").glob("[0-9][0-9][0-9][0-9]-*.md"))
PLACEHOLDERS = {"", "tbd", "?", "todo", "n/a"}


def measured(path):
    """Records that carry a `## Measurements` table, which must be complete."""
    text = path.read_text()
    return text if re.search(r"^## Measurements$", text, re.MULTILINE) else None


def table_rows(text):
    section = text.split("## Measurements", 1)[1]
    section = re.split(r"^## ", section, maxsplit=1, flags=re.MULTILINE)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in row.strip("|").split("|")] for row in rows]


MEASURED = [(p, t) for p in RECORDS if (t := measured(p))]


@pytest.mark.parametrize(("path", "text"), MEASURED, ids=[p.name for p, _ in MEASURED])
def test_measurement_tables_are_complete(path, text):
    rows = table_rows(text)
    assert len(rows) > 2, f"{path.name}: table needs a header, a separator and data"
    for row in rows:
        for cell in row:
            assert cell.lower() not in PLACEHOLDERS, f"{path.name}: empty or placeholder cell"


@pytest.mark.parametrize(("path", "text"), MEASURED, ids=[p.name for p, _ in MEASURED])
def test_decisions_name_keep_or_fallback(path, text):
    match = re.search(r"^Decision: (keep|fallback)\b.+$", text, re.MULTILINE)
    assert match, f"{path.name}: missing `Decision: keep|fallback ...` line"


def test_adr_0004_exists_and_records_the_policy_hash():
    [path] = ROOT.glob("docs/adr/0004-*.md")
    text = path.read_text()
    assert re.search(r"\b[0-9a-f]{64}\b", text), "policy hash (64 hex characters) missing"
    assert "North Europe" in text


def test_adr_0005_records_certificate_fields():
    [path] = ROOT.glob("docs/adr/0005-*.md")
    text = path.read_text()
    for field in ("sourceRepositoryURI", "sourceRepositoryRef", "buildSignerURI"):
        assert field in text, field


def test_adr_0006_names_the_a2a_hosting_choice():
    [path] = ROOT.glob("docs/adr/0006-*.md")
    text = path.read_text()
    assert re.search(r"^Decision: keep .*A2A server.*Foundry", text, re.MULTILINE)
    paths = ("client_to_server", "foundry_to_server", "client_to_foundry", "foundry_to_mcp")
    for path_name in paths:
        assert path_name in text, path_name
