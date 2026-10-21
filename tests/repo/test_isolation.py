import re
from pathlib import Path

PRIVATE_REFERENCES = [
    r"\bsprints?\b",
    r"PROYECTO",
    r"FICHA\.md",
    r"BRAND/",
    r"Rules\.txt",
    r"\.\./\.\./",
]
UNICODE_ALLOWED_DIRS = {"locales", "fixtures", "vectors", "testdata"}
TEXT_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".md",
    ".json",
    ".bicep",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    "",
}
NON_ENGLISH = re.compile("[áéíóúñÁÉÍÓÚÑ¿¡؀-ۿ]")


def text_files(repo_files: list[Path]):
    for path in repo_files:
        if path == Path(__file__).resolve() or path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            yield path, path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def test_no_private_references(repo_files: list[Path]):
    patterns = [re.compile(p, re.IGNORECASE) for p in PRIVATE_REFERENCES]
    hits = [
        f"{path}:{number}: {line.strip()}"
        for path, text in text_files(repo_files)
        for number, line in enumerate(text.splitlines(), 1)
        if any(p.search(line) for p in patterns)
    ]
    assert hits == []


def test_sources_are_english(repo_files: list[Path]):
    hits = [
        f"{path}:{number}: {line.strip()}"
        for path, text in text_files(repo_files)
        if not UNICODE_ALLOWED_DIRS & set(path.parts)
        for number, line in enumerate(text.splitlines(), 1)
        if NON_ENGLISH.search(line)
    ]
    assert hits == []
