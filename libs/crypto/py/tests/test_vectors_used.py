import re
from pathlib import Path

CRYPTO = Path(__file__).resolve().parents[2]


def loads(name: str, text: str) -> bool:
    return re.search(rf'\bvectors\("{re.escape(name)}"\)', text) is not None


def test_matcher_requires_the_load_call() -> None:
    assert loads("jcs", 'V = vectors("jcs")')
    assert not loads("jcs", 'describe("jcs")')
    assert not loads("jcs", '# vectors("jcs2")')


def test_every_vector_file_is_loaded_by_both_suites() -> None:
    names = sorted(path.stem for path in (CRYPTO / "vectors").glob("*.json"))
    assert names
    for suite, suffix in (("py/tests", ".py"), ("ts/test", ".ts")):
        files = [p for p in (CRYPTO / suite).glob(f"*{suffix}") if "vectors_used" not in p.name]
        text = "\n".join(p.read_text(encoding="utf-8") for p in files)
        missing = [name for name in names if not loads(name, text)]
        assert not missing, f"{suite} does not load {missing}"
