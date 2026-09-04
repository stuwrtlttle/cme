from src.cwe_hierarchy import ancestor_cwes


def test_cwe_805_includes_its_parent() -> None:
    assert ancestor_cwes("CWE-805")[:2] == ["CWE-805", "CWE-119"]


def test_unknown_cwe_is_an_exact_only_lookup() -> None:
    assert ancestor_cwes("CWE-999999") == ["CWE-999999"]
