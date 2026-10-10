import pytest

from codeguard.cwe import UNCLASSIFIED, CweGroupError, load_cwe_groups, normalize_cwe


@pytest.mark.parametrize(
    "raw, expected",
    [
        (78, "CWE-78"),
        ("78", "CWE-78"),
        ("CWE-78", "CWE-78"),
        ("cwe-078", "CWE-78"),
        ("CWE-78: Improper Neutralization of Special Elements used in an OS Command", "CWE-78"),
        (None, None),
        ("", None),
        ("not a cwe", None),
        (0, None),
        (True, None),
    ],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_real_file_loads(groups):
    assert len(groups.groups) > 10
    assert groups.group_of("CWE-78") == "os-command-injection"
    assert groups.group_of("CWE-89") == "sql-injection"
    assert groups.group_of("CWE-502") == "unsafe-deserialization"
    assert groups.group_of("CWE-327") == "weak-cryptography"


def test_groups_are_narrow(groups):
    # Different weaknesses must not share a group.
    assert groups.group_of("CWE-78") != groups.group_of("CWE-94")
    assert groups.group_of("CWE-89") != groups.group_of("CWE-78")
    assert groups.group_of("CWE-327") != groups.group_of("CWE-916")


def test_unknown_cwe_is_its_own_group(groups):
    assert groups.group_of("CWE-99999") == "CWE-99999"
    assert groups.group_of(None) == UNCLASSIFIED


def test_every_group_has_a_source(groups):
    for g in groups.groups:
        assert g.source.startswith("https://cwe.mitre.org/"), g.id


def test_cwe_in_two_groups_is_rejected(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text(
        "groups:\n"
        "  - {id: a, cwes: [CWE-78]}\n"
        "  - {id: b, cwes: [78]}\n",
        encoding="utf-8",
    )
    with pytest.raises(CweGroupError, match="CWE-78"):
        load_cwe_groups(p)


def test_missing_file_is_clear_error(tmp_path):
    with pytest.raises(CweGroupError, match="not found"):
        load_cwe_groups(tmp_path / "nope.yaml")
