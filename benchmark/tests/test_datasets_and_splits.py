"""Dataset parsing (task IDs, target CWEs, pinning) and the fixed calibration / test split."""

import json

import pytest

from benchmark import datasets, splits
from benchmark.datasets import DatasetError, parse_jsonl, task_cwes, task_id


def row(raw_id="CWE-20_01", **extra):
    base = {
        "ID": raw_id,
        "Problem": "p",
        "Insecure Code": "def f(): pass",
        "Secure Code": "def f(): pass",
        "Test": "def check(c): pass",
        "Test-FP": "def check(c): pass",
        "Test-SP": "def check(c): pass",
        "Entry_Point": " f ",
    }
    return json.dumps({**base, **extra})


def test_task_ids_become_safe_file_names():
    assert task_id("CWE-502_codeql_1.py") == "CWE-502_codeql_1"
    assert task_id("CWE-862/CWE-287/CWE-306/CWE-863_01") == "CWE-862+CWE-287+CWE-306+CWE-863_01"


def test_target_cwes_come_from_the_id():
    assert task_cwes("CWE-020_author_1") == ("CWE-20",)
    assert task_cwes("CWE-78_03") == ("CWE-78",)
    assert task_cwes("CWE-862+CWE-287+CWE-306+CWE-863_01") == ("CWE-862", "CWE-287", "CWE-306", "CWE-863")
    with pytest.raises(DatasetError):
        task_cwes("no-cwe_here")


def test_parse_jsonl_reads_every_field():
    [task] = parse_jsonl(row("CWE-089_author_1.py") + "\n\n", "SecEvalBase")
    assert task.id == "CWE-089_author_1" and task.cwes == ("CWE-89",)
    assert task.entry_point == "f" and task.subset == "SecEvalBase"


def test_parse_jsonl_reports_the_bad_line():
    with pytest.raises(DatasetError, match="line 2"):
        parse_jsonl(row() + "\n" + json.dumps({"ID": "CWE-1_1"}), "x")


def test_the_dataset_is_pinned_to_a_commit_and_hashes():
    spec = datasets.CODESECEVAL
    assert len(spec.revision) == 40
    assert all(len(sha) == 64 for _, sha in spec.files.values())


def test_a_changed_file_is_refused(tmp_path):
    f = tmp_path / "x.jsonl"
    f.write_text("changed", encoding="utf-8")
    with pytest.raises(DatasetError, match="not the pinned version"):
        datasets._verify(f, "0" * 64, "SecEvalBase")


IDS = [f"CWE-{i}_01" for i in range(1, 256)]


def test_split_is_20_80_disjoint_and_deterministic():
    a = splits.make_split("d", "rev", IDS)
    b = splits.make_split("d", "rev", list(reversed(IDS)))
    assert a == b  # input order does not matter, only the seed
    assert len(a.calibration) == 51 and len(a.test) == 204
    assert not set(a.calibration) & set(a.test)
    assert set(a.calibration) | set(a.test) == set(IDS)


def test_split_is_saved_once_and_then_only_checked(tmp_path):
    path = tmp_path / "d.json"
    first = splits.create_or_check_split("d", "rev", IDS, path)
    assert splits.create_or_check_split("d", "rev", IDS, path) == first
    with pytest.raises(splits.SplitError, match="different set of task IDs"):
        splits.create_or_check_split("d", "rev", IDS[:-1], path)


def test_a_hand_edited_split_is_refused(tmp_path):
    path = tmp_path / "d.json"
    splits.create_or_check_split("d", "rev", IDS, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    moved = data["test"].pop()
    data["calibration"][0], data["test"] = moved, data["test"] + [data["calibration"][0]]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(splits.SplitError, match="edited by hand"):
        splits.create_or_check_split("d", "rev", IDS, path)
