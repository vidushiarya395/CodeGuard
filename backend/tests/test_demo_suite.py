"""The demo suite (demo/): every expected.yaml is valid and points at real code, and the
found / missed / extra comparison works. Nothing is scanned or run here."""

import importlib.util
import sys

import pytest

from codeguard.config import REPO_ROOT
from codeguard.models import Detector, Evidence, Finding, ScanResult

DEMO = REPO_ROOT / "demo"


@pytest.fixture(scope="module")
def run_demo():
    spec = importlib.util.spec_from_file_location("run_demo", DEMO / "run_demo.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_demo"] = module  # dataclasses look their module up here
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop("run_demo", None)


def test_there_are_eight_to_ten_demo_apps(run_demo):
    apps = run_demo.demo_apps()
    assert 8 <= len(apps) <= 10


def test_every_expected_file_is_valid_and_points_at_code(run_demo):
    for folder in run_demo.demo_apps():
        expected = run_demo.load_expected(folder)  # raises on a missing file or a blank line
        assert expected.app == folder.name
        assert expected.vulnerabilities or expected.quiet


def _finding(file, line, cwe, group, detector=Detector.RULE_CHECK, rule="CG-X"):
    return Finding(file=file, line_start=line, line_end=line, cwe=cwe, cwe_group=group, title="t",
                   detectors=[detector], evidence=Evidence(rule_ids=[rule]))  # fmt: skip


def test_compare_counts_found_missed_extra_and_noise(run_demo, groups):
    expected = run_demo.Expected(
        app="x",
        description="d",
        vulnerabilities=[
            run_demo.Vulnerability(file="a.py", line=10, cwe="CWE-89", what="sqli"),
            run_demo.Vulnerability(file="a.py", line=30, cwe="CWE-916", also_cwe=["CWE-327"], what="md5"),
            run_demo.Vulnerability(file="a.py", line=50, cwe="CWE-78", what="cmd"),
        ],
        quiet=[run_demo.Quiet(file="a.py", line=70, cwe="CWE-78", why="list args")],
    )
    result = ScanResult(
        target="x",
        findings=[
            _finding("a.py", 12, "CWE-89", "sql-injection"),  # within 2 lines, same group: found
            _finding("a.py", 30, "CWE-327", "weak-cryptography", Detector.BANDIT, "B324"),  # accepted other CWE
            _finding("a.py", 50, "CWE-79", "xss"),  # right line, wrong group: extra (and cmd is missed)
            _finding("a.py", 70, "CWE-78", "os-command-injection", Detector.BANDIT, "B603"),  # on a quiet line
        ],
    )
    r = run_demo.compare(expected, result, groups)
    assert [v.what for v, _ in r.found] == ["sqli", "md5"]
    assert [v.what for v in r.missed] == ["cmd"]
    assert sorted(f.line_start for f in r.extra) == [50, 70]
    assert [(q.line, f.evidence.rule_ids[0]) for q, f in r.noisy] == [(70, "B603")]
