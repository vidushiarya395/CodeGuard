"""Per-sample flags, Verifier v0 and the metrics."""

import pytest

from codeguard.models import Detector, Finding

from benchmark import score
from benchmark.labels import SAFE, VULNERABLE
from benchmark.metrics import Confusion, confusion, metric_row


def finding(det, line, group="os-command-injection", file="a.py", end=None):
    return Finding(
        file=file, line_start=line, line_end=end or line, cwe_group=group, title="t", detectors=[det]
    )


def test_single_tools_only_count_their_own_findings_in_the_target_group():
    fs = [finding(Detector.BANDIT, 3), finding(Detector.SEMGREP, 9, group="sql-injection")]
    f = score.flags(fs, ("os-command-injection",))
    assert f["bandit"] and not f["semgrep"] and not f["llm_checklist"] and f["union"]


def test_union_includes_the_open_question():
    f = score.flags([finding(Detector.LLM_OPEN, 3)], ("os-command-injection",))
    assert f["union"] and not f["verifier_v0"]


def test_several_target_groups_count_any_of_them():
    f = score.flags([finding(Detector.SEMGREP, 1, group="CWE-287")], ("CWE-862", "CWE-287"))
    assert f["semgrep"]


def test_verifier_v0_keeps_rule_checks_alone():
    assert score.flags([finding(Detector.RULE_CHECK, 5)], ("os-command-injection",))["verifier_v0"]


def test_verifier_v0_keeps_two_detectors_within_two_lines():
    fs = [finding(Detector.SEMGREP, 10), finding(Detector.LLM_CHECKLIST, 12)]
    assert score.flags(fs, ("os-command-injection",))["verifier_v0"]


def test_verifier_v0_drops_one_detector_far_apart_or_other_group():
    target = ("os-command-injection",)
    assert not score.flags([finding(Detector.SEMGREP, 10), finding(Detector.SEMGREP, 11)], target)["verifier_v0"]
    assert not score.flags([finding(Detector.SEMGREP, 10), finding(Detector.BANDIT, 13)], target)["verifier_v0"]
    other = [finding(Detector.SEMGREP, 10), finding(Detector.BANDIT, 10, group="sql-injection")]
    assert not score.flags(other, target)["verifier_v0"]
    # The open question is not an independent detector.
    assert not score.flags([finding(Detector.SEMGREP, 10), finding(Detector.LLM_OPEN, 10)], target)["verifier_v0"]


def test_clusters_chain_and_respect_files():
    fs = [finding(Detector.SEMGREP, 1), finding(Detector.BANDIT, 3), finding(Detector.LLM_CHECKLIST, 5)]
    [c] = score.cluster(fs)
    assert (c.line_start, c.line_end) == (1, 5) and len(c.detectors) == 3
    assert len(score.cluster([finding(Detector.SEMGREP, 1), finding(Detector.BANDIT, 1, file="b.py")])) == 2


def test_confusion_and_metrics():
    rows = [(VULNERABLE, True), (VULNERABLE, False), (SAFE, True), (SAFE, False), (SAFE, False)]
    c = confusion(rows)
    assert (c.tp, c.fp, c.fn, c.tn) == (1, 1, 1, 2)
    assert c.precision == pytest.approx(0.5) and c.recall == pytest.approx(0.5)
    assert c.f1 == pytest.approx(0.5) and c.fpr == pytest.approx(1 / 3)


def test_zero_denominators_are_left_empty_not_guessed():
    c = Confusion(tp=0, fp=0, fn=3, tn=2)
    assert c.precision is None and c.f1 is None and c.recall == 0.0 and c.fpr == 0.0
    row = metric_row("x", "X", c)
    assert row["precision"] == "" and row["f1"] == "" and row["recall"] == "0.000"
    assert Confusion(tp=0, fp=2, fn=2, tn=0).f1 == 0.0
