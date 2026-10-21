"""Comparing two pilot runs: same samples and labels only, per-group flag counts, scan times."""

import pytest

from codeguard.cwe import get_cwe_groups
from codeguard.models import Detector, Finding

from benchmark import compare as cmp
from benchmark import pilot

TOOLS = ["semgrep", "llm_checklist"]


def row(task, label="vulnerable", group="xss", status="scored", **flags):
    return {"task_id": task, "status": status, "label": label, "target_group": group,
            **{t: int(flags.get(t, 0)) for t in TOOLS}}  # fmt: skip


def test_same_samples_and_labels_are_required():
    old = [row("a"), row("b", label="safe"), row("c", status="excluded: not_functional")]
    assert cmp.check_same_samples(old, [row("a"), row("b", label="safe")]) == ["a", "b"]
    with pytest.raises(cmp.CompareError, match="different samples"):
        cmp.check_same_samples(old, [row("a")])
    with pytest.raises(cmp.CompareError, match="different labels"):
        cmp.check_same_samples(old, [row("a"), row("b", label="vulnerable")])


def test_flag_counts_per_group_use_the_same_samples_for_both_runs():
    old = [row("a", semgrep=1), row("b"), row("c", group="CWE-862")]
    new = [row("a", semgrep=1, llm_checklist=1), row("b", llm_checklist=1), row("c", group="missing-authorization", llm_checklist=1)]
    counts = {g.cwe_group: g for g in cmp.flagged_by_group(old, new, TOOLS)}
    assert set(counts) == {"xss", "missing-authorization"}  # named after the new run's groups
    assert (counts["xss"].samples, counts["xss"].old, counts["xss"].new) == (
        2, {"semgrep": 1, "llm_checklist": 0}, {"semgrep": 1, "llm_checklist": 2}
    )
    assert counts["missing-authorization"].old["llm_checklist"] == 0
    assert cmp.flag_changes(old, new, TOOLS) == {("llm_checklist", "gained"): 3}


def test_missing_times_are_not_estimated():
    s = cmp.time_summary({"a": 2.0, "b": None, "c": 4.0})
    assert (s["measured"], s["missing"], s["median"]) == (2, 1, 3.0)
    assert cmp.time_summary({"a": None})["median"] is None
    assert cmp.fmt_seconds(None) == "Not yet measured" and cmp.fmt_seconds(1.234) == "1.2 s"


def test_saved_findings_are_scored_with_todays_cwe_groups():
    groups = get_cwe_groups()
    old = Finding(file="a.py", line_start=1, line_end=1, cwe="CWE-862", cwe_group="CWE-862", title="t",
                  detectors=[Detector.LLM_OPEN])  # fmt: skip
    no_cwe = Finding(file="a.py", line_start=1, line_end=1, cwe_group="unclassified", title="t", detectors=[Detector.SEMGREP])
    regrouped = pilot._regroup([old, no_cwe], groups)
    assert [f.cwe_group for f in regrouped] == ["missing-authorization", "unclassified"]
    assert old.cwe_group == "CWE-862"  # the saved finding itself is not changed


def test_tags_keep_scans_and_results_apart(monkeypatch):
    monkeypatch.setattr(pilot, "_generator_dir", lambda: pilot.RUN_DIR / "gen")
    monkeypatch.setattr(pilot, "_TAG", "")
    assert pilot._stage_dir("scans").name == "scans" and pilot._output("metrics", ".csv").name == "metrics.csv"
    monkeypatch.setattr(pilot, "_TAG", "v2")
    assert pilot._stage_dir("scans").name == "scans-v2" and pilot._output("metrics", ".csv").name == "metrics-v2.csv"
    assert pilot._stage_dir("scans", "").name == "scans"
    # samples and labels are shared, so a tagged run scores the same samples with the same labels
    assert pilot._stage_dir("samples").name == "samples" and pilot._stage_dir("labels").name == "labels"
