"""Agent 2's AI review (checklist + open question), with a fake provider only."""

import json
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from codeguard import scan
from codeguard.agents.llm_review import CHECKLIST, LLM_CHECKS, OPEN_QUESTION, review_sources, run_llm_review
from codeguard.cli import app as cli_app
from codeguard.config import REPO_ROOT, Settings
from codeguard.llm.base import LLMAuthError, QuotaExhausted
from codeguard.llm.checklist import get_checklist, load_checklist
from codeguard.llm.prompts import code_block
from codeguard.models import Confidence, Detector, ToolState
from codeguard.rulechecks.loader import RuleFileError
from codeguard.rulechecks.source import load_sources

from conftest import CHECKLIST_IDS, FakeIndex, checklist_json, honest_reviewer, prompt_code

CODE = (
    "import sqlite3\n"  # 1
    "\n"  # 2
    "\n"  # 3
    "def find(db, name):\n"  # 4
    '    return db.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'  # 5
    "\n"  # 6
    "\n"  # 7
    "def calc(expr):\n"  # 8
    "    return eval(expr)\n"  # 9
)


@pytest.fixture
def app_file(tmp_path):
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "app.py").write_text(CODE, encoding="utf-8")
    return folder


def review(folder, client, groups, max_files=20):
    return {o.run.tool: o for o in review_sources(load_sources(folder), client, get_checklist(), groups, max_files)}


def respond_by_task(checklist, open_answer='{"issues": []}'):
    """Answer checklist prompts with `checklist` and open-question prompts with `open_answer`."""
    answers = {"checklist": list(checklist) if isinstance(checklist, list) else checklist}

    def respond(system, user):
        if user.startswith("Task: is anything else"):
            return open_answer
        c = answers["checklist"]
        return c.pop(0) if isinstance(c, list) else c

    return respond


def test_yes_answer_becomes_a_finding_with_evidence(app_file, make_llm, groups):
    client = make_llm(respond_by_task(checklist_json({"CG-CHK-002": [5], "CG-CHK-003": [9]})))
    runs = review(app_file, client, groups)
    chk = runs[CHECKLIST]
    assert chk.run.state == ToolState.OK and chk.run.findings_count == 2
    sql = next(f for f in chk.findings if f.evidence.rule_ids == ["CG-CHK-002"])
    assert (sql.file, sql.line_start, sql.line_end, sql.cwe, sql.cwe_group) == ("app.py", 5, 5, "CWE-89", "sql-injection")
    assert sql.detectors == [Detector.LLM_CHECKLIST]
    assert "db.execute" in sql.evidence.matched_code
    assert sql.evidence.llm_reasons == ["reason CG-CHK-002"]
    assert any("fake/fake-model" in m and "checklist-v3" in m for m in sql.evidence.messages)
    assert sql.confidence is None  # set later by the Verifier
    usage = chk.run.llm
    assert (usage.provider, usage.model, usage.prompt_version, usage.calls) == ("fake", "fake-model", "checklist-v3", 1)


def test_neighbouring_lines_make_one_finding(app_file, make_llm, groups):
    client = make_llm(respond_by_task(checklist_json({"CG-CHK-003": [8, 9, 5]})))
    found = [(f.line_start, f.line_end) for f in review(app_file, client, groups)[CHECKLIST].findings]
    assert found == [(5, 5), (8, 9)]


@pytest.mark.parametrize("lines,why", [([99], "line 99 does not exist (app.py has 9 lines)"), ([0], "line 0 does not exist"), ([2], "line 2 is empty"), ([], "gave no line number"), ([9, 120], "line 120 does not exist")])
def test_answers_pointing_to_lines_that_do_not_exist_are_rejected(app_file, make_llm, groups, lines, why):
    client = make_llm(respond_by_task(checklist_json({"CG-CHK-003": lines, "CG-CHK-002": [5]})))
    chk = review(app_file, client, groups)[CHECKLIST]
    assert [f.evidence.rule_ids[0] for f in chk.findings] == ["CG-CHK-002"]  # the valid answer is kept
    assert any("CG-CHK-003 answer rejected" in n and why in n for n in chk.run.notes), chk.run.notes


def test_answer_that_skips_items_is_asked_again(app_file, make_llm, groups):
    client = make_llm(respond_by_task([checklist_json(skip=("CG-CHK-005",)), checklist_json({"CG-CHK-003": [9]})]))
    chk = review(app_file, client, groups)[CHECKLIST]
    assert chk.run.state == ToolState.OK and len(chk.findings) == 1
    retry_prompt = client.provider.calls[1][1]
    assert "items not answered: CG-CHK-005" in retry_prompt


def test_answer_that_never_covers_every_item_fails_the_check(app_file, make_llm, groups):
    bad = json.dumps({"answers": [{"id": "CG-CHK-999", "answer": "no", "lines": [], "reason": ""}]})
    chk = review(app_file, make_llm(respond_by_task(bad)), groups)[CHECKLIST]
    assert chk.run.state == ToolState.FAILED and chk.findings == []
    assert "unknown item IDs: CG-CHK-999" in chk.run.message
    assert chk.run.llm.calls == 3


def test_open_question_findings_are_always_low_confidence(app_file, make_llm, groups):
    issues = {"issues": [
        {"line": 4, "cwe": "CWE-306", "title": "No authentication", "reason": "anyone can call it"},
        {"line": 5, "line_end": 5, "cwe": "89", "title": "Injection", "reason": "again"},
        {"line": 77, "cwe": "CWE-20", "title": "Ghost", "reason": "made up"},
        {"line": 9, "line_end": 8, "cwe": "CWE-20", "title": "Backwards", "reason": "bad range"},
    ]}  # fmt: skip
    opn = review(app_file, make_llm(respond_by_task(checklist_json(), json.dumps(issues))), groups)[OPEN_QUESTION]
    assert [(f.line_start, f.cwe, f.cwe_group) for f in opn.findings] == [(4, "CWE-306", "missing-authentication"), (5, "CWE-89", "sql-injection")]
    assert all(f.confidence == Confidence.LOW and f.detectors == [Detector.LLM_OPEN] for f in opn.findings)
    assert any("line 77 does not exist" in n for n in opn.run.notes)
    assert any("line_end 8 is before line 9" in n for n in opn.run.notes)


def test_open_question_keeps_at_most_five(app_file, make_llm, groups):
    issues = {"issues": [{"line": 9, "cwe": "CWE-20", "title": f"t{i}", "reason": "r"} for i in range(8)]}
    opn = review(app_file, make_llm(respond_by_task(checklist_json(), json.dumps(issues))), groups)[OPEN_QUESTION]
    assert len(opn.findings) == 5 and any("only the first 5" in n for n in opn.run.notes)


def test_daily_quota_stops_the_review_and_says_so(tmp_path, make_llm, groups):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("x = eval(input())\n", encoding="utf-8")
    replies = [checklist_json({"CG-CHK-003": [1]}), '{"issues": []}', QuotaExhausted("daily limit of 200 requests reached")]
    runs = review(tmp_path, make_llm(replies), groups)
    chk = runs[CHECKLIST]
    assert chk.run.state == ToolState.OK and len(chk.findings) == 1
    assert "1 file(s) not reviewed (daily limit of 200 requests reached): b.py" in chk.run.message


def test_rejected_key_skips_the_review(app_file, make_llm, groups):
    runs = review(app_file, make_llm([LLMAuthError("Gemini rejected the API key (HTTP 400)")]), groups)
    for tool in LLM_CHECKS:
        assert runs[tool].run.state == ToolState.SKIPPED and "rejected the API key" in runs[tool].run.message


def test_file_limit(tmp_path, make_llm, groups):
    for i in range(3):
        (tmp_path / f"m{i}.py").write_text("x = 1\n", encoding="utf-8")
    runs = review(tmp_path, make_llm(honest_reviewer), groups, max_files=2)
    assert any("Only the first 2 Python files" in n and "m2.py" in n for n in runs[CHECKLIST].run.notes)
    assert runs[CHECKLIST].run.llm.calls == 2


def test_without_a_key_the_review_is_skipped_not_failed(app_file):
    # conftest makes make_client raise LLMUnavailable, as it does when no key is set.
    outcomes = run_llm_review(app_file, Settings())
    assert [(o.run.tool, o.run.state) for o in outcomes] == [(t, ToolState.SKIPPED) for t in LLM_CHECKS]


def test_turned_off_review_sends_nothing(app_file):
    outcomes = run_llm_review(app_file, replace(Settings(), llm_review=False))
    assert all("turned off" in o.run.message for o in outcomes)


def test_scan_code_runs_the_review_next_to_the_other_checks(monkeypatch, make_llm):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)
    result = scan.scan_code(CODE, "calc.py", index=FakeIndex(), llm=make_llm(honest_reviewer))
    by_tool = {r.tool: r for r in result.tool_runs}
    assert by_tool[CHECKLIST].state == ToolState.OK and by_tool[OPEN_QUESTION].state == ToolState.OK
    llm_found = {(f.file, f.line_start, f.evidence.rule_ids[0]) for f in result.findings if f.detectors == [Detector.LLM_CHECKLIST]}
    assert llm_found == {("calc.py", 5, "CG-CHK-002"), ("calc.py", 9, "CG-CHK-003")}
    # The rule checks still report eval on their own (CG-DEP-007).
    assert any(f.evidence.rule_ids == ["CG-DEP-007"] for f in result.findings)


def test_secrets_in_llm_reasons_are_masked(monkeypatch, make_llm):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)
    code = 'PASSWORD = "Tr0ub4dor&3xyz"\n'
    answer = json.loads(checklist_json({"CG-CHK-013": [1]}))
    for a in answer["answers"]:
        if a["id"] == "CG-CHK-013":
            a["reason"] = 'The password "Tr0ub4dor&3xyz" is hard-coded.'
    result = scan.scan_code(code, "cfg.py", index=FakeIndex(), llm=make_llm(respond_by_task(json.dumps(answer))))
    f = next(f for f in result.findings if f.detectors == [Detector.LLM_CHECKLIST])
    assert "Tr0ub4dor&3xyz" not in f.evidence.llm_reasons[0]


def test_cli_no_llm_flag(monkeypatch, tmp_path):
    seen = {}

    def fake_scan_path(p, settings):
        seen["llm_review"] = settings.llm_review
        return scan.ScanResult(target=str(p))

    monkeypatch.setattr("codeguard.cli.scan_path", fake_scan_path)
    res = CliRunner().invoke(cli_app, ["scan", str(tmp_path), "--no-llm"])
    assert res.exit_code == 0, res.output
    assert seen == {"llm_review": False}


def test_cli_check_llm(monkeypatch, make_llm):
    client = make_llm(['{"ok": true}'])
    monkeypatch.setattr("codeguard.llm.make_client", lambda settings=None: client)
    res = CliRunner().invoke(cli_app, ["check-llm"])
    assert res.exit_code == 0, res.output
    assert "Provider: fake" in res.output and "OK" in res.output and "1 request" in res.output


def test_cli_check_llm_without_key(monkeypatch):
    res = CliRunner().invoke(cli_app, ["check-llm"])
    assert res.exit_code == 1 and "AI provider not working" in res.output


def test_code_block_numbers_lines_and_uses_its_own_marker():
    block = code_block("a.py", "x = 1\n\ny = 2\n")
    assert prompt_code(block) == {1: "x = 1", 2: "", 3: "y = 2"}
    marker = block.split()[1]
    assert block.rstrip().endswith(f"CODE {marker}>>>") and marker not in "x = 1\n\ny = 2\n"


# --- rules/checklist.yaml ---


def test_checklist_items_have_a_named_cwe_group_and_documented_sources(groups):
    doc = (REPO_ROOT / "docs" / "RULE_SOURCES.md").read_text(encoding="utf-8")
    for item in get_checklist().items:
        assert item.cwe in groups.by_cwe, f"{item.id}: {item.cwe} is not in rules/cwe_groups.yaml"
        assert item.id in doc and item.cwe in doc, f"{item.id} is missing from docs/RULE_SOURCES.md"
        for src in item.sources:
            assert src in doc, f"source of {item.id} missing from docs/RULE_SOURCES.md: {src}"
    assert len(CHECKLIST_IDS) == len(set(CHECKLIST_IDS)) >= 10


def test_broken_checklist_is_rejected(tmp_path):
    text = (REPO_ROOT / "rules" / "checklist.yaml").read_text(encoding="utf-8")
    (tmp_path / "checklist.yaml").write_text(text.replace("cwe: CWE-89", "cwe: not-a-cwe", 1), encoding="utf-8")
    with pytest.raises(RuleFileError, match="checklist.yaml"):
        load_checklist(tmp_path)
