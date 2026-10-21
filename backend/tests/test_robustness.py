"""Unknown code must never crash a scan: every problem becomes a clear message and the other checks still run."""

import codecs
import io
import zipfile

import pytest
from typer.testing import CliRunner

from codeguard import scan
from codeguard.agents.ai_mistake_finder import ALL_CHECKS, LOGIC, TAINT
from codeguard.agents.llm_review import LLM_CHECKS
from codeguard.cli import app as cli_app
from codeguard.llm.base import QuotaExhausted
from codeguard.models import Detector, ToolState
from codeguard.textio import decode_source

from conftest import FakeIndex, checklist_json


@pytest.fixture(autouse=True)
def no_external_scanners(monkeypatch):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)


def run(path, **kw):
    return scan.scan_path(path, index=FakeIndex(), **kw)


def runs(result):
    return {r.tool: r for r in result.tool_runs}


def rule_ids(result):
    return sorted({(f.file, f.evidence.rule_ids[0]) for f in result.findings})


def all_file_errors(result):
    return [e for r in result.tool_runs for e in r.file_errors]


def assert_every_check_ran(result):
    states = {t: r.state for t, r in runs(result).items()}
    assert all(states[t] == ToolState.OK for t in ALL_CHECKS), states
    assert states["semgrep"] == ToolState.MISSING and states["bandit"] == ToolState.MISSING


# --- files that are not ordinary Python ---


def test_file_that_does_not_parse(tmp_path):
    (tmp_path / "broken.py").write_text('API_KEY = "AKIAABCDEFGHIJKLMNOP"\ndef f(:\n', encoding="utf-8")
    (tmp_path / "ok.py").write_text("import os, sys\nos.system('ls ' + sys.argv[1])\n", encoding="utf-8")
    result = run(tmp_path)
    assert_every_check_ran(result)
    assert any("broken.py: not valid Python (line 2)" in e for e in all_file_errors(result))
    # Text checks still look at the broken file; AST checks still look at the good one.
    assert ("broken.py", "CG-SEC-001") in rule_ids(result)
    assert ("ok.py", "CG-TNT-001") in rule_ids(result)


def test_file_too_large(tmp_path):
    (tmp_path / "huge.py").write_text("x = 1\n" * 400_000, encoding="utf-8")  # 2.4 MB
    (tmp_path / "small.py").write_text("eval(input())\n", encoding="utf-8")
    result = run(tmp_path)
    assert_every_check_ran(result)
    assert any("huge.py: skipped (larger than 2 MB)" in e for e in all_file_errors(result))
    assert ("small.py", "CG-TNT-002") in rule_ids(result)


def test_long_file_under_the_limit_is_scanned(tmp_path):
    body = "".join(f"def f{i}(request):\n    return request\n\n" for i in range(5000))
    (tmp_path / "long.py").write_text("import sys\n" + body + "eval(sys.argv[1])\n", encoding="utf-8")
    result = run(tmp_path)
    assert_every_check_ran(result)
    assert ("long.py", "CG-TNT-002") in rule_ids(result)


def test_deeply_nested_code(tmp_path):
    (tmp_path / "parens.py").write_text("x = " + "(" * 500 + "1" + ")" * 500 + "\n", encoding="utf-8")
    (tmp_path / "chain.py").write_text("import sys\ny = sys.argv[1]" + " + y" * 20_000 + "\neval(y)\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("eval(input())\n", encoding="utf-8")
    result = run(tmp_path)
    assert_every_check_ran(result)
    errors = all_file_errors(result)
    assert any(e.startswith("parens.py:") for e in errors)
    assert ("ok.py", "CG-TNT-002") in rule_ids(result)
    for e in errors:
        assert "Traceback" not in e


@pytest.mark.parametrize(
    "name,data,note",
    [
        ("utf16.py", codecs.BOM_UTF16_LE + "eval(input())\n".encode("utf-16-le"), "read as UTF-16"),
        ("utf8bom.py", codecs.BOM_UTF8 + b"eval(input())\n", None),
        ("latin1.py", b"# -*- coding: latin-1 -*-\nname = 'Jos\xe9'\neval(input())\n", "read as iso-8859-1"),
        ("badbytes.py", b"eval(input())  # caf\xe9\n", "some bytes are not valid UTF-8"),
        ("badcookie.py", b"# -*- coding: klingon -*-\neval(input())\n", "coding declaration is not valid"),
    ],
)
def test_odd_encodings(tmp_path, name, data, note):
    (tmp_path / name).write_bytes(data)
    result = run(tmp_path)
    assert_every_check_ran(result)
    errors = all_file_errors(result)
    if note:
        assert any(note in e for e in errors), errors
    if name != "badcookie.py":  # a broken coding line is a SyntaxError for Python too
        assert (name, "CG-TNT-002") in rule_ids(result)


def test_binary_file_with_a_py_name(tmp_path):
    (tmp_path / "blob.py").write_bytes(b"\x00\x01\x02\xff\xfe" * 1000)
    result = run(tmp_path)
    assert_every_check_ran(result)
    assert any("blob.py: contains null bytes" in e for e in all_file_errors(result))


def test_decode_source_never_raises():
    for data in (b"", b"\xff\xfe", b"\xef\xbb\xbf", b"\x00" * 10, bytes(range(256))):
        text, _ = decode_source(data)
        assert isinstance(text, str)


def test_empty_file_and_empty_folder(tmp_path):
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    result = run(tmp_path)
    assert_every_check_ran(result)
    assert result.findings == []
    empty_dir = tmp_path / "nothing"
    empty_dir.mkdir()
    result = run(empty_dir)
    assert_every_check_ran(result)
    assert result.findings == []


# --- zip archives ---


def make_zip(path, entries: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_zip_is_scanned_and_unsafe_entries_are_skipped(tmp_path):
    archive = make_zip(
        tmp_path / "project.zip",
        {
            "proj/app.py": b"import sys, os\nos.system('rm ' + sys.argv[1])\n",
            "proj/requirements.txt": b"flask==0.12\n",
            "../evil.py": b"print('outside')\n",
            "/abs.py": b"x = 1\n",
            "proj/.venv/lib/site.py": b"eval(input())\n",
            "proj/README.md": b"# hi\n",
        },
    )
    result = scan.scan_zip(archive, index=FakeIndex())
    assert result.target == "project.zip"
    assert ("proj/app.py", "CG-TNT-001") in rule_ids(result)
    assert ("proj/requirements.txt", "CG-OSV-001") in rule_ids(result)
    assert not any("site.py" in f.file for f in result.findings)  # vendored folders are skipped
    assert result.notes[0] == "1 Python file(s) taken from project.zip."
    assert any("../evil.py: skipped (path leaves the archive folder)" in n for n in result.notes)
    assert any("/abs.py: skipped (path leaves the archive folder)" in n for n in result.notes)
    assert not (tmp_path / "evil.py").exists()


def test_zip_without_python(tmp_path):
    archive = make_zip(tmp_path / "docs.zip", {"README.md": b"# hi\n", "img.png": b"\x89PNG"})
    with pytest.raises(scan.ScanInputError, match=r"docs.zip contains no Python files \(.py\) to scan \(2 other file"):
        scan.scan_zip(archive, index=FakeIndex())


def test_not_a_zip(tmp_path):
    fake = tmp_path / "fake.zip"
    fake.write_bytes(b"this is not a zip")
    with pytest.raises(scan.ScanInputError, match="fake.zip is not a valid zip file"):
        scan.scan_zip(fake, index=FakeIndex())


def test_zip_entry_lying_about_its_size_is_skipped(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.py", b"x = 1\n" * 10)
        zf.writestr("big.py", b"#" * 3_000_000)
    archive = tmp_path / "mixed.zip"
    archive.write_bytes(buf.getvalue())
    result = scan.scan_zip(archive, index=FakeIndex())
    assert any("big.py: skipped" in n for n in result.notes)


def test_cli_reports_zip_problems_clearly(tmp_path):
    archive = make_zip(tmp_path / "docs.zip", {"README.md": b"# hi\n"})
    res = CliRunner().invoke(cli_app, ["scan", str(archive), "--no-llm", "--offline"])
    assert res.exit_code == 2
    assert "contains no Python files" in res.output


# --- tools, detectors and providers that fail ---


def test_missing_scanners_leave_the_other_checks_running(tmp_path):
    (tmp_path / "a.py").write_text("eval(input())\n", encoding="utf-8")
    result = run(tmp_path)
    r = runs(result)
    assert r["semgrep"].state == ToolState.MISSING and r["semgrep"].message
    assert r["bandit"].state == ToolState.MISSING and r["bandit"].message
    assert r[TAINT].state == ToolState.OK and r[TAINT].findings_count == 1


def test_a_crashing_agent_becomes_a_failed_tool_run(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("eval(input())\n", encoding="utf-8")

    def boom(*args, **kwargs):
        raise RuntimeError("bug in the rule checks")

    monkeypatch.setattr("codeguard.scan.run_rule_checks", boom)
    result = run(tmp_path)
    r = runs(result)
    for tool in ALL_CHECKS:
        assert r[tool].state == ToolState.FAILED and "RuntimeError: bug in the rule checks" in r[tool].message
    assert r["semgrep"].state == ToolState.MISSING  # the other agents still reported
    assert all(r[t].state == ToolState.SKIPPED for t in LLM_CHECKS)


def test_a_crashing_check_on_one_file_keeps_the_others(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("eval(input())\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("eval(input())\n", encoding="utf-8")
    from codeguard.rulechecks import taint as taint_module

    real = taint_module.check_taint

    def flaky(src, facts, book, groups):
        if src.rel == "a.py":
            raise ValueError("unexpected AST shape")
        return real(src, facts, book, groups)

    monkeypatch.setattr("codeguard.agents.ai_mistake_finder.check_taint", flaky)
    result = run(tmp_path)
    t = runs(result)[TAINT]
    assert t.state == ToolState.OK
    assert t.file_errors == ["a.py: taint failed (ValueError: unexpected AST shape)"]
    assert [f.file for f in result.findings if f.detectors == [Detector.TAINT]] == ["b.py"]
    assert runs(result)[LOGIC].state == ToolState.OK


def test_secret_masking_failure_removes_snippets(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text('PASSWORD = "Tr0ub4dor&3xyz"\n', encoding="utf-8")

    def boom(*args, **kwargs):
        raise RuntimeError("redaction bug")

    monkeypatch.setattr("codeguard.scan.mask_secrets", boom)
    result = run(tmp_path)
    assert result.findings and all(f.evidence.matched_code is None for f in result.findings)
    assert runs(result)["redaction"].state == ToolState.FAILED


def test_provider_daily_limit_mid_scan(tmp_path, make_llm):
    (tmp_path / "a.py").write_text("eval(input())\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("eval(input())\n", encoding="utf-8")
    client = make_llm([checklist_json({"CG-CHK-003": [1]}), '{"issues": []}', QuotaExhausted("daily limit of 18 requests reached")])
    result = run(tmp_path, llm=client)
    r = runs(result)
    assert r["llm:checklist"].state == ToolState.OK
    assert "1 file(s) not reviewed (daily limit of 18 requests reached): b.py" in r["llm:checklist"].message
    # The no-AI checks are not affected.
    assert sorted(f.file for f in result.findings if f.detectors == [Detector.TAINT]) == ["a.py", "b.py"]


def test_provider_limit_from_the_start_skips_the_ai_but_not_the_scan(tmp_path, make_llm):
    (tmp_path / "a.py").write_text("eval(input())\n", encoding="utf-8")
    result = run(tmp_path, llm=make_llm([QuotaExhausted("daily limit of 18 requests reached")]))
    r = runs(result)
    assert all(r[t].state == ToolState.SKIPPED and "daily limit" in r[t].message for t in LLM_CHECKS)
    assert_every_check_ran(result)
