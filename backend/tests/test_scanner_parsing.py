"""Parser tests on saved tool output. These need no tools and no internet."""

from codeguard.models import Detector, ToolState
from codeguard.scanners.bandit import parse_bandit_output
from codeguard.scanners.base import normalize_rel_path
from codeguard.scanners.semgrep import parse_semgrep_output


def test_normalize_rel_path():
    assert normalize_rel_path(".\\vulnerable\\a.py") == "vulnerable/a.py"
    assert normalize_rel_path("./a.py") == "a.py"
    assert normalize_rel_path("a/b.py") == "a/b.py"


def test_semgrep_fixture(fixtures_dir, examples_dir, groups):
    raw = (fixtures_dir / "semgrep_examples.json").read_text(encoding="utf-8")
    out = parse_semgrep_output(raw, "", 0, examples_dir, groups)
    assert out.run.state == ToolState.OK
    assert out.run.version == "1.179.0"
    assert out.run.findings_count == len(out.findings) == 3

    shell = next(f for f in out.findings if f.file == "vulnerable/command_injection.py")
    assert shell.line_start == 6
    assert shell.cwe == "CWE-78"
    assert shell.cwe_group == "os-command-injection"
    assert shell.detectors == [Detector.SEMGREP]
    assert "subprocess-shell-true" in shell.evidence.rule_ids[0]
    # Evidence is the real line from the file, not Semgrep's "requires login" placeholder.
    assert "shell=True" in shell.evidence.matched_code
    assert shell.evidence.tool_severity == {"semgrep": "ERROR"}


def test_bandit_fixture(fixtures_dir, examples_dir, groups):
    raw = (fixtures_dir / "bandit_examples.json").read_text(encoding="utf-8")
    out = parse_bandit_output(raw, "", 1, examples_dir, groups)
    assert out.run.state == ToolState.OK
    assert len(out.findings) == 6
    by_rule = {f.evidence.rule_ids[0]: f for f in out.findings}
    assert set(by_rule) == {"B404", "B602", "B608", "B403", "B301", "B324"}

    sql = by_rule["B608"]
    assert sql.file == "vulnerable/sql_injection.py"
    assert sql.line_start == 6
    assert sql.cwe == "CWE-89" and sql.cwe_group == "sql-injection"
    assert "SELECT" in sql.evidence.matched_code
    assert by_rule["B301"].cwe_group == "unsafe-deserialization"
    # No finding points at a safe file.
    assert not any(f.file.startswith("safe/") for f in out.findings)


def test_semgrep_garbage_output_fails_cleanly(examples_dir, groups):
    out = parse_semgrep_output("not json", "Some crash happened", 2, examples_dir, groups)
    assert out.run.state == ToolState.FAILED
    assert "exit code 2" in out.run.message
    assert out.findings == []


def test_semgrep_network_error_gets_hint(examples_dir, groups):
    out = parse_semgrep_output("", "Failed to download configuration from https://semgrep.dev", 2, examples_dir, groups)
    assert out.run.state == ToolState.FAILED
    assert "internet" in out.run.message


def test_bandit_empty_output_fails_cleanly(examples_dir, groups):
    out = parse_bandit_output("", "usage: bandit ...", 2, examples_dir, groups)
    assert out.run.state == ToolState.FAILED
    assert out.findings == []


def test_bandit_file_errors_are_reported(examples_dir, groups):
    raw = '{"errors": [{"filename": ".\\\\bad.py", "reason": "syntax error while parsing AST from file"}], "results": []}'
    out = parse_bandit_output(raw, "", 0, examples_dir, groups)
    assert out.run.state == ToolState.OK
    assert out.run.file_errors == ["bad.py: syntax error while parsing AST from file"]


def test_malformed_result_is_skipped_not_crash(examples_dir, groups):
    raw = '{"results": [{"filename": "x.py"}, {"nonsense": 1}], "errors": []}'
    out = parse_bandit_output(raw, "", 1, examples_dir, groups)
    assert out.run.state == ToolState.OK
    assert out.findings == []
