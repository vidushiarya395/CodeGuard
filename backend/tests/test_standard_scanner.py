import subprocess
from dataclasses import replace

import pytest

from codeguard.agents import standard_scanner
from codeguard.agents.standard_scanner import ScanInputError, safe_filename, scan_code, scan_path
from codeguard.models import Detector, ToolState
from codeguard.scanners import base

from conftest import requires_bandit, requires_semgrep

# --- Behaviour when tools are missing or broken (no real tools needed) ---


def test_missing_semgrep_is_reported_not_raised(settings, examples_dir, monkeypatch):
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)
    s = replace(settings, semgrep_path=str(examples_dir / "no-such-semgrep.exe"))
    result = scan_path(examples_dir / "safe", settings=s)
    states = {r.tool: r.state for r in result.tool_runs}
    assert states == {"semgrep": ToolState.MISSING, "bandit": ToolState.MISSING}
    semgrep_run = next(r for r in result.tool_runs if r.tool == "semgrep")
    assert "not found" in semgrep_run.message
    assert result.findings == []


def test_timeout_is_reported(settings, examples_dir, monkeypatch):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(base.subprocess, "run", boom)
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: "semgrep")
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: ["bandit"])
    result = scan_path(examples_dir / "safe", settings=replace(settings, scanner_timeout_s=1))
    assert all(r.state == ToolState.TIMEOUT for r in result.tool_runs)
    assert all("did not finish" in r.message for r in result.tool_runs)


def test_tool_that_cannot_start_is_missing(settings, examples_dir, monkeypatch):
    def not_found(*args, **kwargs):
        raise FileNotFoundError("gone")

    monkeypatch.setattr(base.subprocess, "run", not_found)
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: "semgrep")
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: ["bandit"])
    result = scan_path(examples_dir / "safe", settings=settings)
    assert all(r.state == ToolState.MISSING for r in result.tool_runs)


# --- Input checks ---


def test_missing_path():
    with pytest.raises(ScanInputError, match="not found"):
        scan_path(standard_scanner.Path("definitely/not/here.py"))


def test_empty_code_rejected():
    with pytest.raises(ScanInputError, match="empty"):
        scan_code("   \n")


def test_too_many_lines_rejected(settings):
    with pytest.raises(ScanInputError, match="limit"):
        scan_code("x = 1\n" * 11, settings=replace(settings, max_paste_lines=10))


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, "snippet.py"),
        ("", "snippet.py"),
        ("app.py", "app.py"),
        ("app", "app.py"),
        ("../../etc/passwd", "passwd.py"),
        ("C:\\Windows\\evil.py", "evil.py"),
        ("my file!.py", "my_file_.py"),
        (".hidden.py", "hidden.py"),
    ],
)
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected


# --- Real tools (skipped if not installed; Semgrep also needs internet for p/python) ---


@pytest.mark.integration
@requires_bandit
def test_bandit_real_vulnerable_and_safe(settings, examples_dir, monkeypatch):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    vuln = scan_path(examples_dir / "vulnerable", settings=settings)
    groups = {f.cwe_group for f in vuln.findings if Detector.BANDIT in f.detectors}
    assert {"os-command-injection", "sql-injection", "unsafe-deserialization", "weak-cryptography"} <= groups

    safe = scan_path(examples_dir / "safe", settings=settings)
    bandit_run = next(r for r in safe.tool_runs if r.tool == "bandit")
    assert bandit_run.state == ToolState.OK
    assert safe.findings == []


@pytest.mark.integration
@requires_semgrep
def test_semgrep_real_vulnerable_and_safe(settings, examples_dir, monkeypatch):
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)
    vuln = scan_path(examples_dir / "vulnerable", settings=settings)
    semgrep_run = next(r for r in vuln.tool_runs if r.tool == "semgrep")
    assert semgrep_run.state == ToolState.OK, semgrep_run.message
    groups = {f.cwe_group for f in vuln.findings}
    assert {"os-command-injection", "weak-cryptography"} <= groups

    safe = scan_path(examples_dir / "safe", settings=settings)
    assert safe.findings == []


@pytest.mark.integration
@requires_bandit
def test_scan_code_reports_snippet_name(settings, monkeypatch):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    code = "import pickle\n\n\ndef load(b):\n    return pickle.loads(b)\n"
    result = scan_code(code, "loader.py", settings=settings)
    assert result.target == "loader.py"
    b301 = next(f for f in result.findings if "B301" in f.evidence.rule_ids)
    assert b301.file == "loader.py" and b301.line_start == 5
    assert b301.evidence.matched_code.strip() == "return pickle.loads(b)"


@pytest.mark.integration
@requires_bandit
def test_nosec_comment_does_not_hide_findings(settings, monkeypatch):
    # Scanned code must not be able to switch our checks off.
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    code = "import pickle  # nosec\n\n\ndef load(b):\n    return pickle.loads(b)  # nosec\n"
    result = scan_code(code, settings=settings)
    assert any("B301" in f.evidence.rule_ids for f in result.findings)
