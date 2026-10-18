"""Scanned code is never executed, even when a file is named like a module the scanners import.

Regression: pasted code saved as string.py made Bandit's own Python import it (Bandit failed with
"No module named 'fastjsonx'"). Each scanned file below writes a marker file, prints and exits if it
is ever run, so "the marker does not exist" proves nothing ran.
"""

import json
from pathlib import Path

import pytest

from codeguard import scan
from codeguard.agents import standard_scanner
from codeguard.models import Detector, ToolState
from codeguard.scanners import ScanTarget, bandit, semgrep
from codeguard.scanners.base import CommandResult, to_rel_path

from conftest import FakeIndex, requires_bandit, requires_semgrep

STDLIB_NAMES = ["string.py", "os.py", "json.py"]


def booby_trap(marker: Path) -> str:
    """Code that leaves a marker and fails loudly if run, plus a never-called function that both
    scanners flag (Bandit: eval B307; Semgrep p/python: subprocess-shell-true)."""
    return (
        f"open({str(marker)!r}, 'w').write('executed')\n"
        "print('SCANNED CODE WAS EXECUTED')\n"
        "import fastjsonx\n"
        "raise SystemExit(3)\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def run(expr, cmd):\n"
        "    subprocess.call(cmd, shell=True)\n"
        "    return eval(expr)\n"
    )


def only(monkeypatch, tool: str):
    """Run only one external scanner, to keep these tests fast."""
    if tool == "bandit":
        monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    else:
        monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)


def run_of(result, tool: str):
    return next(r for r in result.tool_runs if r.tool == tool)


def assert_not_run(result, tool: str, marker: Path):
    run = run_of(result, tool)
    assert run.state == ToolState.OK, run.message
    assert run.message is None, run.message
    assert not any("fastjsonx" in e or "ModuleNotFound" in e for e in run.file_errors), run.file_errors
    assert not marker.exists(), "scanned code was executed"


# --- Real scanners ---


@requires_bandit
@pytest.mark.parametrize("name", STDLIB_NAMES)
def test_pasted_file_named_like_stdlib_is_not_run_by_bandit(monkeypatch, tmp_path, name):
    only(monkeypatch, "bandit")
    marker = tmp_path / "marker.txt"
    result = scan.scan_code(booby_trap(marker), name, index=FakeIndex())
    assert_not_run(result, "bandit", marker)
    assert result.target == name
    assert "B307" in {f.evidence.rule_ids[0] for f in result.findings if f.file == name}
    assert {f.file for f in result.findings} == {name}  # the internal cg_*.py name never shows


@requires_bandit
def test_folder_with_stdlib_named_files_is_not_run_by_bandit(tmp_path, settings, groups):
    marker = tmp_path / "marker.txt"
    project = tmp_path / "project"
    project.mkdir()
    for name in STDLIB_NAMES:
        (project / name).write_text(booby_trap(marker), encoding="utf-8")
    run = bandit.run_bandit(ScanTarget.from_path(project), settings, groups)
    assert run.run.state == ToolState.OK, run.run.message
    assert not marker.exists(), "scanned code was executed"
    assert {f.file for f in run.findings if f.evidence.rule_ids == ["B307"]} == set(STDLIB_NAMES)


@requires_semgrep
def test_pasted_file_named_like_stdlib_is_not_run_by_semgrep(monkeypatch, tmp_path):
    only(monkeypatch, "semgrep")
    marker = tmp_path / "marker.txt"
    result = scan.scan_code(booby_trap(marker), "string.py", index=FakeIndex())
    assert_not_run(result, "semgrep", marker)
    assert {f.file for f in result.findings} == {"string.py"}
    assert any(f.detectors == [Detector.SEMGREP] and "shell-true" in f.evidence.rule_ids[0] for f in result.findings)


@requires_semgrep
def test_folder_with_stdlib_named_files_is_not_run_by_semgrep(tmp_path, settings, groups):
    marker = tmp_path / "marker.txt"
    project = tmp_path / "project"
    project.mkdir()
    for name in STDLIB_NAMES:
        (project / name).write_text(booby_trap(marker), encoding="utf-8")
    run = semgrep.run_semgrep(ScanTarget.from_path(project), settings, groups)
    assert run.run.state == ToolState.OK, run.run.message
    assert not marker.exists(), "scanned code was executed"
    assert {f.file for f in run.findings if "shell-true" in f.evidence.rule_ids[0]} == set(STDLIB_NAMES)


@requires_bandit
def test_parent_folder_named_vendor_does_not_hide_files(tmp_path, settings, groups):
    # Excludes must only match folders inside the scanned code, not the folders around it.
    project = tmp_path / "vendor" / "project"
    (project / "vendor").mkdir(parents=True)
    (project / "app.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    (project / "vendor" / "lib.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    run = bandit.run_bandit(ScanTarget.from_path(project), settings, groups)
    assert run.run.state == ToolState.OK, run.run.message
    assert {f.file for f in run.findings} == {"app.py"}


# --- How the tools are started (no real tools needed) ---


def test_scanners_never_run_inside_the_scanned_folder(monkeypatch, tmp_path):
    seen = {}

    def fake_run(tool):
        def run(cmd, cwd, timeout_s):
            seen[tool] = (cmd, Path(cwd))
            return CommandResult(1, "", "", 0.0)

        return run

    monkeypatch.setattr(bandit, "find_bandit", lambda: ["python", "-P", "-m", "bandit"])
    monkeypatch.setattr(semgrep, "find_semgrep", lambda s: "semgrep")
    monkeypatch.setattr(bandit, "run_command", fake_run("bandit"))
    monkeypatch.setattr(semgrep, "run_command", fake_run("semgrep"))
    (tmp_path / "string.py").write_text("x = 1\n", encoding="utf-8")

    standard_scanner.scan_path(tmp_path / "string.py")
    scanned = tmp_path.resolve()
    for tool in ("bandit", "semgrep"):
        cmd, cwd = seen[tool]
        assert cwd.resolve() != scanned and scanned not in cwd.resolve().parents
        assert cmd[-1] == str(scanned / "string.py")  # absolute target, not relative to cwd


def test_bandit_is_started_without_cwd_on_sys_path():
    base = bandit.find_bandit()
    if base is None or len(base) == 1:
        pytest.skip("Bandit is not installed as a module of this Python")
    assert base[1] == "-P"


def test_absolute_tool_paths_become_relative_to_the_scan_root(tmp_path, groups):
    root = tmp_path.resolve()
    assert to_rel_path(str(root / "pkg" / "a.py"), root) == "pkg/a.py"
    assert to_rel_path("./pkg/a.py", root) == "pkg/a.py"
    result = {
        "filename": str(root / "pkg" / "a.py"),
        "line_number": 1,
        "line_range": [1],
        "test_id": "B307",
        "test_name": "blacklist",
        "issue_text": "Use of eval.",
    }
    raw = json.dumps({"errors": [], "results": [result]})
    out = bandit.parse_bandit_output(raw, "", 1, root, groups)
    assert [f.file for f in out.findings] == ["pkg/a.py"]


# --- Rule checks still see the user's file name ---


def no_external_scanners(monkeypatch):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)


def test_settings_rule_uses_the_pasted_file_name(monkeypatch):
    no_external_scanners(monkeypatch)
    result = scan.scan_code("DEBUG = True\n", "settings.py", index=FakeIndex())
    assert [(f.evidence.rule_ids[0], f.file) for f in result.findings] == [("CG-SET-004", "settings.py")]
    other = scan.scan_code("DEBUG = True\n", "views.py", index=FakeIndex())
    assert other.findings == []


def test_pasted_code_is_saved_under_an_internal_name(monkeypatch):
    names = []
    real = scan.scan_path
    monkeypatch.setattr(scan, "scan_path", lambda p, *a, **k: (names.append(p.name), real(p, *a, **k))[1])
    no_external_scanners(monkeypatch)
    scan.scan_code("x = 1\n", "string.py", index=FakeIndex())
    assert len(names) == 1 and names[0].startswith("cg_") and names[0] != "string.py"

