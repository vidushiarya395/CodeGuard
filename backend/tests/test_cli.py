import json

from typer.testing import CliRunner

from codeguard.cli import app
from codeguard.models import Detector, Evidence, Finding, ScanResult, ToolRun, ToolState

runner = CliRunner()


def fake_result(target="x.py"):
    return ScanResult(
        target=target,
        findings=[
            Finding(
                file="x.py",
                line_start=2,
                line_end=2,
                cwe="CWE-78",
                cwe_group="os-command-injection",
                title="Subprocess call with shell=True",
                detectors=[Detector.BANDIT],
                evidence=Evidence(rule_ids=["B602"], tool_severity={"bandit": "HIGH"}),
            )
        ],
        tool_runs=[
            ToolRun(tool="semgrep", state=ToolState.MISSING, message="Semgrep was not found."),
            ToolRun(tool="bandit", state=ToolState.OK, version="1.9.4", findings_count=1),
        ],
    )


def test_scan_prints_table(monkeypatch, tmp_path):
    monkeypatch.setattr("codeguard.cli.scan_path", lambda p: fake_result())
    res = runner.invoke(app, ["scan", str(tmp_path)], env={"COLUMNS": "200"})
    assert res.exit_code == 0, res.output
    assert "B602" in res.output
    assert "os-command-injection" in res.output
    assert "Semgrep was not found." in res.output
    assert "missing" in res.output


def test_scan_json(monkeypatch, tmp_path):
    monkeypatch.setattr("codeguard.cli.scan_path", lambda p: fake_result())
    res = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["findings"][0]["cwe"] == "CWE-78"


def test_scan_missing_path():
    res = runner.invoke(app, ["scan", "no/such/path.py"])
    assert res.exit_code == 2


def test_no_scanner_ran(monkeypatch, tmp_path):
    result = ScanResult(
        target="x",
        tool_runs=[
            ToolRun(tool="semgrep", state=ToolState.MISSING),
            ToolRun(tool="bandit", state=ToolState.FAILED, message="broken"),
        ],
    )
    monkeypatch.setattr("codeguard.cli.scan_path", lambda p: result)
    res = runner.invoke(app, ["scan", str(tmp_path)], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    assert "nothing was checked" in res.output
