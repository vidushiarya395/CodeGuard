"""The combined scan (Agent 1 + Agent 2 rule checks) through scan_path, scan_code, the CLI and the API."""

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from codeguard import api, scan
from codeguard.agents.ai_mistake_finder import ALL_CHECKS
from codeguard.cli import app as cli_app
from codeguard.models import Detector, ToolState
from codeguard.scanners.semgrep import build_command

from conftest import FakeIndex


def no_external_scanners(monkeypatch):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    monkeypatch.setattr("codeguard.scanners.bandit.find_bandit", lambda: None)


CODE = 'import yaml\nimport fastjsonx\n\nAPI_KEY = "YOUR_API_KEY_HERE"\n\n\ndef load(t):\n    return yaml.load(t)\n'


def test_scan_code_includes_rule_checks(monkeypatch):
    no_external_scanners(monkeypatch)
    result = scan.scan_code(CODE, "loader.py", index=FakeIndex())
    assert result.target == "loader.py"
    states = {r.tool: r.state for r in result.tool_runs}
    assert states["semgrep"] == ToolState.MISSING and states["bandit"] == ToolState.MISSING
    assert all(states[t] == ToolState.OK for t in ALL_CHECKS)
    got = {(f.evidence.rule_ids[0], f.file, f.line_start) for f in result.findings}
    assert got == {("CG-PKG-001", "loader.py", 2), ("CG-SEC-003", "loader.py", 4), ("CG-DEP-004", "loader.py", 8)}
    assert all(f.detectors == [Detector.RULE_CHECK] for f in result.findings)


def test_pasted_file_name_is_its_own_module(monkeypatch):
    # "import helpers" inside helpers.py is the file itself, not a PyPI package.
    no_external_scanners(monkeypatch)
    index = FakeIndex()
    scan.scan_code("import helpers\n", "helpers.py", index=index)
    assert index.calls == []


def test_semgrep_does_not_skip_test_folders():
    # Regression: Semgrep's default ignore list silently skipped every tests/ folder.
    cmd = build_command("semgrep", type("S", (), {"semgrep_config": "p/python"})(), type("T", (), {"arg": "."})())
    assert "--x-ignore-semgrepignore-files" in cmd and "--no-git-ignore" in cmd


def test_api_returns_rule_findings(monkeypatch):
    no_external_scanners(monkeypatch)
    monkeypatch.setattr(api, "scan_code", lambda code, filename: scan.scan_code(code, filename, index=FakeIndex()))
    res = TestClient(api.app).post("/api/scan", json={"code": CODE, "filename": "loader.py"})
    assert res.status_code == 200
    body = res.json()
    assert {f["evidence"]["rule_ids"][0] for f in body["findings"]} == {"CG-PKG-001", "CG-SEC-003", "CG-DEP-004"}
    assert {r["tool"] for r in body["tool_runs"]} >= set(ALL_CHECKS)


def test_cli_shows_rule_checks_and_skipped_state(monkeypatch, tmp_path):
    no_external_scanners(monkeypatch)
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    monkeypatch.setattr(
        "codeguard.cli.scan_path", lambda p, settings: scan.scan_path(p, settings, index=FakeIndex(down=True))
    )
    res = CliRunner().invoke(cli_app, ["scan", str(tmp_path)], env={"COLUMNS": "200"})
    assert res.exit_code == 0, res.output
    assert "rule:packages" in res.output and "skipped" in res.output
    assert "CG-DEP-004" in res.output and "CG-SEC-003" in res.output


def test_cli_offline_flag_sets_offline(monkeypatch, tmp_path):
    seen = {}

    def fake_scan_path(p, settings):
        seen["offline"] = settings.offline
        return scan.ScanResult(target=str(p))

    monkeypatch.setattr("codeguard.cli.scan_path", fake_scan_path)
    res = CliRunner().invoke(cli_app, ["scan", str(tmp_path), "--offline"])
    assert res.exit_code == 0, res.output
    assert seen == {"offline": True}
