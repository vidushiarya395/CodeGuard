"""Secret values are masked in every finding from every detector (codeguard.redact)."""

import json

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from codeguard import api, scan
from codeguard.cli import app as cli_app
from codeguard.models import Detector, Evidence, Finding, ScanResult, ToolRun, ToolState

from conftest import FakeIndex, requires_bandit

SECRET = "Tr0ub4dor-prod-42"
MASKED = "Tr0u********"
CODE = f'DB_PASSWORD = "{SECRET}"\n'


def bandit_like(file, line, test_id, cwe, text, code):
    """A finding exactly as the Bandit parser builds it: raw line, value quoted in the message."""
    return Finding(
        file=file,
        line_start=line,
        line_end=line,
        cwe=cwe,
        cwe_group={"CWE-798": "hardcoded-credentials", "CWE-89": "sql-injection"}.get(cwe, cwe),
        title=text,
        detectors=[Detector.BANDIT],
        evidence=Evidence(rule_ids=[test_id], matched_code=code, messages=[f"[bandit {test_id}] {text}"]),
    )


def fake_agent1(monkeypatch, make_findings):
    """Replace Semgrep + Bandit with findings built from the scanned file (no tools needed)."""

    def fake(path, settings, groups):
        file = path.name if path.is_file() else "test4.py"
        return ScanResult(
            target=str(path),
            findings=make_findings(file),
            tool_runs=[ToolRun(tool="bandit", state=ToolState.OK)],
        )

    monkeypatch.setattr(scan.standard_scanner, "scan_path", fake)


def b105(file):
    return [
        bandit_like(file, 1, "B105", "CWE-798", f"Possible hardcoded password: '{SECRET}'", CODE.rstrip("\n"))
    ]


def assert_masked(text):
    assert SECRET not in text
    assert "prod-42" not in text
    assert MASKED in text


def test_cli_table_json_and_api_never_show_the_secret(monkeypatch, tmp_path):
    fake_agent1(monkeypatch, b105)
    (tmp_path / "test4.py").write_text(CODE, encoding="utf-8")
    monkeypatch.setattr(
        "codeguard.cli.scan_path", lambda p, settings: scan.scan_path(p, settings, index=FakeIndex())
    )
    runner = CliRunner()

    table = runner.invoke(cli_app, ["scan", str(tmp_path / "test4.py")], env={"COLUMNS": "250"})
    assert table.exit_code == 0, table.output
    assert_masked(table.output)

    as_json = runner.invoke(cli_app, ["scan", str(tmp_path / "test4.py"), "--json"])
    assert as_json.exit_code == 0, as_json.output
    assert_masked(as_json.output)
    bandit = next(f for f in json.loads(as_json.output)["findings"] if f["detectors"] == ["bandit"])
    assert MASKED in bandit["title"] and MASKED in bandit["evidence"]["matched_code"]
    assert all(SECRET not in m for m in bandit["evidence"]["messages"])

    monkeypatch.setattr(api, "scan_code", lambda code, filename: scan.scan_code(code, filename, index=FakeIndex()))
    res = TestClient(api.app).post("/api/scan", json={"code": CODE, "filename": "test4.py"})
    assert res.status_code == 200
    assert_masked(res.text)


@requires_bandit
def test_real_bandit_finding_is_masked(monkeypatch, tmp_path):
    monkeypatch.setattr("codeguard.scanners.semgrep.find_semgrep", lambda s: None)
    (tmp_path / "test4.py").write_text(CODE, encoding="utf-8")
    result = scan.scan_path(tmp_path / "test4.py", index=FakeIndex())
    assert any(Detector.BANDIT in f.detectors for f in result.findings)
    assert_masked(result.model_dump_json())


def test_only_the_credential_is_masked_on_its_line(monkeypatch, tmp_path):
    code = f'conn = connect(host="db.example.com", password="{SECRET}")\n'
    fake_agent1(
        monkeypatch,
        lambda file: [
            bandit_like(file, 1, "B106", "CWE-798", f"Possible hardcoded password: '{SECRET}'", code.rstrip("\n"))
        ],
    )
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    out = scan.scan_path(tmp_path / "app.py", index=FakeIndex()).model_dump_json()
    assert_masked(out)
    assert "db.example.com" in out


def test_credential_line_without_a_secret_like_name_is_masked(monkeypatch, tmp_path):
    # Semgrep-style: the message does not quote the value, and "DB_PASS" is not a name the
    # secrets rule knows. The flagged line's literal is still masked.
    code = f'DB_PASS = "{SECRET}"\n'

    def semgrep_like(file):
        f = bandit_like(file, 1, "python.hardcoded-password", "CWE-798", "Hard-coded password", code.rstrip("\n"))
        f.detectors = [Detector.SEMGREP]
        return [f]

    fake_agent1(monkeypatch, semgrep_like)
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    assert_masked(scan.scan_path(tmp_path / "app.py", index=FakeIndex()).model_dump_json())


def test_ordinary_code_and_placeholders_are_not_masked(monkeypatch, tmp_path):
    code = 'API_KEY = "YOUR_API_KEY_HERE"\nquery = "SELECT name FROM users WHERE id = " + uid\n'
    fake_agent1(
        monkeypatch,
        lambda file: [
            bandit_like(file, 1, "B105", "CWE-798", "Possible hardcoded password: 'YOUR_API_KEY_HERE'", code.split("\n")[0]),
            bandit_like(file, 2, "B608", "CWE-89", "Possible SQL injection vector", code.split("\n")[1]),
        ],
    )
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    result = scan.scan_path(tmp_path / "app.py", index=FakeIndex())
    bandit = {f.evidence.rule_ids[0]: f for f in result.findings if Detector.BANDIT in f.detectors}
    assert "YOUR_API_KEY_HERE" in bandit["B105"].title
    assert bandit["B608"].evidence.matched_code == code.split("\n")[1]
    assert "*" not in result.model_dump_json()
