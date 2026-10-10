from fastapi.testclient import TestClient

from codeguard import api
from codeguard.agents.standard_scanner import ScanInputError
from codeguard.models import ScanResult, ToolRun, ToolState

client = TestClient(api.app)


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_scan_returns_result(monkeypatch):
    seen = {}

    def fake_scan(code, filename):
        seen["code"], seen["filename"] = code, filename
        return ScanResult(target="app.py", tool_runs=[ToolRun(tool="bandit", state=ToolState.OK)])

    monkeypatch.setattr(api, "scan_code", fake_scan)
    res = client.post("/api/scan", json={"code": "print(1)\n", "filename": "app.py"})
    assert res.status_code == 200
    body = res.json()
    assert body["target"] == "app.py"
    assert body["tool_runs"][0]["state"] == "ok"
    assert seen == {"code": "print(1)\n", "filename": "app.py"}


def test_scan_bad_input_is_422(monkeypatch):
    def fake_scan(code, filename):
        raise ScanInputError("The code is empty.")

    monkeypatch.setattr(api, "scan_code", fake_scan)
    res = client.post("/api/scan", json={"code": ""})
    assert res.status_code == 422
    assert res.json()["detail"] == "The code is empty."


def test_scan_requires_code_field():
    assert client.post("/api/scan", json={}).status_code == 422


def test_scan_rejects_huge_body():
    res = client.post("/api/scan", json={"code": "x" * (api.MAX_CODE_CHARS + 1)})
    assert res.status_code == 422
