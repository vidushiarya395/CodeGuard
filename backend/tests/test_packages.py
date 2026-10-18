"""Package checks (PyPI / OSV), the disk cache and the no-internet behaviour. No real network is used."""

import urllib.error

import pytest

from codeguard.agents.ai_mistake_finder import PACKAGES, VULN_VERSIONS, run_rule_checks
from codeguard.models import ToolState
from codeguard.rulechecks import netclient
from codeguard.rulechecks.netclient import HttpPackageIndex, JsonCache, NetworkDown, canonical_name
from codeguard.rulechecks.packages import map_import, parse_requirement, pip_install_refs
from codeguard.rulechecks.source import SourceFile, is_requirements_file

from conftest import FakeIndex


def write(folder, files):
    for rel, text in files.items():
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return folder


def runs(outcomes):
    return {o.run.tool: o for o in outcomes}


# --- Parsing ---


@pytest.mark.parametrize(
    "line, expected",
    [
        ("flask==0.12", ("flask", "0.12")),
        ("Flask[async] == 2.0.1 ; python_version > '3.8'", ("Flask", "2.0.1")),
        ("requests>=2.31", ("requests", None)),
        ("requests", ("requests", None)),
        ("django==4.*", ("django", None)),
        ("mypkg @ https://example.com/mypkg.whl", ("mypkg", None)),
        ("-r other.txt", None),
        ("--index-url https://example.com", None),
        ("git+https://github.com/x/y.git", None),
        ("./local/path", None),
        ("", None),
    ],
)
def test_parse_requirement(line, expected):
    assert parse_requirement(line) == expected


def test_pip_install_lines():
    text = (
        "# pip install requests==2.19.0 flask -U\n"
        '"""Run: python -m pip install --index-url https://x.org/simple fastjsonx"""\n'
        "!pip install -r requirements.txt numpy\n"
        "x = 1  # nothing here\n"
        "# Install with pip install pandas.\n"
    )
    src = SourceFile(rel="a.py", text=text, lines=text.splitlines())
    got = [(r.pypi_name, r.version, r.line) for r in pip_install_refs(src)]
    assert got == [
        ("requests", "2.19.0", 1),
        ("flask", None, 1),
        ("fastjsonx", None, 2),
        ("numpy", None, 3),
        ("pandas", None, 5),
    ]


def test_map_import(rulebook):
    m = rulebook.import_map.map
    assert map_import("cv2", m) == (True, "opencv-python")
    assert map_import("google.cloud.storage.blob", m) == (True, "google-cloud-storage")
    assert map_import("google.something_else", m) == (False, "google")
    assert map_import("bpy.ops", m) == (True, None)
    assert map_import("numpy.linalg", m) == (False, "numpy")


def test_canonical_name():
    assert canonical_name("PyYAML") == canonical_name("pyyaml") == "pyyaml"
    assert canonical_name("python_dateutil") == "python-dateutil"


@pytest.mark.parametrize(
    "rel, expected",
    [("requirements.txt", True), ("requirements-dev.txt", True), ("requirements/base.txt", True),
     ("notes.txt", False), ("requirements.py", False)],
)  # fmt: skip
def test_is_requirements_file(rel, expected):
    assert is_requirements_file(rel) is expected


# --- What gets looked up ---


def test_stdlib_relative_and_local_modules_are_not_looked_up(tmp_path):
    write(
        tmp_path,
        {
            "app.py": "import os, json\nfrom . import views\nfrom helpers import util\nimport mypkg.sub\nimport cv2\n",
            "helpers.py": "",
            "mypkg/__init__.py": "",
            "mypkg/sub.py": "",
        },
    )
    index = FakeIndex()
    findings = [f for o in run_rule_checks(tmp_path, index=index) for f in o.findings]
    assert [c for c in index.calls if c[0] == "pypi"] == [("pypi", "opencv-python")]
    assert findings == []


def test_one_finding_per_file_and_package(tmp_path):
    write(tmp_path, {"a.py": "import fakepkgzz\nfrom fakepkgzz import x\n", "b.py": "import fakepkgzz.sub\n"})
    index = FakeIndex()
    pkg = runs(run_rule_checks(tmp_path, index=index))[PACKAGES]
    assert sorted((f.file, f.line_start) for f in pkg.findings) == [("a.py", 1), ("b.py", 1)]
    assert sum(1 for c in index.calls if c[0] == "pypi") == 1  # looked up once
    f = pkg.findings[0]
    assert f.cwe == "CWE-829" and f.cwe_group == "untrusted-package"
    assert "https://pypi.org/project/fakepkgzz/" in f.evidence.references


def test_requirements_and_osv(tmp_path):
    write(tmp_path, {"requirements.txt": "flask==0.12\nmadeuppkg-qq==1.0\nrequests>=2\n"})
    index = FakeIndex()
    out = runs(run_rule_checks(tmp_path, index=index))
    assert [(f.file, f.line_start) for f in out[PACKAGES].findings] == [("requirements.txt", 2)]
    osv = out[VULN_VERSIONS].findings
    assert [(f.line_start, f.cwe) for f in osv] == [(1, "CWE-1395")]
    assert osv[0].title == "flask==0.12 has 1 known vulnerability"
    assert any("GHSA-test-0001" in m and "CVE-2000-0001" in m for m in osv[0].evidence.messages)
    # A package that does not exist is not sent to OSV.
    assert ("osv", "madeuppkg-qq", "1.0") not in index.calls


# --- No internet ---


def test_network_down_marks_checks_skipped(tmp_path):
    write(tmp_path, {"app.py": "import requests\n", "requirements.txt": "flask==0.12\n"})
    out = runs(run_rule_checks(tmp_path, index=FakeIndex(down=True)))
    for tool in (PACKAGES, VULN_VERSIONS):
        assert out[tool].run.state == ToolState.SKIPPED, tool
        assert "could not be reached" in out[tool].run.message
        assert out[tool].findings == []
    # The checks that need no network still ran.
    assert all(o.run.state == ToolState.OK for t, o in out.items() if t not in (PACKAGES, VULN_VERSIONS))


def test_nothing_to_check_is_ok_even_offline(tmp_path):
    write(tmp_path, {"app.py": "import os\n"})
    out = runs(run_rule_checks(tmp_path, index=FakeIndex(down=True)))
    assert out[PACKAGES].run.state == ToolState.OK
    assert "No package names" in out[PACKAGES].run.message


class _FlakyIndex(FakeIndex):
    def pypi_exists(self, name):
        if name == "flask":
            raise NetworkDown("timeout")
        return super().pypi_exists(name)


def test_partial_failure_is_ok_with_message(tmp_path):
    write(tmp_path, {"app.py": "import requests\nimport flask\n"})
    run = runs(run_rule_checks(tmp_path, index=_FlakyIndex()))[PACKAGES].run
    assert run.state == ToolState.OK
    assert "1 of 2" in run.message and "flask" in run.message


# --- The real client, with the HTTP layer replaced ---


class _Resp:
    def __init__(self, body=b"{}"):
        self.body = body

    def read(self, *_):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_http_client_caches_answers(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        if "doesnotexist" in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        if "osv" in req.full_url:
            return _Resp(b'{"vulns": [{"id": "PYSEC-1", "summary": "bad", "aliases": ["CVE-1"]}]}')
        return _Resp()

    monkeypatch.setattr(netclient.urllib.request, "urlopen", fake_urlopen)
    idx = HttpPackageIndex(tmp_path, timeout_s=1)
    assert idx.pypi_exists("Requests") is True
    assert idx.pypi_exists("requests") is True  # same canonical name, from the cache
    assert idx.pypi_exists("doesnotexist") is False
    assert idx.osv_vulns("Flask", "0.12")[0]["id"] == "PYSEC-1"
    assert idx.osv_vulns("flask", "0.12")[0]["id"] == "PYSEC-1"
    assert len(calls) == 3

    # A new client (a later scan) reuses the disk cache, even with the network off.
    offline = HttpPackageIndex(tmp_path, offline=True)
    assert offline.pypi_exists("requests") is True
    assert offline.osv_vulns("flask", "0.12")[0]["id"] == "PYSEC-1"
    with pytest.raises(NetworkDown):
        offline.pypi_exists("numpy")
    assert len(calls) == 3


def test_http_client_fails_fast_after_network_error(tmp_path, monkeypatch):
    calls = []

    def no_network(req, timeout):
        calls.append(req.full_url)
        raise urllib.error.URLError("getaddrinfo failed")

    monkeypatch.setattr(netclient.urllib.request, "urlopen", no_network)
    idx = HttpPackageIndex(tmp_path, timeout_s=1)
    for name in ("a", "b", "c"):
        with pytest.raises(NetworkDown):
            idx.pypi_exists(name)
    assert len(calls) == 1
    assert "pypi.org" in idx.down_reason


def test_stale_cache_is_used_when_offline(tmp_path, monkeypatch):
    cache = JsonCache(tmp_path)
    cache.put("pypi", "requests", True)
    monkeypatch.setattr(netclient, "TTL_PYPI_EXISTS", -1)  # every cached answer counts as expired
    assert HttpPackageIndex(tmp_path, offline=True).pypi_exists("requests") is True


def test_cache_file_names_are_hashes(tmp_path):
    cache = JsonCache(tmp_path)
    cache.put("pypi", "../../evil", True)
    files = list((tmp_path / "pypi").iterdir())
    assert len(files) == 1 and ".." not in files[0].name
    assert cache.get("pypi", "../../evil")[0] is True


def test_real_world_imports_map_correctly(rulebook):
    # Found by scanning popular libraries.
    m = rulebook.import_map.map
    assert map_import("opentelemetry.trace", m) == (True, "opentelemetry-api")
    assert map_import("markdown_it", m) == (True, "markdown-it-py")
    assert map_import("_typeshed", m) == (True, None)
    assert map_import("annotationlib", m) == (True, None)
    assert map_import("_winreg", m) == (True, None)  # Python 2 standard library
    assert map_import("ctags", m) == (True, "python-ctags3")
