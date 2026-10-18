"""Hallucinated packages (CG-PKG-001) and known-vulnerable pinned versions (CG-OSV-001)."""

from __future__ import annotations

import ast
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from codeguard.cwe import CweGroups
from codeguard.models import Finding
from codeguard.rulechecks.loader import ImportMapFile, RuleMeta
from codeguard.rulechecks.netclient import LookupFailed, NetworkDown, PackageIndex, canonical_name, is_valid_name
from codeguard.rulechecks.source import SourceFile, SourceSet, make_finding

STDLIB = frozenset(sys.stdlib_module_names) | {"__future__", "__main__"}
MAX_LOOKUP_THREADS = 8
MAX_ADVISORIES_SHOWN = 10

# PEP 508 name with optional extras and version, e.g. requests, uvicorn[standard], flask==2.0.1
_REQ = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;]*)"
)
_PINNED = re.compile(r"^\s*===?\s*(?P<ver>[A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$")
_PIP_INSTALL = re.compile(r"(?:^|[\s!`\"'(;&|])(?:python3?(?:\.\d+)?\s+-m\s+)?pip3?\s+install\s+(?P<args>.*)$", re.I)
# pip options that take a value, so the next word is not a package
_PIP_VALUE_OPTS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
    "--platform", "--python-version", "--implementation", "--abi", "--trusted-host", "--src",
    "--upgrade-strategy", "--progress-bar", "--cache-dir", "--log", "--proxy", "--timeout",
}  # fmt: skip


@dataclass
class PackageRef:
    """One place where the code depends on a PyPI package."""

    pypi_name: str
    file: SourceFile
    line: int
    origin: str  # "import", "requirements" or "pip install"
    shown_as: str  # what the code wrote, e.g. the import name
    version: str | None = None  # only for exact pins (name==1.2.3)


@dataclass
class PackageCheckResult:
    pkg_findings: list[Finding] = field(default_factory=list)
    osv_findings: list[Finding] = field(default_factory=list)
    names_total: int = 0
    names_unchecked: list[str] = field(default_factory=list)
    versions_total: int = 0
    versions_unchecked: list[str] = field(default_factory=list)
    pypi_problem: str | None = None
    osv_problem: str | None = None


# --- Finding the references ---


def map_import(module: str, import_map: dict[str, str | None]) -> tuple[bool, str | None]:
    """Return (known, pypi_name). Longest dotted prefix in the map wins; otherwise the top name."""
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if key in import_map:
            return True, import_map[key]
    return False, parts[0]


def import_refs(src: SourceFile, local_modules: set[str], import_map: dict[str, str | None]) -> list[PackageRef]:
    if src.tree is None:
        return []
    refs: list[PackageRef] = []
    seen: set[str] = set()
    for node in ast.walk(src.tree):
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules = [node.module]
        else:
            continue  # relative imports (from . import x) are always the project's own code
        for module in modules:
            top = module.split(".")[0]
            if top in STDLIB or top in local_modules:
                continue
            known, pypi = map_import(module, import_map)
            if pypi is None:  # mapped to null: not distributed on PyPI
                continue
            key = canonical_name(pypi)
            if key in seen:
                continue
            seen.add(key)
            shown = module if known and "." in module else top
            refs.append(PackageRef(pypi, src, node.lineno, "import", shown))
    refs.sort(key=lambda r: r.line)
    return refs


def parse_requirement(text: str) -> tuple[str, str | None] | None:
    """'flask[async]==2.0.1 ; python_version>"3"' -> ("flask", "2.0.1"). None if not a plain requirement."""
    text = text.strip()
    if not text or text.startswith(("-", ".", "/", "\\")):
        return None
    m = _REQ.match(text)
    if not m:
        return None
    spec = m.group("spec").strip()
    if spec.startswith("@"):
        return m.group("name"), None  # direct reference: name @ url
    if "://" in text:
        return None  # a bare URL such as git+https://...
    if spec and not re.match(r"^[<>=!~]", spec):
        return None  # not a requirement (e.g. a stray sentence)
    pinned = _PINNED.match(spec) if spec else None
    version = pinned.group("ver") if pinned and "*" not in pinned.group("ver") else None
    return m.group("name"), version


def requirements_refs(src: SourceFile) -> list[PackageRef]:
    refs = []
    for lineno, raw in enumerate(src.lines, start=1):
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0]
        parsed = parse_requirement(line)
        if parsed and is_valid_name(parsed[0]):
            name, version = parsed
            refs.append(PackageRef(name, src, lineno, "requirements", name, version))
    return refs


def pip_install_refs(src: SourceFile) -> list[PackageRef]:
    """Packages named in "pip install ..." lines (comments, docstrings, strings, notebooks' !pip)."""
    refs = []
    for lineno, raw in enumerate(src.lines, start=1):
        m = _PIP_INSTALL.search(raw)
        if not m:
            continue
        args = re.split(r"&&|\|\||[;|`\"')]|\s#", m.group("args"))[0]
        skip_next = False
        for word in args.split():
            if skip_next:
                skip_next = False
                continue
            if word.startswith("-"):
                skip_next = word in _PIP_VALUE_OPTS
                continue
            word = word.strip(",.:")
            if not word or any(c in word for c in "/\\:") or word.endswith((".txt", ".whl", ".gz", ".zip")):
                continue
            parsed = parse_requirement(word)
            if parsed and is_valid_name(parsed[0]):
                refs.append(PackageRef(parsed[0], src, lineno, "pip install", parsed[0], parsed[1]))
    return refs


def collect_refs(sources: SourceSet, import_map: ImportMapFile) -> list[PackageRef]:
    refs: list[PackageRef] = []
    for src in sources.python:
        refs += import_refs(src, sources.local_modules, import_map.map)
        refs += pip_install_refs(src)
    for src in sources.requirements:
        refs += requirements_refs(src)
    return refs


# --- Looking them up ---


def _lookup_all(keys: list, fn) -> tuple[dict, list, str | None]:
    """Look up every key in parallel. Returns (answers, keys that could not be checked, first problem)."""
    answers: dict = {}
    unchecked: list = []
    first_problem: str | None = None

    def one(key):
        try:
            return key, fn(*key) if isinstance(key, tuple) else fn(key), None
        except (NetworkDown, LookupFailed) as exc:
            return key, None, str(exc)

    if not keys:
        return answers, unchecked, None
    with ThreadPoolExecutor(max_workers=min(MAX_LOOKUP_THREADS, len(keys))) as pool:
        for key, value, problem in pool.map(one, keys):
            if problem is None:
                answers[key] = value
            else:
                unchecked.append(key)
                first_problem = first_problem or problem
    return answers, unchecked, first_problem


def check_packages(
    sources: SourceSet,
    rules: dict[str, RuleMeta],
    import_map: ImportMapFile,
    index: PackageIndex,
    groups: CweGroups,
) -> PackageCheckResult:
    result = PackageCheckResult()
    refs = collect_refs(sources, import_map)

    names = sorted({canonical_name(r.pypi_name) for r in refs})
    result.names_total = len(names)
    exists, unchecked, result.pypi_problem = _lookup_all(names, index.pypi_exists)
    result.names_unchecked = unchecked

    pkg_rule = rules["CG-PKG-001"]
    reported: set[tuple[str, str]] = set()
    for ref in refs:
        key = canonical_name(ref.pypi_name)
        if exists.get(key) is not False or (ref.file.rel, key) in reported:
            continue
        reported.add((ref.file.rel, key))
        if ref.origin == "import":
            mapped = f" (looked up as '{ref.pypi_name}')" if canonical_name(ref.shown_as) != key else ""
            detail = f"'{ref.shown_as}' is imported, but PyPI has no package named '{ref.pypi_name}'{mapped}."
            title = f"Imported package '{ref.shown_as}' does not exist on PyPI"
        else:
            detail = f"'{ref.pypi_name}' is listed in {ref.origin}, but PyPI has no package with this name."
            title = f"Package '{ref.pypi_name}' does not exist on PyPI"
        detail += " If it is a module of your own project that was not part of this scan, you can ignore this."
        result.pkg_findings.append(
            make_finding(
                pkg_rule,
                ref.file,
                ref.line,
                ref.line,
                groups,
                title=title,
                detail=detail,
                extra_refs=[f"https://pypi.org/project/{key}/"],
            )
        )

    # Known vulnerabilities, only for exact pins of packages that exist (or could not be checked).
    pinned = [r for r in refs if r.version and exists.get(canonical_name(r.pypi_name)) is not False]
    versions = sorted({(canonical_name(r.pypi_name), r.version) for r in pinned})
    result.versions_total = len(versions)
    vulns, unchecked_v, result.osv_problem = _lookup_all(versions, index.osv_vulns)
    result.versions_unchecked = [f"{n}=={v}" for n, v in unchecked_v]

    osv_rule = rules["CG-OSV-001"]
    for ref in pinned:
        found = vulns.get((canonical_name(ref.pypi_name), ref.version)) or []
        if not found:
            continue
        ids = [v["id"] for v in found]
        lines = []
        for v in found[:MAX_ADVISORIES_SHOWN]:
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            alias = f" ({', '.join(cves[:2])})" if cves else ""
            lines.append(f"{v['id']}{alias}: {v.get('summary') or 'no summary'}")
        if len(found) > MAX_ADVISORIES_SHOWN:
            lines.append(f"... and {len(found) - MAX_ADVISORIES_SHOWN} more advisories")
        n = len(found)
        result.osv_findings.append(
            make_finding(
                osv_rule,
                ref.file,
                ref.line,
                ref.line,
                groups,
                title=f"{ref.pypi_name}=={ref.version} has {n} known {'vulnerability' if n == 1 else 'vulnerabilities'}",
                detail=f"OSV lists {n} advisor{'y' if n == 1 else 'ies'} for {ref.pypi_name} {ref.version} ({ref.origin}).",
                extra_messages=lines,
                extra_refs=[f"https://osv.dev/vulnerability/{i}" for i in ids[:MAX_ADVISORIES_SHOWN]],
            )
        )
    return result
