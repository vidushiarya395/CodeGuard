"""Agent 2: AI-Mistake Finder, rule-check part (no AI).

Five checks, every rule defined in rules/*.yaml:
  rule:packages            imported or listed packages that do not exist on PyPI
  rule:vulnerable-versions pinned versions with known vulnerabilities (OSV)
  rule:deprecated-apis     deprecated or unsafe functions
  rule:secrets             hard-coded and placeholder secrets
  rule:insecure-settings   debug=True, verify=False and similar

Each check reports its own ToolRun, so the CLI and UI can say exactly what ran, what was
skipped (e.g. no internet for PyPI / OSV) and why. Like Agent 1, it only collects findings;
merging and ranking is the Verifier's job (Agent 3).

The AI part of Agent 2 (LLM checklist review and the open question) is in llm_review.py.
"""

from __future__ import annotations

import time
from pathlib import Path

from codeguard import __version__
from codeguard.config import Settings, get_settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.models import Finding, ToolRun, ToolState
from codeguard.rulechecks.loader import RuleFileError, Rulebook, get_rulebook
from codeguard.rulechecks.netclient import HttpPackageIndex, PackageIndex
from codeguard.rulechecks.packages import check_packages
from codeguard.rulechecks.pyast import check_ast_rules
from codeguard.rulechecks.secrets import SecretMatcher, check_secrets
from codeguard.rulechecks.source import SourceSet, dedupe, load_sources
from codeguard.scanners.base import ScannerOutcome

PACKAGES = "rule:packages"
VULN_VERSIONS = "rule:vulnerable-versions"
DEPRECATED = "rule:deprecated-apis"
SECRETS = "rule:secrets"
SETTINGS = "rule:insecure-settings"
ALL_CHECKS = (PACKAGES, VULN_VERSIONS, DEPRECATED, SECRETS, SETTINGS)

MAX_NAMES_IN_MESSAGE = 5


def run_rule_checks(
    path: Path,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
    rulebook: Rulebook | None = None,
    display_name: str | None = None,
) -> list[ScannerOutcome]:
    settings = settings or get_settings()
    groups = groups or get_cwe_groups()
    try:
        book = rulebook or get_rulebook(settings.rules_dir)
    except RuleFileError as exc:
        return [ScannerOutcome(ToolRun(tool=t, state=ToolState.FAILED, message=f"Rule file problem: {exc}")) for t in ALL_CHECKS]

    start = time.perf_counter()
    sources = load_sources(path, display_name)
    load_time = time.perf_counter() - start
    index = index or HttpPackageIndex(settings.cache_dir, settings.net_timeout_s, settings.offline)

    outcomes = [
        *_package_outcomes(sources, book, index, groups),
        # File problems (unreadable, not valid Python) are listed once, on the first local check.
        _local_outcome(
            DEPRECATED, sources, lambda s: check_ast_rules(s, book.deprecated.rules, groups), load_time, sources.errors
        ),
        _local_outcome(SECRETS, sources, _secrets_fn(book, groups)),
        _local_outcome(SETTINGS, sources, lambda s: check_ast_rules(s, book.settings.rules, groups)),
    ]
    return outcomes


def _secrets_fn(book: Rulebook, groups: CweGroups):
    matcher = SecretMatcher(book.secrets)
    return lambda s: check_secrets(s, book.secrets, groups, matcher)


def _local_outcome(
    tool: str, sources: SourceSet, fn, load_time: float = 0.0, file_errors: list[str] | None = None
) -> ScannerOutcome:
    """Run a check that needs no network over every Python file."""
    start = time.perf_counter()
    findings: list[Finding] = []
    for src in sources.python:
        findings += fn(src)
    findings = dedupe(findings)
    run = ToolRun(
        tool=tool,
        state=ToolState.OK,
        version=__version__,
        duration_s=round(time.perf_counter() - start + load_time, 3),
        findings_count=len(findings),
        file_errors=list(file_errors or []),
    )
    return ScannerOutcome(run, findings)


def _package_outcomes(sources: SourceSet, book: Rulebook, index: PackageIndex, groups: CweGroups) -> list[ScannerOutcome]:
    start = time.perf_counter()
    rules = {r.id: r for r in book.packages.rules}
    try:
        res = check_packages(sources, rules, book.import_map, index, groups)
    except Exception as exc:  # a bug here must not take down the whole scan
        msg = f"Package check failed: {type(exc).__name__}: {exc}"
        return [ScannerOutcome(ToolRun(tool=t, state=ToolState.FAILED, message=msg)) for t in (PACKAGES, VULN_VERSIONS)]
    duration = round(time.perf_counter() - start, 3)

    pkg_run = _network_run(
        PACKAGES, "PyPI", res.names_total, res.names_unchecked, "package name", res.pypi_problem, duration
    )
    pkg_run.findings_count = len(res.pkg_findings)
    osv_run = _network_run(
        VULN_VERSIONS, "OSV", res.versions_total, res.versions_unchecked, "pinned version", res.osv_problem, duration
    )
    osv_run.findings_count = len(res.osv_findings)
    return [ScannerOutcome(pkg_run, res.pkg_findings), ScannerOutcome(osv_run, res.osv_findings)]


def _network_run(
    tool: str, service: str, total: int, unchecked: list[str], what: str, problem: str | None, duration: float
) -> ToolRun:
    if total == 0:
        return ToolRun(tool=tool, state=ToolState.OK, version=__version__, duration_s=duration, message=f"No {what}s to check.")
    if not unchecked:
        return ToolRun(tool=tool, state=ToolState.OK, version=__version__, duration_s=duration)
    names = ", ".join(unchecked[:MAX_NAMES_IN_MESSAGE]) + (" ..." if len(unchecked) > MAX_NAMES_IN_MESSAGE else "")
    reason = f" ({problem})" if problem else ""
    if len(unchecked) == total:
        if problem and problem.startswith("offline mode"):
            why = "offline mode is on (--offline or CODEGUARD_OFFLINE=1) and no cached answer was found"
        else:
            why = f"{service} could not be reached{reason}"
        return ToolRun(
            tool=tool,
            state=ToolState.SKIPPED,
            version=__version__,
            duration_s=duration,
            message=f"Skipped: {why}. {total} {what}(s) were not checked.",
        )
    return ToolRun(
        tool=tool,
        state=ToolState.OK,
        version=__version__,
        duration_s=duration,
        message=f"{len(unchecked)} of {total} {what}s could not be checked{reason}: {names}",
    )
