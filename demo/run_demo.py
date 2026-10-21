"""Scan the demo apps and compare the findings with each app's expected.yaml.

For every app it prints what was found, missed and reported extra, and any finding on a line that
must stay quiet. These are demo results on small hand-written apps, NOT research results: the
apps and their expected lists were written by the CodeGuard author, and the findings are raw
(no Verifier yet). The research numbers come from benchmark/ only.

    python demo/run_demo.py                      # no AI review (uses no free-tier AI quota)
    python demo/run_demo.py --llm                # also run the AI review (provider from .env)
    python demo/run_demo.py --app flask_blog --show-extra
    python demo/run_demo.py --json demo-results.json

A finding counts for an expected vulnerability when it is in the same file, within 2 lines, and
its CWE is in the same CWE group (rules/cwe_groups.yaml). The demo apps are only read, never run.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

import typer
import yaml
from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console
from rich.table import Table

from codeguard.config import get_settings
from codeguard.cwe import CweGroups, get_cwe_groups, normalize_cwe
from codeguard.models import Finding, ScanResult, ToolState
from codeguard.scan import scan_path

DEMO_DIR = Path(__file__).resolve().parent
LINE_TOLERANCE = 2
QUIET_TOLERANCE = 1

app = typer.Typer(add_completion=False, help=__doc__.split("\n\n")[0])
console = Console()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Vulnerability(_Strict):
    file: str
    line: int = Field(ge=1)
    cwe: str
    also_cwe: list[str] = Field(default_factory=list)  # other CWE labels tools commonly use for it
    what: str

    def cwes(self) -> list[str]:
        return [c for c in (normalize_cwe(x) for x in [self.cwe, *self.also_cwe]) if c]


class Quiet(_Strict):
    file: str
    line: int = Field(ge=1)
    cwe: str | None = None  # None: nothing at all may be reported on this line
    why: str


class Expected(_Strict):
    app: str
    description: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    quiet: list[Quiet] = Field(default_factory=list)


def load_expected(folder: Path) -> Expected:
    data = yaml.safe_load((folder / "expected.yaml").read_text(encoding="utf-8"))
    expected = Expected.model_validate(data)
    for entry in [*expected.vulnerabilities, *expected.quiet]:
        path = folder / entry.file
        if not path.is_file():
            raise ValueError(f"{folder.name}/expected.yaml: {entry.file} does not exist")
        lines = path.read_text(encoding="utf-8").splitlines()
        if entry.line > len(lines) or not lines[entry.line - 1].strip():
            raise ValueError(f"{folder.name}/expected.yaml: {entry.file}:{entry.line} is not a code line")
    return expected


def demo_apps() -> list[Path]:
    return sorted(p for p in DEMO_DIR.iterdir() if (p / "expected.yaml").is_file())


@dataclass
class AppResult:
    app: str
    found: list[tuple[Vulnerability, list[Finding]]] = field(default_factory=list)
    missed: list[Vulnerability] = field(default_factory=list)
    extra: list[Finding] = field(default_factory=list)
    noisy: list[tuple[Quiet, Finding]] = field(default_factory=list)
    tool_problems: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def _near(f: Finding, file: str, line: int, tolerance: int) -> bool:
    return f.file == file and f.line_start - tolerance <= line <= f.line_end + tolerance


def _group(cwe: str | None, groups: CweGroups) -> str:
    return groups.group_of(cwe)


def compare(expected: Expected, result: ScanResult, groups: CweGroups, llm: bool = False) -> AppResult:
    out = AppResult(app=expected.app, duration_s=result.duration_s)
    matched: set[str] = set()
    for vuln in expected.vulnerabilities:
        vuln_groups = {_group(c, groups) for c in vuln.cwes()}
        hits = [
            f
            for f in result.findings
            if _near(f, vuln.file, vuln.line, LINE_TOLERANCE) and _group(f.cwe, groups) in vuln_groups
        ]
        if hits:
            out.found.append((vuln, hits))
            matched.update(f.id for f in hits)
        else:
            out.missed.append(vuln)
    for f in result.findings:
        if f.id in matched:
            continue
        out.extra.append(f)
        for q in expected.quiet:
            if _near(f, q.file, q.line, QUIET_TOLERANCE) and (q.cwe is None or _group(f.cwe, groups) == _group(normalize_cwe(q.cwe), groups)):
                out.noisy.append((q, f))
    out.tool_problems = [
        f"{r.tool}: {r.state.value}" + (f" ({r.message})" if r.message else "")
        for r in result.tool_runs
        if r.state != ToolState.OK and (llm or not r.tool.startswith("llm:"))  # AI review off on purpose
    ]
    return out


def _detectors(findings: list[Finding]) -> str:
    return ", ".join(sorted({d.value for f in findings for d in f.detectors}))


def _finding_label(f: Finding) -> str:
    lines = str(f.line_start) if f.line_start == f.line_end else f"{f.line_start}-{f.line_end}"
    rules = ",".join(r.rsplit(".", 1)[-1] for r in f.evidence.rule_ids)
    return f"{f.file}:{lines} {f.cwe or 'no CWE'} [{_detectors([f])}: {rules}] {f.title}"


def print_app(r: AppResult, show_extra: bool) -> None:
    total = len(r.found) + len(r.missed)
    console.print(f"\n[bold]{r.app}[/bold]  found {len(r.found)}/{total}, missed {len(r.missed)}, "
                  f"extra {len(r.extra)}, quiet lines broken {len(r.noisy)}  ({r.duration_s:.1f} s)")  # fmt: skip
    for problem in r.tool_problems:
        console.print(f"  tool: {problem}", style="yellow", markup=False)
    for vuln, hits in r.found:
        console.print(f"  found   {vuln.file}:{vuln.line} {vuln.cwe}  {vuln.what}  (by {_detectors(hits)})", markup=False)
    for vuln in r.missed:
        console.print(f"  MISSED  {vuln.file}:{vuln.line} {vuln.cwe}  {vuln.what}", style="red", markup=False)
    for q, f in r.noisy:
        console.print(f"  NOISE   {_finding_label(f)}  (should stay quiet: {q.why})", style="magenta", markup=False)
    if show_extra:
        for f in r.extra:
            console.print(f"  extra   {_finding_label(f)}", style="dim", markup=False)
    elif r.extra:
        by_detector: dict[str, int] = {}
        for f in r.extra:
            key = _detectors([f])
            by_detector[key] = by_detector.get(key, 0) + 1
        summary = ", ".join(f"{k} {v}" for k, v in sorted(by_detector.items()))
        console.print(f"  extra by detector: {summary}  (--show-extra lists them)", style="dim", markup=False)


@app.command()
def main(
    apps: list[str] = typer.Option([], "--app", help="Only these demo apps (folder names). Default: all."),
    llm: bool = typer.Option(False, "--llm", help="Also run the AI review (uses the provider and quota from .env)."),
    offline: bool = typer.Option(False, "--offline", help="Do not contact PyPI or OSV (cached answers only)."),
    show_extra: bool = typer.Option(False, "--show-extra", help="List every extra finding."),
    json_out: Path | None = typer.Option(None, "--json", help="Also write the results to this JSON file."),
) -> None:
    settings = replace(get_settings(), llm_review=llm, offline=offline or get_settings().offline)
    groups = get_cwe_groups()
    folders = demo_apps()
    if apps:
        unknown = sorted(set(apps) - {f.name for f in folders})
        if unknown:
            console.print(f"[red]Unknown demo app(s): {', '.join(unknown)}[/red]")
            raise typer.Exit(2)
        folders = [f for f in folders if f.name in apps]

    console.print("[bold]CodeGuard demo suite[/bold]: raw findings (no Verifier yet) on hand-written demo apps. "
                  "Demo results, not research results.")  # fmt: skip
    console.print(f"AI review: {'on' if llm else 'off (run with --llm to include it)'}")
    results: list[AppResult] = []
    for folder in folders:
        expected = load_expected(folder)
        result = scan_path(folder, settings=settings, groups=groups)
        r = compare(expected, result, groups, llm)
        results.append(r)
        print_app(r, show_extra)

    table = Table(title="Summary", header_style="bold")
    for col in ("App", "Expected", "Found", "Missed", "Extra", "Quiet broken"):
        table.add_column(col, justify="left" if col == "App" else "right")
    for r in results:
        table.add_row(r.app, str(len(r.found) + len(r.missed)), str(len(r.found)), str(len(r.missed)),
                      str(len(r.extra)), str(len(r.noisy)))  # fmt: skip
    totals = [sum(len(r.found) + len(r.missed) for r in results), sum(len(r.found) for r in results),
              sum(len(r.missed) for r in results), sum(len(r.extra) for r in results), sum(len(r.noisy) for r in results)]  # fmt: skip
    table.add_row("[bold]total[/bold]", *(str(t) for t in totals))
    console.print()
    console.print(table)

    if json_out:
        data = [
            {
                "app": r.app,
                "found": [{**v.model_dump(), "detectors": _detectors(h)} for v, h in r.found],
                "missed": [v.model_dump() for v in r.missed],
                "extra": [_finding_label(f) for f in r.extra],
                "quiet_broken": [{"quiet": q.model_dump(), "finding": _finding_label(f)} for q, f in r.noisy],
                "tool_problems": r.tool_problems,
                "ai_review": llm,
            }
            for r in results
        ]
        json_out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"Results written to {json_out}")


if __name__ == "__main__":
    sys.exit(app())
