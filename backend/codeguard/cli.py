"""Command-line interface:  codeguard scan <path>"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from codeguard import __version__
from codeguard.agents.standard_scanner import ScanInputError, scan_path
from codeguard.models import ScanResult, ToolState

app = typer.Typer(add_completion=False, help="CodeGuard: security checker for AI-generated Python code.")

_STATE_STYLE = {
    ToolState.OK: "green",
    ToolState.MISSING: "yellow",
    ToolState.FAILED: "red",
    ToolState.TIMEOUT: "red",
}


@app.callback()
def main() -> None:
    """CodeGuard command-line tool."""


@app.command()
def version() -> None:
    """Print the CodeGuard version."""
    typer.echo(__version__)


@app.command()
def scan(
    path: Path = typer.Argument(..., help="A Python file or a folder to scan."),
    json_output: bool = typer.Option(False, "--json", help="Print the full result as JSON instead of a table."),
) -> None:
    """Scan a file or folder with Semgrep and Bandit and print the findings."""
    try:
        result = scan_path(path)
    except ScanInputError as exc:
        Console(stderr=True).print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    print_result(result, Console())


def print_result(result: ScanResult, console: Console) -> None:
    console.print(f"[bold]CodeGuard scan[/bold]  {result.target}  ({result.duration_s:.1f} s)")
    for run in result.tool_runs:
        style = _STATE_STYLE.get(run.state, "white")
        version = f" {run.version}" if run.version else ""
        line = f"  {run.tool}{version}: [{style}]{run.state.value}[/{style}]"
        if run.state == ToolState.OK:
            line += f" ({_plural(run.findings_count, 'finding')}, {run.duration_s:.1f} s)"
        console.print(line)
        if run.message:
            console.print(f"    {run.message}", style=style, markup=False)
        for err in run.file_errors[:5]:
            console.print(f"    file error: {err}", style="yellow", markup=False)

    if not result.findings:
        if any(r.state == ToolState.OK for r in result.tool_runs):
            console.print("\nNo findings from the scanners that ran.")
        else:
            console.print("\n[red]No scanner ran successfully, so nothing was checked.[/red]")
        return

    table = Table(header_style="bold")
    table.add_column("Location", overflow="fold")
    table.add_column("CWE / group", overflow="fold")
    table.add_column("Found by", overflow="fold")
    table.add_column("Tool severity", overflow="fold")
    table.add_column("Title", overflow="fold", ratio=1)
    for f in result.findings:
        lines = str(f.line_start) if f.line_start == f.line_end else f"{f.line_start}-{f.line_end}"
        rules = ", ".join(r.rsplit(".", 1)[-1] for r in f.evidence.rule_ids)
        table.add_row(
            f"{f.file}:{lines}",
            f"{f.cwe or '-'}\n{f.cwe_group}",
            f"{', '.join(d.value for d in f.detectors)}\n{rules}",
            ", ".join(f.evidence.tool_severity.values()) or "-",
            f.title,
        )
    console.print()
    console.print(table)
    console.print(
        f"{_plural(len(result.findings), 'raw finding')}. These are unverified scanner results; "
        "confidence and severity are added by the Verifier in a later phase.",
        style="dim",
    )


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


if __name__ == "__main__":
    app()
