"""Command-line interface:  codeguard scan <path>"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from codeguard import __version__
from codeguard.config import get_settings
from codeguard.models import ScanResult, ToolState
from codeguard.scan import ScanInputError, scan_path

app = typer.Typer(add_completion=False, help="CodeGuard: security checker for AI-generated Python code.")

_STATE_STYLE = {
    ToolState.OK: "green",
    ToolState.MISSING: "yellow",
    ToolState.FAILED: "red",
    ToolState.TIMEOUT: "red",
    ToolState.SKIPPED: "yellow",
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
    offline: bool = typer.Option(
        False, "--offline", help="Do not contact PyPI or OSV; package checks use cached answers only."
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the AI checklist review and open question (no code is sent to an AI service)."
    ),
) -> None:
    """Scan a file or folder with Semgrep, Bandit, CodeGuard's rule checks and the AI review, and print the findings."""
    settings = get_settings()
    if offline:
        settings = replace(settings, offline=True)
    if no_llm:
        settings = replace(settings, llm_review=False)
    try:
        result = scan_path(path, settings=settings)
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
        if run.llm:
            u = run.llm
            console.print(
                f"    {u.provider}/{u.model}, prompt {u.prompt_version}: "
                f"{_plural(u.calls, 'request')} sent, {_plural(u.cache_hits, 'cached answer')} reused",
                style="dim",
                markup=False,
            )
        for note in run.notes[:10]:
            console.print(f"    note: {note}", style="yellow", markup=False)
        if len(run.notes) > 10:
            console.print(f"    ... and {len(run.notes) - 10} more notes (see --json)", style="yellow")

    if not result.findings:
        if any(r.state == ToolState.OK for r in result.tool_runs):
            console.print("\nNo findings from the scanners and checks that ran.")
        else:
            console.print("\n[red]No scanner or check ran successfully, so nothing was checked.[/red]")
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
        f"{_plural(len(result.findings), 'raw finding')}. These are unverified results from the scanners "
        "rule checks and AI review; confidence and severity are added by the Verifier in a later phase.",
        style="dim",
    )


@app.command("check-llm")
def check_llm() -> None:
    """Send one tiny test request to the AI provider set in .env, to check the key works. No code is sent."""
    from codeguard.llm import LLMError, make_client
    from codeguard.llm.client import Prompt

    from pydantic import BaseModel

    class _Ok(BaseModel):
        ok: bool

    console = Console()
    settings = get_settings()
    try:
        client = make_client(settings)
        console.print(f"Provider: {client.name}   Model: {client.model}", markup=False)
        prompt = Prompt(
            id="connection-check",
            version="connection-check-v1",
            system="You answer only with JSON.",
            user='Reply with exactly this JSON object: {"ok": true}',
        )
        result = client.complete_json(prompt, _Ok, use_cache=False)
    except LLMError as exc:
        Console(stderr=True).print(f"[red]AI provider not working:[/red] {exc}", highlight=False)
        raise typer.Exit(code=1)
    source = _plural(result.requests, "request")
    version = f" (model version {result.model_version})" if result.model_version else ""
    console.print(f"[green]OK[/green]: the AI provider answered with valid JSON ({source}){version}.", highlight=False)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


if __name__ == "__main__":
    app()
