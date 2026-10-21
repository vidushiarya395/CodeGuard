"""Phase 4 pilot benchmark on CodeSecEval's calibration split (go / no-go checkpoint).

    python -m benchmark.pilot run          every step below, in order
    python -m benchmark.pilot status       how far the run has got
    python -m benchmark.pilot --tag v2 scan      scan the same samples again into scans-v2/
    python -m benchmark.pilot --tag v2 evaluate  score them into metrics-v2.csv, per_sample-v2.csv, ...
    python -m benchmark.pilot compare --new v2   the original run next to the v2 run

Steps (each can also be run on its own):
    download   fetch CodeSecEval at the pinned commit and check its SHA-256
    split      make (once) or check the 20/80 calibration/test split, seed 42
    refcheck   run each calibration task's reference solutions in the sandbox (is the task usable?)
    generate   one sample per usable task from the default model (temperature 0)
    label      run the dataset's tests on each sample in the sandbox
    scan       scan each labelled sample with CodeGuard (Semgrep, Bandit, rule checks, LLM review)
    evaluate   score every tool on the same samples and write the CSV files

Every step saves one file per task and skips tasks that already have one, so the run can be
stopped and started again at any time. When the free daily AI limit is reached, the step stops
with exit code 3 and the run continues from the same point the next day.

A tag (--tag v2) keeps a second set of scans and results next to the original ones, for the same
samples and labels (samples and labels are shared by every tag). Untagged files are never written
by a tagged run.

Only calibration tasks are used. Nothing here is tuned.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import logging
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from codeguard import __version__
from codeguard.config import get_settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.llm.base import LLMError, LLMUnavailable, QuotaExhausted
from codeguard.llm.client import make_client
from codeguard.llm.prompts import CHECKLIST_PROMPT_VERSION
from codeguard.models import Finding, ScanResult, ToolState
from codeguard.scan import scan_code

from benchmark import compare as cmp
from benchmark import datasets, labels, sandbox, score, splits
from benchmark.datasets import CODESECEVAL, Task
from benchmark.generate import GENERATE_PROMPT_VERSION, generate_sample
from benchmark.metrics import METRIC_COLUMNS, confusion, metric_row, write_csv
from benchmark.paths import RUNS_DIR

RUN_DIR = RUNS_DIR / "pilot-codeseceval"
PAUSED_EXIT = 3
DOCKER_WORKERS = 4
MAX_FAILURES_IN_A_ROW = 3  # the same error three times means the provider is not usable right now

app = typer.Typer(add_completion=False, help=__doc__.split("\n\n")[0], no_args_is_help=True)
console = Console()
_TAG = ""  # set by --tag; "" = the original run


@app.callback()
def _options(
    tag: str = typer.Option("", help="Keep scans and results apart under this tag, e.g. v2 (same samples and labels)."),
) -> None:
    global _TAG
    if tag and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,19}", tag):
        raise typer.BadParameter("use lower-case letters, digits and '-', for example v2")
    _TAG = tag


def _suffix(tag: str) -> str:
    return f"-{tag}" if tag else ""


class Paused(Exception):
    """The free daily AI limit is used up. Everything done so far is saved."""


# --- small helpers ---


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def _load(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _client():
    """The generator and reviewer: the provider chosen in .env (LLM_PROVIDER)."""
    try:
        return make_client(get_settings())
    except LLMUnavailable as exc:
        console.print(f"[red]AI provider not available:[/red] {exc}")
        raise typer.Exit(1) from exc


def _generator_dir() -> Path:
    """Samples, labels, scans and results are kept per generator model, so runs never mix."""
    client = _client()
    return RUN_DIR / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{client.name}-{client.model}")


def _stage_dir(stage: str, tag: str | None = None) -> Path:
    # The reference check does not depend on the model, so it is shared. Samples and labels are
    # shared by every tag, so a tagged run scores exactly the same samples with the same labels.
    if stage == "refcheck":
        return RUN_DIR / stage
    if stage == "scans":
        return _generator_dir() / f"scans{_suffix(_TAG if tag is None else tag)}"
    return _generator_dir() / stage


def _output(name: str, ext: str, tag: str | None = None) -> Path:
    """metrics.csv for the original run, metrics-v2.csv for --tag v2, and so on."""
    return _generator_dir() / f"{name}{_suffix(_TAG if tag is None else tag)}{ext}"


def _calibration_tasks() -> list[Task]:
    split = splits.load_split(CODESECEVAL.name)
    if split.revision != CODESECEVAL.revision:
        raise typer.BadParameter(f"the split was made for revision {split.revision}, not {CODESECEVAL.revision}")
    by_id = {t.id: t for t in datasets.load_tasks(CODESECEVAL)}
    return [by_id[i] for i in split.calibration]


def _usable_tasks(tasks: list[Task]) -> list[Task]:
    out = []
    for t in tasks:
        rc = _load(_stage_dir("refcheck") / f"{t.id}.json")
        if rc and rc["usable"]:
            out.append(t)
    return out


def _sandbox_image() -> str:
    try:
        return sandbox.ensure_image()
    except sandbox.SandboxError as exc:
        console.print(f"[red]Sandbox not ready:[/red] {exc}")
        raise typer.Exit(1) from exc


def _quiet_logs() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(message)s")


# --- steps ---


def step_download() -> None:
    folder = datasets.download(CODESECEVAL)
    tasks = datasets.load_tasks(CODESECEVAL)
    console.print(f"CodeSecEval at {CODESECEVAL.revision[:12]}: {len(tasks)} tasks, SHA-256 checked ({folder})")


def step_split() -> None:
    tasks = datasets.load_tasks(CODESECEVAL)
    s = splits.create_or_check_split(CODESECEVAL.name, CODESECEVAL.revision, [t.id for t in tasks])
    console.print(
        f"Split (seed {s.seed}): {len(s.calibration)} calibration, {len(s.test)} test -> {splits.split_path(CODESECEVAL.name)}"
    )


def step_refcheck() -> None:
    tasks = _calibration_tasks()
    todo = [t for t in tasks if not (_stage_dir("refcheck") / f"{t.id}.json").exists()]
    if todo:
        tag = _sandbox_image()
        console.print(f"Checking the reference solutions of {len(todo)} task(s) in the sandbox ({tag}) ...")

        def check(task: Task) -> str:
            tests = {"fp": task.test_fp, "sp": task.test_sp}
            secure = sandbox.run_tests(tag, task.secure_code, task.entry_point, tests)
            insecure = sandbox.run_tests(tag, task.insecure_code, task.entry_point, tests)
            usable, reason = labels.task_usable(secure, insecure)
            _save(
                _stage_dir("refcheck") / f"{task.id}.json",
                {
                    "task_id": task.id,
                    "cwes": list(task.cwes),
                    "usable": usable,
                    "reason": reason,
                    "rule": labels.TASK_RULE,
                    "sandbox_image": tag,
                    "secure": {k: v.to_json() for k, v in secure.items()},
                    "insecure": {k: v.to_json() for k, v in insecure.items()},
                    "checked_at": _now(),
                },
            )
            return task.id

        _run_parallel(check, todo)
    usable = _usable_tasks(tasks)
    console.print(f"Usable tasks: {len(usable)} of {len(tasks)} calibration tasks.")


def _run_parallel(fn, items, key=lambda task: task.id) -> None:
    """Run sandbox jobs side by side. A Docker failure is reported and not saved, so it is retried."""
    errors = []
    with ThreadPoolExecutor(max_workers=DOCKER_WORKERS) as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for fut in futures:
            try:
                fut.result()
            except sandbox.SandboxError as exc:
                errors.append(f"{key(futures[fut])}: {exc}")
    for e in errors:
        console.print(f"[yellow]Not saved, will be retried next time:[/yellow] {e}")


def step_generate() -> None:
    tasks = _usable_tasks(_calibration_tasks())
    todo = [t for t in tasks if not (_stage_dir("samples") / f"{t.id}.json").exists()]
    if not todo:
        console.print(f"Samples: all {len(tasks)} generated.")
        return
    client = _client()
    console.print(f"Generating {len(todo)} sample(s) with {client.name}/{client.model} ({GENERATE_PROMPT_VERSION}) ...")
    failed = in_a_row = 0
    for i, task in enumerate(todo, start=1):
        try:
            record = generate_sample(task, client)
        except QuotaExhausted as exc:
            raise Paused(str(exc)) from exc
        except LLMError as exc:
            failed += 1
            in_a_row += 1
            console.print(f"[yellow]{task.id}: not generated, will be retried next time ({type(exc).__name__}: {exc})[/yellow]")
            if in_a_row == MAX_FAILURES_IN_A_ROW:
                console.print("[red]Stopping: the provider keeps failing (wrong model name, key or outage?).[/red]")
                raise typer.Exit(1) from exc
            continue
        in_a_row = 0
        _save(_stage_dir("samples") / f"{task.id}.json", record)
        console.print(f"  [{i}/{len(todo)}] {task.id}: {record['status']}")
    if failed:
        console.print(f"[yellow]{failed} sample(s) still to generate; run the step again.[/yellow]")


def step_label() -> None:
    tasks = _usable_tasks(_calibration_tasks())
    todo = []
    for t in tasks:
        sample = _load(_stage_dir("samples") / f"{t.id}.json")
        if sample and sample["status"] == "ok" and not (_stage_dir("labels") / f"{t.id}.json").exists():
            todo.append((t, sample))
    if todo:
        tag = _sandbox_image()
        console.print(f"Labelling {len(todo)} sample(s) with the dataset's tests in the sandbox ...")

        def label(item) -> None:
            task, sample = item
            results = sandbox.run_tests(tag, sample["code"], task.entry_point, {"fp": task.test_fp, "sp": task.test_sp})
            lab, reason = labels.label_sample(results)
            _save(
                _stage_dir("labels") / f"{task.id}.json",
                {
                    "task_id": task.id,
                    "label": lab,
                    "reason": reason,
                    "rule": labels.LABEL_RULE,
                    "sandbox_image": tag,
                    "results": {k: v.to_json() for k, v in results.items()},
                    "labeled_at": _now(),
                },
            )

        _run_parallel(label, todo, key=lambda item: item[0].id)
    counts = Counter(
        (_load(_stage_dir("labels") / f"{t.id}.json") or {}).get("label", "not labelled") for t in tasks
    )
    console.print("Labels: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))


def _incomplete(result: ScanResult) -> list[str]:
    return [f"{r.tool}: {r.state.value} ({r.message or ''})" for r in result.tool_runs if r.state != ToolState.OK]


def step_scan() -> None:
    settings = get_settings()
    groups = get_cwe_groups()
    tasks = _usable_tasks(_calibration_tasks())
    todo = []
    for t in tasks:
        lab = _load(_stage_dir("labels") / f"{t.id}.json")
        if lab and lab["label"] in labels.SCORED_LABELS and not (_stage_dir("scans") / f"{t.id}.json").exists():
            todo.append(t)
    if not todo:
        console.print("Scans: nothing left to scan.")
        return
    if not settings.llm_review:
        console.print("[red]CODEGUARD_LLM_REVIEW is off; the LLM checklist cannot be scored. Turn it on in .env.[/red]")
        raise typer.Exit(1)
    console.print(f"Scanning {len(todo)} sample(s) with CodeGuard ...")
    for i, task in enumerate(todo, start=1):
        sample = _load(_stage_dir("samples") / f"{task.id}.json")
        result = scan_code(sample["code"], filename=f"{task.id}.py", settings=settings, groups=groups)
        problems = _incomplete(result)
        if problems:
            llm_stopped = any(
                r.tool.startswith("llm:") and r.state == ToolState.SKIPPED for r in result.tool_runs
            )
            if llm_stopped:
                raise Paused("; ".join(problems))
            console.print(f"[yellow]{task.id}: scan incomplete, not saved: {'; '.join(problems)}[/yellow]")
            continue
        _save(
            _stage_dir("scans") / f"{task.id}.json",
            {
                "task_id": task.id,
                "cwes": list(task.cwes),
                "target_groups": list(score.target_groups(task.cwes, groups)),
                "scanned_at": _now(),
                "semgrep_configs": list(settings.semgrep_configs),
                "checklist_prompt_version": CHECKLIST_PROMPT_VERSION,
                "result": result.model_dump(mode="json"),
            },
        )
        console.print(f"  [{i}/{len(todo)}] {task.id}: {len(result.findings)} finding(s)")


def _regroup(findings: list[Finding], groups: CweGroups) -> list[Finding]:
    """A saved scan stores each finding's CWE group as it was on the day of the scan. Score it with
    today's rules/cwe_groups.yaml instead, the same way for every tool, so the result of a run never
    depends on when its scans were made."""
    return [f.model_copy(update={"cwe_group": groups.group_of(f.cwe)}) if f.cwe else f for f in findings]


def _score_run(tasks: list[Task], groups: CweGroups, tag: str) -> tuple[list[dict], list, dict]:
    """Per-sample rows, (label, target group, flags) for every scored sample, and run metadata."""
    per_sample: list[dict] = []
    scored: list[tuple[str, str, dict[str, bool]]] = []  # (label, target group, flags)
    meta = {"generator": Counter(), "reviewer": Counter(), "tools": {}, "semgrep_configs": Counter()}
    for t in tasks:
        targets = score.target_groups(t.cwes, groups)
        row = {"task_id": t.id, "cwe": t.cwe_label, "target_group": "+".join(targets)}
        rc = _load(_stage_dir("refcheck") / f"{t.id}.json")
        sample = _load(_stage_dir("samples") / f"{t.id}.json")
        lab = _load(_stage_dir("labels") / f"{t.id}.json")
        scan = _load(_stage_dir("scans", tag) / f"{t.id}.json")
        if rc is None:
            row["status"] = "reference check not run"
        elif not rc["usable"]:
            row["status"], row["reason"] = "excluded: task tests unusable", rc["reason"]
        elif sample is None:
            row["status"] = "not generated yet"
        elif sample["status"] != "ok":
            row["status"], row["reason"] = "excluded: invalid generation", sample.get("error")
        elif lab is None:
            row["status"] = "not labelled yet"
        elif lab["label"] not in labels.SCORED_LABELS:
            row["status"], row["reason"] = f"excluded: {lab['label']}", lab["reason"]
        elif scan is None:
            row["status"] = "not scanned yet"
        else:
            result = ScanResult.model_validate(scan["result"])
            f = score.flags(_regroup(result.findings, groups), targets)
            row.update(status="scored", label=lab["label"], reason=lab["reason"], **{k: int(v) for k, v in f.items()})
            scored.append((lab["label"], row["target_group"], f))
            meta["generator"][f"{sample['provider']}/{sample['model']} (version {sample.get('model_version')})"] += 1
            for run in result.tool_runs:
                meta["tools"][run.tool] = run.version
                if run.llm:
                    meta["reviewer"][f"{run.llm.provider}/{run.llm.model} ({run.llm.prompt_version})"] += 1
            meta["semgrep_configs"][",".join(scan.get("semgrep_configs") or ["not recorded"])] += 1
        per_sample.append(row)
    return per_sample, scored, meta


def _metric_rows(scored: list) -> list[dict]:
    return [metric_row(name, title, confusion([(lab, f[name]) for lab, _, f in scored])) for name, title in score.TOOLS]


FLAG_COLS = [name for name, _ in score.TOOLS]
PER_SAMPLE_COLUMNS = ["task_id", "cwe", "target_group", "status", "label", *FLAG_COLS, "reason"]


def step_evaluate() -> None:
    groups = get_cwe_groups()
    tasks = _calibration_tasks()
    per_sample, scored, meta = _score_run(tasks, groups, _TAG)

    write_csv(_output("per_sample", ".csv"), PER_SAMPLE_COLUMNS, per_sample)
    rows = _metric_rows(scored)
    write_csv(_output("metrics", ".csv"), METRIC_COLUMNS, rows)

    by_group = []
    for g in sorted({tg for _, tg, _ in scored}):
        sub = [(lab, f) for lab, tg, f in scored if tg == g]
        for name, title in score.TOOLS:
            by_group.append({"cwe_group": g, **metric_row(name, title, confusion([(lab, f[name]) for lab, f in sub]))})
    write_csv(_output("metrics_by_group", ".csv"), ["cwe_group", *METRIC_COLUMNS], by_group)

    status_counts = Counter(r["status"] for r in per_sample)
    gen_models = {k.split(" (")[0] for k in meta["generator"]}
    rev_models = {k.split(" (")[0] for k in meta["reviewer"]}
    _save(
        _output("run", ".json"),
        {
            "evaluated_at": _now(),
            "tag": _TAG or None,
            "codeguard_version": __version__,
            "dataset": {"name": CODESECEVAL.name, "source": CODESECEVAL.source, "revision": CODESECEVAL.revision},
            "split": {"file": "benchmark/splits/codeseceval.json", "part": "calibration"},
            "calibration_tasks": len(tasks),
            "status_counts": dict(status_counts),
            "generator": dict(meta["generator"]),
            "reviewer": dict(meta["reviewer"]),
            "generator_is_reviewer": bool(gen_models & rev_models),
            "tool_versions": meta["tools"],
            "semgrep_configs": dict(meta["semgrep_configs"]),
            "sandbox_image": sandbox.image_tag(),
            "task_rule": labels.TASK_RULE,
            "label_rule": labels.LABEL_RULE,
            "unit": "one generated sample, judged on its task's target CWE group (rules/cwe_groups.yaml)",
        },
    )
    _print_table(rows, status_counts, len(tasks), bool(gen_models & rev_models))


def _print_table(rows: list[dict], status_counts: Counter, n_tasks: int, same_model: bool) -> None:
    console.print()
    console.print(f"Calibration tasks: {n_tasks}")
    for status, n in sorted(status_counts.items(), key=lambda x: -x[1]):
        console.print(f"  {status}: {n}")
    if same_model:
        console.print("[yellow]Note: the generator and the reviewer are the same model.[/yellow]")
    table = Table(title="Pilot results (CodeSecEval, calibration split" + (f", {_TAG})" if _TAG else ")"))
    for col in ("Tool", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "FP rate"):
        table.add_column(col, justify="left" if col == "Tool" else "right")
    for r in rows:
        table.add_row(
            r["label"], str(r["tp"]), str(r["fp"]), str(r["fn"]), str(r["tn"]),
            *(r[k] or "n/a" for k in ("precision", "recall", "f1", "fpr")),
        )  # fmt: skip
    console.print(table)
    console.print(f"CSV files in {_generator_dir()}")


STEPS = {
    "download": step_download,
    "split": step_split,
    "refcheck": step_refcheck,
    "generate": step_generate,
    "label": step_label,
    "scan": step_scan,
    "evaluate": step_evaluate,
}


def _run_step(name: str) -> None:
    _quiet_logs()
    try:
        STEPS[name]()
    except Paused as exc:
        console.print(f"[yellow]Paused: {exc}[/yellow]")
        console.print("Everything done so far is saved. Run the same command again after the limit resets.")
        raise typer.Exit(PAUSED_EXIT) from exc
    except (datasets.DatasetError, splits.SplitError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


def _make_command(name: str):
    def command() -> None:
        _run_step(name)

    command.__doc__ = STEPS[name].__name__.replace("step_", "Run the ") + " step."
    return command


for _name in STEPS:
    app.command(_name)(_make_command(_name))


@app.command()
def run() -> None:
    """Run every step in order (each skips work it has already done)."""
    for name in STEPS:
        console.rule(name)
        _run_step(name)


@app.command()
def status() -> None:
    """How far the run has got."""
    for stage in ("refcheck", "samples", "labels", "scans"):
        folder = _stage_dir(stage)
        n = len(list(folder.glob("*.json"))) if folder.exists() else 0
        console.print(f"{stage:9} {n} file(s)")


# --- compare two runs on the same samples ---


def _scan_times(tag: str, task_ids: list[str]) -> tuple[dict[str, float | None], dict[str, float | None]]:
    """Semgrep's time and the whole scan's time per sample, as saved in each scan file.
    None where the scan file or the time was not saved."""
    semgrep: dict[str, float | None] = {}
    total: dict[str, float | None] = {}
    for t in task_ids:
        scan = _load(_stage_dir("scans", tag) / f"{t}.json")
        result = (scan or {}).get("result") or {}
        runs = {r.get("tool"): r for r in result.get("tool_runs") or []}
        semgrep[t] = runs.get("semgrep", {}).get("duration_s")
        total[t] = result.get("duration_s")
    return semgrep, total


SHORT_NAMES = {"semgrep": "Semgrep", "bandit": "Bandit", "rule_checks": "Rules", "llm_checklist": "LLM chk",
               "union": "Union", "verifier_v0": "Ver. v0"}  # fmt: skip


def _change(a, b) -> str:
    a = "n/a" if a in (None, "") else str(a)
    b = "n/a" if b in (None, "") else str(b)
    return a if a == b else f"{a}->{b}"


@app.command("compare")
def compare_runs(
    old: str = typer.Option("", help="Tag of the earlier run ('' = the original, untagged run)."),
    new: str = typer.Option("v2", help="Tag of the later run."),
) -> None:
    """Show two runs side by side on the same samples and labels, and write compare-<new>-*.csv."""
    groups = get_cwe_groups()
    tasks = _calibration_tasks()
    old_rows, old_scored, _ = _score_run(tasks, groups, old)
    new_rows, new_scored, new_meta = _score_run(tasks, groups, new)
    try:
        ids = cmp.check_same_samples(old_rows, new_rows)
    except cmp.CompareError as exc:
        console.print(f"[red]Cannot compare: {exc}[/red]")
        raise typer.Exit(1) from exc
    if not ids:
        console.print("[red]Cannot compare: no scored samples yet. Run scan and evaluate for both tags first.[/red]")
        raise typer.Exit(1)
    old_name, new_name = old or "original", new or "original"
    old_metrics, new_metrics = _metric_rows(old_scored), _metric_rows(new_scored)

    note = (
        f"Measured on the same {len(ids)} calibration samples (same labels) that motivated the new checklist "
        "items and Semgrep packs. This is a calibration-split check, not a test-split result, and may "
        "overstate how much the changes help on unseen tasks."
    )
    console.print()
    console.print(f"[yellow]{note}[/yellow]")

    # The earlier run, scored again today, must give the numbers saved on the day it was evaluated.
    saved = _output("metrics", ".csv", old)
    if saved.exists():
        with saved.open(encoding="utf-8", newline="") as fh:
            before = {r["tool"]: r for r in csv.DictReader(fh)}
        same = all(
            str(m[k]) == before.get(m["tool"], {}).get(k) for m in old_metrics for k in ("tp", "fp", "fn", "tn")
        )
        colour = "green" if same else "red"
        console.print(f"[{colour}]{old_name} run scored again reproduces {saved.name}: {'yes' if same else 'NO'}[/{colour}]")

    table = Table(title=f"Pilot results, {old_name}->{new_name} (CodeSecEval, calibration split)")
    cols = ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr")
    for col in ("Tool", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "FP rate"):
        table.add_column(col, justify="left" if col == "Tool" else "right")
    metric_out = []
    for a, b in zip(old_metrics, new_metrics):
        table.add_row(a["label"], *(_change(a[k], b[k]) for k in cols))
        metric_out.append({"tool": a["tool"], "label": a["label"], **{f"{k}_{s}": r[k] for k in cols for s, r in (("old", a), ("new", b))}})
    console.print(table)

    by_group = cmp.flagged_by_group(old_rows, new_rows, FLAG_COLS)
    gtable = Table(title=f"Samples flagged per target CWE group, {old_name}->{new_name}")
    gtable.add_column("Target CWE group", overflow="fold")
    gtable.add_column("N", justify="right")
    gtable.add_column("Vuln", justify="right")
    titles = dict(score.TOOLS)
    for tool in FLAG_COLS:
        gtable.add_column(SHORT_NAMES.get(tool, tool), justify="right")
    group_out = []
    for g in by_group:
        gtable.add_row(g.cwe_group, str(g.samples), str(g.vulnerable), *(_change(g.old[t], g.new[t]) for t in FLAG_COLS))
        group_out.append({"cwe_group": g.cwe_group, "samples": g.samples, "vulnerable": g.vulnerable,
                          **{f"{t}_{s}": c[t] for t in FLAG_COLS for s, c in (("old", g.old), ("new", g.new))}})  # fmt: skip
    console.print(gtable)
    changes = cmp.flag_changes(old_rows, new_rows, FLAG_COLS)
    if changes:
        console.print("Flag changes: " + ", ".join(f"{titles[t]} {kind} {n}" for (t, kind), n in sorted(changes.items())))
    else:
        console.print("Flag changes: none")

    old_sg, old_total = _scan_times(old, ids)
    new_sg, new_total = _scan_times(new, ids)
    ttable = Table(title=f"Scan time per sample, {old_name}->{new_name}")
    for col in ("Sample", "Semgrep old", "Semgrep new", "Change", "Whole scan old", "Whole scan new"):
        ttable.add_column(col, justify="left" if col == "Sample" else "right")
    time_out = []
    for t in ids:
        a, b = old_sg[t], new_sg[t]
        diff = f"{b - a:+.1f} s" if a is not None and b is not None else cmp.NOT_MEASURED
        ttable.add_row(t, cmp.fmt_seconds(a), cmp.fmt_seconds(b), diff, cmp.fmt_seconds(old_total[t]), cmp.fmt_seconds(new_total[t]))
        time_out.append({"task_id": t, "semgrep_old_s": a, "semgrep_new_s": b, "scan_old_s": old_total[t], "scan_new_s": new_total[t]})  # fmt: skip
    for name, a, b in (("Semgrep", old_sg, new_sg), ("Whole scan", old_total, new_total)):
        sa, sb = cmp.time_summary(a), cmp.time_summary(b)
        ttable.add_row(f"[bold]{name} median[/bold]", cmp.fmt_seconds(sa["median"]), cmp.fmt_seconds(sb["median"]), "", "", "")
        ttable.add_row(f"[bold]{name} mean[/bold]", cmp.fmt_seconds(sa["mean"]), cmp.fmt_seconds(sb["mean"]), "", "", "")
    console.print(ttable)
    console.print(f"Semgrep packs in the {new_name} run: " + "; ".join(f"{k} ({v} samples)" for k, v in new_meta["semgrep_configs"].items()))

    prefix = f"compare-{old_name}-vs-{new_name}"
    write_csv(_generator_dir() / f"{prefix}-metrics.csv", list(metric_out[0]), metric_out)
    write_csv(_generator_dir() / f"{prefix}-by_group.csv", list(group_out[0]), group_out)
    write_csv(_generator_dir() / f"{prefix}-times.csv", list(time_out[0]), time_out)
    _save(_generator_dir() / f"{prefix}.json", {"compared_at": _now(), "samples": len(ids), "note": note})
    console.print(f"CSV files in {_generator_dir()} ({prefix}-*.csv)")


if __name__ == "__main__":
    app()
    sys.exit(0)
