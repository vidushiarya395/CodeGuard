"""Compare two pilot runs on the same samples (for example before and after adding checklist items).

Pure functions only; benchmark/pilot.py reads the files and prints the tables. Nothing here
changes how a sample is scored: both runs go through the same score.flags and metrics code.
"""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass

NOT_MEASURED = "Not yet measured"


class CompareError(ValueError):
    """The two runs cannot be compared (different samples or labels)."""


def scored(rows: list[dict]) -> dict[str, dict]:
    return {r["task_id"]: r for r in rows if r.get("status") == "scored"}


def check_same_samples(old_rows: list[dict], new_rows: list[dict]) -> list[str]:
    """Both runs must score exactly the same samples with the same labels. Returns the task IDs."""
    old, new = scored(old_rows), scored(new_rows)
    if set(old) != set(new):
        only_old, only_new = sorted(set(old) - set(new)), sorted(set(new) - set(old))
        raise CompareError(f"the runs score different samples (only old: {only_old}; only new: {only_new})")
    changed = sorted(t for t in old if old[t]["label"] != new[t]["label"])
    if changed:
        raise CompareError(f"the runs have different labels for: {changed}")
    return sorted(old)


@dataclass
class GroupCount:
    cwe_group: str
    samples: int
    vulnerable: int
    old: dict[str, int]
    new: dict[str, int]


def flagged_by_group(old_rows: list[dict], new_rows: list[dict], tools: list[str]) -> list[GroupCount]:
    """How many samples each tool flagged, per target CWE group. Samples are grouped by the new
    run's target group, so both columns count exactly the same samples."""
    old, new = scored(old_rows), scored(new_rows)
    by_group: dict[str, list[str]] = {}
    for task_id, row in new.items():
        by_group.setdefault(row["target_group"], []).append(task_id)
    out = []
    for group in sorted(by_group):
        ids = by_group[group]
        out.append(
            GroupCount(
                cwe_group=group,
                samples=len(ids),
                vulnerable=sum(new[t]["label"] == "vulnerable" for t in ids),
                old={tool: sum(bool(int(old[t][tool])) for t in ids) for tool in tools},
                new={tool: sum(bool(int(new[t][tool])) for t in ids) for tool in tools},
            )
        )
    return out


def flag_changes(old_rows: list[dict], new_rows: list[dict], tools: list[str]) -> Counter:
    """(tool, 'gained' | 'lost') -> number of samples whose flag changed between the runs."""
    old, new = scored(old_rows), scored(new_rows)
    changes: Counter = Counter()
    for t in new:
        for tool in tools:
            a, b = bool(int(old[t][tool])), bool(int(new[t][tool]))
            if a != b:
                changes[(tool, "gained" if b else "lost")] += 1
    return changes


def time_summary(times: dict[str, float | None]) -> dict[str, float | int | None]:
    measured = [v for v in times.values() if v is not None]
    return {
        "measured": len(measured),
        "missing": len(times) - len(measured),
        "median": statistics.median(measured) if measured else None,
        "mean": statistics.fmean(measured) if measured else None,
    }


def fmt_seconds(value: float | None) -> str:
    return NOT_MEASURED if value is None else f"{value:.1f} s"
