"""Precision, recall, F1 and false-positive rate from per-sample flags and labels.

TP = flagged and vulnerable, FP = flagged and safe, FN = missed and vulnerable, TN = not flagged and safe.
A value whose denominator is zero is left empty ("n/a"), never guessed.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from benchmark.labels import SAFE, VULNERABLE


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None if p is None or r is None else 0.0
        return 2 * p * r / (p + r)

    @property
    def fpr(self) -> float | None:
        return _ratio(self.fp, self.fp + self.tn)


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def confusion(rows: list[tuple[str, bool]]) -> Confusion:
    """rows: (label, flagged) for every scored sample."""
    tp = sum(1 for label, flagged in rows if flagged and label == VULNERABLE)
    fp = sum(1 for label, flagged in rows if flagged and label == SAFE)
    fn = sum(1 for label, flagged in rows if not flagged and label == VULNERABLE)
    tn = sum(1 for label, flagged in rows if not flagged and label == SAFE)
    return Confusion(tp, fp, fn, tn)


METRIC_COLUMNS = ["tool", "label", "n", "vulnerable", "safe", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"]


def metric_row(tool: str, label: str, c: Confusion) -> dict:
    return {
        "tool": tool,
        "label": label,
        "n": c.n,
        "vulnerable": c.tp + c.fn,
        "safe": c.fp + c.tn,
        "tp": c.tp,
        "fp": c.fp,
        "fn": c.fn,
        "tn": c.tn,
        "precision": fmt(c.precision),
        "recall": fmt(c.recall),
        "f1": fmt(c.f1),
        "fpr": fmt(c.fpr),
    }


def fmt(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}"


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
