"""The calibration / test split: made once (seed 42, 20% calibration), saved, never changed.

Anything that is tuned (trust weights, thresholds) may only look at calibration tasks. Final numbers
come from test tasks only. Once the split file exists, it is the split: making it again must give
the same file, and a dataset with different task IDs is refused instead of silently re-split.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from benchmark.paths import SPLITS_DIR

SEED = 42
CALIBRATION_FRACTION = 0.2


class SplitError(RuntimeError):
    pass


@dataclass(frozen=True)
class Split:
    dataset: str
    revision: str
    seed: int
    calibration_fraction: float
    calibration: tuple[str, ...]
    test: tuple[str, ...]

    def to_json(self) -> dict:
        return {
            "dataset": self.dataset,
            "revision": self.revision,
            "seed": self.seed,
            "calibration_fraction": self.calibration_fraction,
            "counts": {"calibration": len(self.calibration), "test": len(self.test)},
            "calibration": list(self.calibration),
            "test": list(self.test),
        }


def make_split(
    dataset: str, revision: str, task_ids: list[str], seed: int = SEED, fraction: float = CALIBRATION_FRACTION
) -> Split:
    ids = sorted(set(task_ids))
    if len(ids) != len(task_ids):
        raise SplitError("task IDs are not unique")
    random.Random(seed).shuffle(ids)
    n_cal = round(len(ids) * fraction)
    return Split(dataset, revision, seed, fraction, tuple(sorted(ids[:n_cal])), tuple(sorted(ids[n_cal:])))


def split_path(dataset: str) -> Path:
    return SPLITS_DIR / f"{dataset}.json"


def load_split(dataset: str, path: Path | None = None) -> Split:
    path = path or split_path(dataset)
    if not path.exists():
        raise SplitError(f"{path} does not exist. Run the split step first.")
    data = json.loads(path.read_text(encoding="utf-8"))
    return Split(
        data["dataset"],
        data["revision"],
        data["seed"],
        data["calibration_fraction"],
        tuple(data["calibration"]),
        tuple(data["test"]),
    )


def create_or_check_split(dataset: str, revision: str, task_ids: list[str], path: Path | None = None) -> Split:
    """Save the split the first time; afterwards only check that the saved one still matches."""
    path = path or split_path(dataset)
    fresh = make_split(dataset, revision, task_ids)
    if path.exists():
        saved = load_split(dataset, path)
        if set(saved.calibration) | set(saved.test) != set(task_ids):
            raise SplitError(
                f"{path} was made for a different set of task IDs. The split is fixed once; "
                "it is never re-made to fit new data."
            )
        if saved.calibration != fresh.calibration:
            raise SplitError(f"{path} does not match seed {SEED}; it was edited by hand.")
        return saved
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fresh.to_json(), indent=1) + "\n", encoding="utf-8")
    return fresh
