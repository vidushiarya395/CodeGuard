"""Where the benchmark keeps its files."""

from __future__ import annotations

from codeguard.config import REPO_ROOT

BENCH_DIR = REPO_ROOT / "benchmark"
EXTERNAL_DIR = BENCH_DIR / "external"  # downloaded datasets, never committed
RUNS_DIR = BENCH_DIR / "runs"  # run output, never committed
SPLITS_DIR = BENCH_DIR / "splits"  # the fixed calibration / test splits, committed
SANDBOX_DIR = BENCH_DIR / "sandbox"  # the Docker image used to run dataset tests
