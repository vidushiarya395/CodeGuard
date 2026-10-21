"""Download and load the benchmark datasets, pinned to an exact commit.

CodeSecEval (arXiv 2407.02395, ISSTA 2026): 255 Python tasks. The official repository
(github.com/CY-SCUT-MS/CodeSecEval) points to the data on Hugging Face. Each task has a problem
statement, an insecure and a secure reference solution, a functional test suite (Test-FP) and a
security test suite (Test-SP), both written as `check(candidate)`.

The files are downloaded from one fixed Hugging Face commit and their SHA-256 is checked, so every
run uses exactly the same data. The data is only read here (parsed as JSON); none of its code is
ever run outside the Docker sandbox.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from codeguard import __version__
from codeguard.cwe import normalize_cwe

from benchmark.paths import EXTERNAL_DIR

USER_AGENT = f"CodeGuard-benchmark/{__version__}"


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    source: str  # where the pinned files come from, for the paper
    revision: str  # the pinned commit
    url_template: str  # {revision} and {path} are filled in
    files: dict[str, tuple[str, str]]  # subset -> (path in the repo, expected sha256)

    @property
    def local_dir(self) -> Path:
        return EXTERNAL_DIR / self.name / self.revision


CODESECEVAL = DatasetSpec(
    name="codeseceval",
    source="https://huggingface.co/datasets/JasonWang1/CodeSecEval (linked from github.com/CY-SCUT-MS/CodeSecEval)",
    revision="c3ffce09269f2d7b092888efe05d070b6fcb97f5",
    url_template="https://huggingface.co/datasets/JasonWang1/CodeSecEval/resolve/{revision}/{path}",
    files={
        "SecEvalBase": (
            "data/SecEvalBase/test.jsonl",
            "9bfb204a254d174465c1019b3f06f0dab0ad2915ee3b0f739b278f51ba1b4779",
        ),
        "SecEvalPlus": (
            "data/SecEvalPlus/test.jsonl",
            "f2098b4e0d7c8ad58c2855e3de3b8f1a4cc2d8c8dfa654c93979fa8e8fc1a050",
        ),
    },
)


class DatasetError(RuntimeError):
    pass


@dataclass(frozen=True)
class Task:
    id: str  # e.g. "CWE-502_codeql_1", "CWE-20_01" or "CWE-862+CWE-287+CWE-306+CWE-863_01"
    subset: str
    cwes: tuple[str, ...]  # target CWEs read from the task ID, e.g. ("CWE-502",); a few tasks name several
    problem: str
    insecure_code: str
    secure_code: str
    test: str
    test_fp: str  # functional tests only
    test_sp: str  # security tests only
    entry_point: str

    @property
    def cwe_label(self) -> str:
        return "/".join(self.cwes)


_ID_CWES = re.compile(r"^((?:CWE-\d+\+)*CWE-\d+)[_-]", re.IGNORECASE)


def task_cwes(task_id: str) -> tuple[str, ...]:
    """The target CWEs are the prefix of the task ID: "CWE-020_author_1" -> ("CWE-20",),
    "CWE-862+CWE-287_01" -> ("CWE-862", "CWE-287")."""
    m = _ID_CWES.match(task_id)
    cwes = tuple(normalize_cwe(part) for part in m.group(1).split("+")) if m else ()
    if not cwes or None in cwes:
        raise DatasetError(f"task ID without a CWE prefix: {task_id!r}")
    return cwes  # type: ignore[return-value]


def task_id(raw_id: str) -> str:
    """A dataset ID made safe as a file name: SecEvalBase IDs end in ".py" ("CWE-502_codeql_1.py"),
    which is dropped, and IDs naming several CWEs ("CWE-862/CWE-287_01") use "+" instead of "/"."""
    raw_id = raw_id.strip()
    raw_id = raw_id[:-3] if raw_id.endswith(".py") else raw_id
    return raw_id.replace("/", "+")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(spec: DatasetSpec = CODESECEVAL, force: bool = False) -> Path:
    """Download every file of the pinned revision and check its SHA-256. Returns the local folder."""
    for subset, (rel, expected) in spec.files.items():
        dest = spec.local_dir / rel
        if dest.exists() and not force:
            _verify(dest, expected, subset)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = spec.url_template.format(revision=spec.revision, path=rel)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(50_000_000)
        tmp = dest.with_suffix(dest.suffix + ".part")
        tmp.write_bytes(data)
        _verify(tmp, expected, subset)
        tmp.replace(dest)
    return spec.local_dir


def _verify(path: Path, expected: str, subset: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise DatasetError(
            f"{subset}: {path.name} has SHA-256 {actual}, expected {expected}. "
            "The file is not the pinned version; delete it and download again."
        )


def load_tasks(spec: DatasetSpec = CODESECEVAL) -> list[Task]:
    """All tasks of the pinned dataset, sorted by ID. Download first."""
    tasks: list[Task] = []
    for subset, (rel, expected) in spec.files.items():
        path = spec.local_dir / rel
        if not path.exists():
            raise DatasetError(f"{path} is missing. Run the download step first.")
        _verify(path, expected, subset)
        tasks += parse_jsonl(path.read_text(encoding="utf-8"), subset)
    ids = [t.id for t in tasks]
    twice = sorted({i for i in ids if ids.count(i) > 1})
    if twice:
        raise DatasetError(f"duplicate task IDs: {', '.join(twice)}")
    return sorted(tasks, key=lambda t: t.id)


def parse_jsonl(text: str, subset: str) -> list[Task]:
    tasks = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            tid = task_id(row["ID"])
            tasks.append(
                Task(
                    id=tid,
                    subset=subset,
                    cwes=task_cwes(tid),
                    problem=row["Problem"],
                    insecure_code=row["Insecure Code"],
                    secure_code=row["Secure Code"],
                    test=row["Test"],
                    test_fp=row["Test-FP"],
                    test_sp=row["Test-SP"],
                    entry_point=row["Entry_Point"].strip(),
                )
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise DatasetError(f"{subset} line {n}: not a valid task ({exc})") from exc
    return tasks
