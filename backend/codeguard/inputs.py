"""Turning user input into files on disk to scan: a zip archive (an upload, later a GitHub download).

Only Python files and requirements files are taken out of the archive; nothing is ever run.
Entries that could escape the folder ("../x.py", absolute paths, links), vendored folders, and
anything past the size or file limits are skipped and listed, so the user sees what was left out.
"""

from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from codeguard.rulechecks.source import is_requirements_file
from codeguard.scanners.base import SKIP_DIRS

MAX_ZIP_PY_FILES = 300  # same limits as a GitHub repository (CODEGUARD_RULES: 300 .py files, 5 MB)
MAX_ZIP_BYTES = 5_000_000  # total size of the files taken out
MAX_ENTRY_BYTES = 2_000_000  # one file (larger files are skipped by the rule checks anyway)
MAX_RATIO = 200  # an entry that unpacks to more than 200x its packed size is treated as a zip bomb
MAX_NOTES = 20


class ZipInputError(ValueError):
    """The archive cannot be used (not a zip, no Python files in it)."""


@dataclass
class ZipReport:
    python_files: int = 0
    other_files: int = 0
    skipped: list[str] = field(default_factory=list)

    def notes(self) -> list[str]:
        out = self.skipped[:MAX_NOTES]
        if len(self.skipped) > MAX_NOTES:
            out.append(f"... and {len(self.skipped) - MAX_NOTES} more entries skipped")
        return out


def _safe_parts(name: str) -> tuple[str, ...] | None:
    """The entry's path parts, or None if it could leave the target folder."""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = PurePosixPath(name).parts
    if any(p in ("..", "") for p in parts):
        return None
    return parts


def extract_zip(archive: Path, dest: Path) -> ZipReport:
    report = ZipReport()
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise ZipInputError(f"{archive.name} is not a valid zip file ({exc}).") from exc
    except OSError as exc:
        raise ZipInputError(f"{archive.name} could not be read ({exc.strerror or exc}).") from exc

    total = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = _safe_parts(info.filename)
            if parts is None:
                report.skipped.append(f"{info.filename}: skipped (path leaves the archive folder)")
                continue
            rel = "/".join(parts)
            is_py = rel.endswith(".py")
            if not is_py and not is_requirements_file(rel):
                report.other_files += 1
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                report.skipped.append(f"{rel}: skipped (symbolic link)")
                continue
            if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1]):
                continue  # installed or vendored code, not the user's own (same rule as folder scans)
            if info.file_size > MAX_ENTRY_BYTES:
                report.skipped.append(f"{rel}: skipped (larger than {MAX_ENTRY_BYTES // 1_000_000} MB)")
                continue
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 1_000_000:
                report.skipped.append(f"{rel}: skipped (compressed suspiciously well; possible zip bomb)")
                continue
            if is_py and report.python_files >= MAX_ZIP_PY_FILES:
                report.skipped.append(f"{rel}: skipped (more than {MAX_ZIP_PY_FILES} Python files)")
                continue
            if total + info.file_size > MAX_ZIP_BYTES:
                report.skipped.append(f"{rel}: skipped (archive larger than {MAX_ZIP_BYTES // 1_000_000} MB)")
                continue
            target = dest.joinpath(*parts)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                data = _read_limited(zf, info)
            except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:  # encrypted, corrupt
                report.skipped.append(f"{rel}: skipped (could not be unpacked: {exc})")
                continue
            target.write_bytes(data)
            total += len(data)
            if is_py:
                report.python_files += 1
    if report.python_files == 0:
        others = f" ({report.other_files} other file(s) were ignored)" if report.other_files else ""
        raise ZipInputError(f"{archive.name} contains no Python files (.py) to scan{others}.")
    return report


def _read_limited(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read one entry, never more than its declared size (a lying header cannot fill the disk)."""
    with zf.open(info) as fh:
        data = fh.read(info.file_size + 1)
    if len(data) > info.file_size:
        raise ValueError("entry is larger than its header says")
    return data
