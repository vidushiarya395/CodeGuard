"""CWE helpers: turn tool output into "CWE-<n>" and look up its narrow group."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from codeguard.config import get_settings

UNCLASSIFIED = "unclassified"

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalize_cwe(value: object) -> str | None:
    """Accepts 78, "78", "CWE-78", "CWE-78: OS Command Injection" and returns "CWE-78"."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    text = str(value).strip()
    if text.isdigit():
        return f"CWE-{int(text)}" if int(text) > 0 else None
    match = _CWE_RE.search(text)
    return f"CWE-{int(match.group(1))}" if match else None


@dataclass(frozen=True)
class CweGroup:
    id: str
    name: str
    cwes: tuple[str, ...]
    source: str


class CweGroupError(ValueError):
    """The cwe_groups.yaml file is broken."""


@dataclass(frozen=True)
class CweGroups:
    groups: tuple[CweGroup, ...]
    by_cwe: dict[str, str]

    def group_of(self, cwe: str | None) -> str:
        """Return the group ID for a CWE. Unknown CWEs become their own group."""
        if not cwe:
            return UNCLASSIFIED
        return self.by_cwe.get(cwe, cwe)

    def get(self, group_id: str) -> CweGroup | None:
        return next((g for g in self.groups if g.id == group_id), None)


def load_cwe_groups(path: Path) -> CweGroups:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CweGroupError(f"CWE group file not found: {path}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
        raise CweGroupError(f"{path}: expected a top-level 'groups' list")

    groups: list[CweGroup] = []
    by_cwe: dict[str, str] = {}
    seen_ids: set[str] = set()
    for i, raw in enumerate(data["groups"]):
        if not isinstance(raw, dict):
            raise CweGroupError(f"{path}: group #{i + 1} is not a mapping")
        gid = str(raw.get("id", "")).strip()
        if not gid:
            raise CweGroupError(f"{path}: group #{i + 1} has no id")
        if gid in seen_ids:
            raise CweGroupError(f"{path}: duplicate group id '{gid}'")
        seen_ids.add(gid)
        cwes: list[str] = []
        for raw_cwe in raw.get("cwes") or []:
            cwe = normalize_cwe(raw_cwe)
            if cwe is None:
                raise CweGroupError(f"{path}: group '{gid}' has an invalid CWE '{raw_cwe}'")
            if cwe in by_cwe:
                raise CweGroupError(
                    f"{path}: {cwe} is in both '{by_cwe[cwe]}' and '{gid}'; each CWE may be in one group"
                )
            by_cwe[cwe] = gid
            cwes.append(cwe)
        if not cwes:
            raise CweGroupError(f"{path}: group '{gid}' has no CWEs")
        groups.append(
            CweGroup(id=gid, name=str(raw.get("name", gid)), cwes=tuple(cwes), source=str(raw.get("source", "")))
        )
    return CweGroups(groups=tuple(groups), by_cwe=by_cwe)


@lru_cache(maxsize=4)
def _cached(path_str: str) -> CweGroups:
    return load_cwe_groups(Path(path_str))


def get_cwe_groups() -> CweGroups:
    return _cached(str(get_settings().rules_dir / "cwe_groups.yaml"))
