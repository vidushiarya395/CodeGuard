"""Loads and validates rules/checklist.yaml (the LLM checklist and the untrusted-text patterns)."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator

from codeguard.config import get_settings
from codeguard.cwe import normalize_cwe
from codeguard.rulechecks.loader import RuleFileError, _load, _Strict

CHECK_ID_RE = re.compile(r"^CG-CHK-\d{3}$")


class ChecklistItem(_Strict):
    id: str
    title: str
    cwe: str
    question: str
    sources: list[str] = Field(min_length=1)

    @field_validator("cwe", mode="before")
    @classmethod
    def _check_cwe(cls, v: object) -> str:
        cwe = normalize_cwe(v)
        if cwe is None:
            raise ValueError(f"invalid CWE '{v}'")
        return cwe

    @field_validator("sources")
    @classmethod
    def _check_sources(cls, v: list[str]) -> list[str]:
        for url in v:
            if not url.startswith("https://"):
                raise ValueError(f"source must be an https:// link, got '{url}'")
        return v

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not CHECK_ID_RE.match(v):
            raise ValueError(f"checklist id '{v}' must look like CG-CHK-001")
        return v


class ChecklistFile(_Strict):
    version: int
    items: list[ChecklistItem] = Field(min_length=1)
    untrusted_text_patterns: list[str] = Field(default_factory=list)

    @field_validator("untrusted_text_patterns")
    @classmethod
    def _compiles(cls, v: list[str]) -> list[str]:
        for rx in v:
            try:
                re.compile(rx)
            except re.error as exc:
                raise ValueError(f"bad regex {rx!r}: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _unique(self) -> "ChecklistFile":
        ids = [i.id for i in self.items]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"checklist id used twice: {', '.join(dupes)}")
        return self

    def compiled_patterns(self) -> list[re.Pattern]:
        return [re.compile(rx, re.IGNORECASE) for rx in self.untrusted_text_patterns]


def load_checklist(rules_dir: Path) -> ChecklistFile:
    return _load(rules_dir / "checklist.yaml", ChecklistFile)


@lru_cache(maxsize=4)
def _cached(path_str: str) -> ChecklistFile:
    return load_checklist(Path(path_str))


def get_checklist(rules_dir: Path | None = None) -> ChecklistFile:
    return _cached(str(rules_dir or get_settings().rules_dir))


__all__ = ["ChecklistFile", "ChecklistItem", "RuleFileError", "get_checklist", "load_checklist"]
