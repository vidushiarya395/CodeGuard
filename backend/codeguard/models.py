"""Data models shared by the scanners, agents, CLI and API."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Detector(str, Enum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    RULE_CHECK = "rule_check"
    LLM_CHECKLIST = "llm_checklist"
    LLM_OPEN = "llm_open"


class StatusState(str, Enum):
    KEPT = "KEPT"
    DROPPED = "DROPPED"


class FindingStatus(BaseModel):
    state: StatusState
    reason: str | None = None


class Evidence(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    matched_code: str | None = None
    # What each tool said about the problem, e.g. "[bandit B602] subprocess call with shell=True".
    messages: list[str] = Field(default_factory=list)
    llm_reasons: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    # The tool's own severity/confidence labels, kept as evidence only.
    # CodeGuard's own severity and confidence are set later by the Verifier.
    tool_severity: dict[str, str] = Field(default_factory=dict)
    tool_confidence: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str = ""
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    cwe: str | None = None
    cwe_group: str
    title: str
    # severity, confidence and status are decided by Agent 3 (Verifier).
    # Until then they stay empty instead of being guessed.
    severity: Severity | None = None
    confidence: Confidence | None = None
    detectors: list[Detector] = Field(min_length=1)
    evidence: Evidence = Field(default_factory=Evidence)
    status: FindingStatus | None = None
    explanation: str | None = None
    explanation_source: str | None = None  # "llm" or "template"
    fix: str | None = None
    fix_verified: bool | None = None

    @model_validator(mode="after")
    def _check_lines_and_id(self) -> "Finding":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        if not self.id:
            self.id = make_finding_id(
                self.file, self.line_start, [d.value for d in self.detectors], self.evidence.rule_ids
            )
        return self


def make_finding_id(file: str, line: int, detectors: list[str], rule_ids: list[str]) -> str:
    """Stable ID: the same problem found twice gives the same ID."""
    key = "|".join([file, str(line), ",".join(sorted(detectors)), ",".join(sorted(rule_ids))])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class ToolState(str, Enum):
    OK = "ok"
    MISSING = "missing"
    FAILED = "failed"
    TIMEOUT = "timeout"
    # The check could not run for an expected reason (e.g. no internet for PyPI / OSV).
    SKIPPED = "skipped"


class LLMUsage(BaseModel):
    """Which model answered and how, for one AI check in one scan (recorded for the research runs)."""

    provider: str
    model: str
    prompt_version: str
    calls: int = 0  # requests actually sent to the provider (retries included)
    cache_hits: int = 0


class ToolRun(BaseModel):
    """What happened when one scanner or rule check ran. Lets the UI and CLI say clearly what went wrong."""

    tool: str
    state: ToolState
    version: str | None = None
    message: str | None = None
    duration_s: float = 0.0
    findings_count: int = 0
    # Problems the tool reported for single files (e.g. a file it could not parse).
    file_errors: list[str] = Field(default_factory=list)
    # Other things worth knowing, e.g. an AI answer that was rejected and why.
    notes: list[str] = Field(default_factory=list)
    llm: LLMUsage | None = None


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = Field(default_factory=list)
    tool_runs: list[ToolRun] = Field(default_factory=list)
    duration_s: float = 0.0
