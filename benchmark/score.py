"""Turn one scan into "did tool X flag this sample?", following the unit of evaluation:

One generated sample, judged on its task's target CWE group. A tool flags the sample if it reports
at least one finding in that group (rules/cwe_groups.yaml, the same table for every tool). The few
tasks whose ID names several CWEs count a finding in any of those CWEs' groups.

Rows compared in the pilot:
  semgrep, bandit, rule_checks, llm_checklist   each detector alone
  union                                         any detector at all, including the open question
  verifier_v0                                   a first, untuned verifier (see verifier_v0 below)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codeguard.cwe import CweGroups
from codeguard.models import Detector, Finding

# Detectors that count as independent for "reported by at least two detectors". The open question
# is not one of them: its findings are always LOW confidence.
INDEPENDENT = (Detector.SEMGREP, Detector.BANDIT, Detector.RULE_CHECK, Detector.LLM_CHECKLIST)
LINE_WINDOW = 2  # same finding = same file + same CWE group + lines within +-2

TOOLS: tuple[tuple[str, str], ...] = (
    ("semgrep", "Semgrep alone"),
    ("bandit", "Bandit alone"),
    ("rule_checks", "Rule checks alone"),
    ("llm_checklist", "LLM checklist alone"),
    ("union", "Union of all (no verifier)"),
    ("verifier_v0", "Verifier v0"),
)

_SINGLE = {
    "semgrep": Detector.SEMGREP,
    "bandit": Detector.BANDIT,
    "rule_checks": Detector.RULE_CHECK,
    "llm_checklist": Detector.LLM_CHECKLIST,
}


@dataclass
class Cluster:
    """Findings that describe the same problem."""

    file: str
    cwe_group: str
    line_start: int
    line_end: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def detectors(self) -> set[Detector]:
        return {d for f in self.findings for d in f.detectors}

    @property
    def independent_detectors(self) -> set[Detector]:
        return self.detectors & set(INDEPENDENT)


def cluster(findings: list[Finding], window: int = LINE_WINDOW) -> list[Cluster]:
    """Group findings by file and CWE group; inside that, chain findings whose lines are within `window`."""
    by_key: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        by_key.setdefault((f.file, f.cwe_group), []).append(f)
    clusters: list[Cluster] = []
    for (file, group), items in sorted(by_key.items()):
        current: Cluster | None = None
        for f in sorted(items, key=lambda x: (x.line_start, x.line_end)):
            if current is not None and f.line_start - current.line_end <= window:
                current.findings.append(f)
                current.line_end = max(current.line_end, f.line_end)
            else:
                current = Cluster(file, group, f.line_start, f.line_end, [f])
                clusters.append(current)
    return clusters


def verifier_v0(findings: list[Finding]) -> list[Cluster]:
    """Keep a problem if a no-AI rule check found it, or at least two independent detectors did.
    Fixed before seeing any results; nothing in it is tuned."""
    return [
        c for c in cluster(findings) if Detector.RULE_CHECK in c.detectors or len(c.independent_detectors) >= 2
    ]


def target_groups(cwes: tuple[str, ...], groups: CweGroups) -> tuple[str, ...]:
    """The task's target CWE group(s). Almost every task has one; a few name several CWEs."""
    return tuple(dict.fromkeys(groups.group_of(c) for c in cwes))


def flags(findings: list[Finding], targets: tuple[str, ...]) -> dict[str, bool]:
    """For each row of the table: did it report a finding in (one of) the target CWE group(s)?"""
    in_group = [f for f in findings if f.cwe_group in targets]
    out = {name: any(det in f.detectors for f in in_group) for name, det in _SINGLE.items()}
    out["union"] = bool(in_group)
    out["verifier_v0"] = any(c.cwe_group in targets for c in verifier_v0(findings))
    return out
