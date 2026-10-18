"""Masks secret values in every finding, whichever detector reported it.

The secrets rule check masks its own evidence, but Semgrep and Bandit copy the raw line and
often quote the value in their message (Bandit: "Possible hardcoded password: '...'"). This runs
once on the combined findings, before anything is printed, returned or stored, so the CLI, the
JSON output, the API and exports never repeat a secret in full.

Only secret-looking values are masked:
  - values the secrets rule recognizes (rules/secrets.yaml), in every finding for that file;
  - on a line flagged as a hard-coded credential (by any detector), the string literal that holds
    the credential: the one tied to a secret-like name or quoted by the tool itself. If neither
    applies, every string literal on those lines is masked, to be safe.
Placeholders ("YOUR_API_KEY_HERE") stay visible, like in the secrets rule check.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from codeguard.cwe import CweGroups
from codeguard.models import Finding
from codeguard.rulechecks.loader import RuleFileError, get_rulebook
from codeguard.rulechecks.secrets import SecretMatcher, _label, mask, recognized_secrets
from codeguard.rulechecks.source import SourceFile, load_sources

CREDENTIAL_CWE = "CWE-798"
MIN_LENGTH = 4  # used when the secrets rule file cannot be loaded
_QUOTED = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")
_LITERAL = re.compile(r"""^[A-Za-z]*('''|\"\"\"|'|")(.*)\1$""", re.DOTALL)


def mask_secrets(
    findings: list[Finding],
    path: Path,
    groups: CweGroups,
    rules_dir: Path | None = None,
    display_name: str | None = None,
) -> list[Finding]:
    """Mask secret values in the title and evidence of every finding (changes the findings in place)."""
    if not findings:
        return findings
    try:
        matcher: SecretMatcher | None = SecretMatcher(get_rulebook(rules_dir).secrets)
    except RuleFileError:
        matcher = None  # still mask credential lines, just without the rule file's filters
    cred_group = groups.group_of(CREDENTIAL_CWE)

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)
    sources = load_sources(path, display_name)
    files = {s.rel: s for s in [*sources.python, *sources.requirements] if s.rel in by_file}

    for rel, file_findings in by_file.items():
        src = files.get(rel)
        if src is None:
            continue
        literals = _literals(src)
        file_secrets = recognized_secrets(src, matcher) if matcher else set()
        file_secrets = _with_raw_forms(file_secrets, literals)
        for f in file_findings:
            secrets = set(file_secrets)
            if f.cwe_group == cred_group:
                secrets |= _credential_values(f, src, literals, matcher)
            if secrets:
                _apply(f, secrets)
    return findings


class _Literal:
    __slots__ = ("value", "start", "end", "name", "_node", "_text", "_raw")

    def __init__(self, value: str, start: int, end: int, name: str | None, node=None, text: str = "", raw=None) -> None:
        self.value, self.start, self.end, self.name = value, start, end, name
        self._node, self._text, self._raw = node, text, raw

    @property
    def raw(self) -> str:
        """The literal as written in the file, without quotes (looked up only when needed)."""
        if self._raw is None:
            segment = ast.get_source_segment(self._text, self._node) or ""
            m = _LITERAL.match(segment)
            self._raw = m.group(2) if m else self.value
        return self._raw


def _literals(src: SourceFile) -> list[_Literal]:
    """Every string literal in the file, with its source form and the name it is stored under, if any."""
    if src.tree is None:
        return [
            _Literal(m.group(2), n, n, None, raw=m.group(2))
            for n, line in enumerate(src.lines, start=1)
            for m in _QUOTED.finditer(line)
        ]
    names: dict[int, str] = {}
    for node in ast.walk(src.tree):
        pairs = []
        if isinstance(node, ast.Assign):
            pairs = [(t, node.value) for t in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = [(node.target, node.value)]
        elif isinstance(node, ast.Dict):
            pairs = [(k, v) for k, v in zip(node.keys, node.values) if k is not None]
        elif isinstance(node, ast.Compare) and len(node.comparators) == 1:
            pairs = [(node.left, node.comparators[0]), (node.comparators[0], node.left)]
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    names[id(kw.value)] = kw.arg
        for target, value in pairs:
            label = _label(target)
            if label is not None:
                names[id(value)] = label

    out = []
    for node in ast.walk(src.tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            end = node.end_lineno or node.lineno
            out.append(_Literal(node.value, node.lineno, end, names.get(id(node)), node, src.text))
    return out


def _with_raw_forms(values: set[str], literals: list[_Literal]) -> set[str]:
    """Add the source form of each value too (they differ when the literal has escapes)."""
    return values | {lit.raw for lit in literals if lit.value in values and lit.raw}


def _credential_values(f: Finding, src: SourceFile, literals: list[_Literal], matcher: SecretMatcher | None) -> set[str]:
    """The string literal(s) on a hard-coded-credential finding's lines that hold the credential."""
    min_len = matcher.cfg.min_length if matcher else MIN_LENGTH
    tool_text = "\n".join([f.title, *f.evidence.messages])
    on_lines = []
    for lit in literals:
        if lit.end < f.line_start or lit.start > f.line_end:
            continue
        v = lit.value.strip()
        if len(v) < min_len:
            continue
        if matcher and (matcher.is_placeholder(v) or v.lower() in matcher.ignored_values):
            continue
        on_lines.append(lit)

    strong = [
        lit for lit in on_lines
        if lit.value in tool_text or (matcher and lit.name is not None and matcher.is_secret_name(lit.name))
    ]  # fmt: skip
    chosen = strong or on_lines
    return {s for lit in chosen for s in (lit.value, lit.raw) if s}


def _apply(f: Finding, secrets: set[str]) -> None:
    # Longest first, so a secret that contains another one is masked as a whole.
    ordered = sorted(secrets, key=len, reverse=True)
    pattern = re.compile(
        "|".join(rf"(?<![A-Za-z0-9_]){re.escape(s)}(?![A-Za-z0-9_])" for s in ordered)
    )

    def sub(text: str) -> str:
        return pattern.sub(lambda m: mask(m.group(0)), text)

    f.title = sub(f.title)
    ev = f.evidence
    if ev.matched_code:
        ev.matched_code = sub(ev.matched_code)
    ev.messages = [sub(m) for m in ev.messages]
    ev.llm_reasons = [sub(m) for m in ev.llm_reasons]
