"""Hard-coded and placeholder secrets (rules/secrets.yaml, CWE-798).

Secret values are masked in the evidence, so a report never repeats a real secret in full.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from codeguard.cwe import CweGroups
from codeguard.models import Finding
from codeguard.rulechecks.loader import SecretsFile
from codeguard.rulechecks.source import SourceFile, make_finding

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PATH_LIKE = re.compile(r"^(?:/|\./|\.\./|~/|[A-Za-z]:[\\/])")
_ENV_GETTERS = {"os.getenv", "os.environ.get", "os.environ.setdefault"}

HARD_CODED = "CG-SEC-002"
PLACEHOLDER = "CG-SEC-003"


def normalize_name(name: str) -> str:
    """apiKey -> api_key, "X-Api-Key" -> x_api_key."""
    return _NON_ALNUM.sub("_", _CAMEL.sub(r"\1_\2", name).lower()).strip("_")


@dataclass
class SecretMatcher:
    cfg: SecretsFile

    def __post_init__(self) -> None:
        self.name_re = re.compile(self.cfg.secret_name_regex)
        self.suffixes = {s.lower() for s in self.cfg.ignored_name_suffixes}
        self.prefixes = {s.lower() for s in self.cfg.ignored_name_prefixes}
        self.placeholders = {v.strip().lower() for v in self.cfg.placeholder_values}
        self.placeholder_res = [re.compile(r, re.IGNORECASE) for r in self.cfg.placeholder_regexes]
        self.compare_re = re.compile(self.cfg.compare_name_regex)
        self.ignored_values = {v.strip().lower() for v in self.cfg.ignored_values}
        self.ignored_value_res = [re.compile(r) for r in self.cfg.ignored_value_regexes]
        self.tokens = [(t.name, re.compile(t.regex)) for t in self.cfg.token_patterns]

    def is_secret_name(self, name: str) -> bool:
        norm = normalize_name(name)
        if not norm or not self.name_re.search(norm):
            return False
        parts = norm.split("_")
        return parts[-1] not in self.suffixes and parts[0] not in self.prefixes

    def is_placeholder(self, value: str) -> bool:
        v = value.strip()
        return v.lower() in self.placeholders or any(r.search(v) for r in self.placeholder_res)

    def classify(self, name: str, value: str, comparison: bool = False) -> str | None:
        """Return the rule ID for  <secret-like name> = "<value>", or None if it is not a secret."""
        if not self.is_secret_name(name):
            return None
        if comparison and not self.compare_re.search(normalize_name(name)):
            return None
        v = value.strip()
        if not v or ("{" in v and "}" in v):  # empty, or a format template like "Bearer {}"
            return None
        if v.lower() in self.ignored_values or any(r.search(v) for r in self.ignored_value_res):
            return None
        if normalize_name(v) == normalize_name(name):
            return None  # a label equal to its own name, e.g. apiKey = "apiKey"
        if self.is_placeholder(v):
            return PLACEHOLDER
        if _ENV_VAR_NAME.match(v) and self.is_secret_name(v):
            return None  # the name of an environment variable, e.g. "OPENAI_API_KEY"
        if len(v) < self.cfg.min_length or len(v.split()) > 2 or _PATH_LIKE.match(v):
            return None  # too short, a sentence, or a file path
        return HARD_CODED


def mask(value: str) -> str:
    keep = 2 if len(value) <= 8 else 4
    return value[:keep] + "*" * min(max(len(value) - keep, 3), 12)


def _masked_lines(src: SourceFile, start: int, end: int, secret: str) -> str | None:
    text = src.snippet(start, end)
    return text.replace(secret, mask(secret)) if text and secret else text


def _str_const(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _label(node: ast.AST) -> str | None:
    """The name a value is stored under: x, obj.x, obj["x"]."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _str_const(node.slice)
    return None


def _call_name(func: ast.AST) -> str | None:
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return None


def _candidates(tree: ast.Module):
    """Yield (name, value, node, is_comparison) for every place a string constant is tied to a name."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = _str_const(node.value)
            if value is not None:
                for t in node.targets:
                    if (label := _label(t)) is not None:
                        yield label, value, node, False
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = _str_const(node.value)
            label = _label(node.target)
            if value is not None and label is not None:
                yield label, value, node, False
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                key, value = _str_const(k), _str_const(v)
                if key is not None and value is not None:
                    yield key, value, v, False
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                value = _str_const(kw.value)
                if kw.arg and value is not None:
                    yield kw.arg, value, kw.value, False
            # os.getenv("SECRET_KEY", "dev-secret"): a default secret used when the variable is unset.
            if _call_name(node.func) in _ENV_GETTERS and node.args:
                var = _str_const(node.args[0])
                default = _str_const(node.args[1]) if len(node.args) > 1 else None
                if default is None:
                    default = next((_str_const(k.value) for k in node.keywords if k.arg == "default"), None)
                if var and default:
                    yield var, default, node, False
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left, right = node.left, node.comparators[0]
            for a, b in ((left, right), (right, left)):
                label, value = _label(a), _str_const(b)
                if label is not None and value is not None:
                    yield label, value, node, True


def recognized_secrets(src: SourceFile, matcher: SecretMatcher) -> set[str]:
    """Every value this rule treats as a real secret in the file (CG-SEC-001 tokens, CG-SEC-002 values).

    Placeholders (CG-SEC-003) are not included: they are guessable defaults, not secrets, and are
    shown in full so the user can recognize them.
    """
    values = {m.group(0) for line in src.lines for _, rx in matcher.tokens for m in rx.finditer(line)}
    if src.tree is not None:
        values |= {v for name, v, _, cmp in _candidates(src.tree) if matcher.classify(name, v, cmp) == HARD_CODED}
    return {v for v in values if v}


def check_secrets(src: SourceFile, cfg: SecretsFile, groups: CweGroups, matcher: SecretMatcher | None = None) -> list[Finding]:
    matcher = matcher or SecretMatcher(cfg)
    rules = {r.id: r for r in cfg.rules}
    findings: list[Finding] = []
    token_lines: set[int] = set()

    # CG-SEC-001: known token formats anywhere in the text (code, strings and comments).
    for lineno, line in enumerate(src.lines, start=1):
        for name, rx in matcher.tokens:
            m = rx.search(line)
            if m:
                token_lines.add(lineno)
                findings.append(
                    make_finding(
                        rules["CG-SEC-001"],
                        src,
                        lineno,
                        lineno,
                        groups,
                        title=f"Hard-coded {name}",
                        detail=f"Looks like a {name} ({mask(m.group(0))}).",
                        matched_code=line.replace(m.group(0), mask(m.group(0))),
                    )
                )
                break

    if src.tree is None:
        return findings

    seen: set[tuple[int, str]] = set()
    for name, value, node, comparison in _candidates(src.tree):
        rule_id = matcher.classify(name, value, comparison)
        if rule_id is None:
            continue
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        if start in token_lines or (start, rule_id) in seen:
            continue
        seen.add((start, rule_id))
        if rule_id == PLACEHOLDER:
            detail = f'"{name}" is set to the placeholder "{value.strip()[:40]}".'
            matched = src.snippet(start, end)
        else:
            detail = f'"{name}" is set to a fixed value ({mask(value)}).'
            matched = _masked_lines(src, start, end, value)
        findings.append(make_finding(rules[rule_id], src, start, end, groups, detail=detail, matched_code=matched))
    findings.sort(key=lambda f: f.line_start)
    return findings
