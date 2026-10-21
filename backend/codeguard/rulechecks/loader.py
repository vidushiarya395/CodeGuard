"""Loads and validates the rule files in rules/.

Every file is checked with pydantic when it is loaded, so a typo in a YAML file gives a clear
error naming the file, instead of a rule that silently never fires.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from codeguard.config import get_settings
from codeguard.cwe import normalize_cwe

RULE_ID_RE = re.compile(r"^CG-[A-Z]{2,5}-\d{3}$")


class RuleFileError(ValueError):
    """A rule file is missing or broken."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _as_list(value: Any) -> Any:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class RuleMeta(_Strict):
    """What every rule has: an ID, a CWE, a message, a fix hint and at least one real source."""

    id: str
    title: str
    cwe: str
    message: str
    fix_hint: str
    sources: list[str] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not RULE_ID_RE.match(v):
            raise ValueError(f"rule id '{v}' must look like CG-ABC-001")
        return v

    @field_validator("cwe", mode="before")
    @classmethod
    def _check_cwe(cls, v: Any) -> str:
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


class Condition(_Strict):
    """One condition on a call argument (see the comment at the top of deprecated_apis.yaml)."""

    arg: str | None = None
    position: int | None = Field(default=None, ge=0)
    is_: Any = Field(default=None, alias="is")
    in_: list[str] | None = Field(default=None, alias="in")
    missing: bool = False
    missing_or_not_in: list[str] | None = None
    not_constant: bool = False
    dict_has: dict[str, Any] | None = None
    # The argument is a string constant matching this regex (case-insensitive).
    matches: str | None = None
    # The argument is missing, False or None (a variable or call is unknown, so it does not hold).
    not_true: bool = False

    @field_validator("matches")
    @classmethod
    def _regex(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"bad regex {v!r}: {exc}") from exc
        return v

    @property
    def has_is(self) -> bool:
        # "is: null" and no "is" at all both give None, so check what was actually written.
        return "is_" in self.model_fields_set

    @model_validator(mode="after")
    def _check(self) -> "Condition":
        if self.arg is None and self.position is None:
            raise ValueError("a condition needs 'arg' or 'position'")
        tests = [
            self.has_is,
            self.in_ is not None,
            self.missing,
            self.missing_or_not_in is not None,
            self.not_constant,
            self.dict_has is not None,
            self.matches is not None,
            self.not_true,
        ]
        if sum(tests) != 1:
            raise ValueError(
                "a condition needs exactly one of: is, in, missing, missing_or_not_in, not_constant, dict_has, "
                "matches, not_true"
            )
        return self


class Pattern(_Strict):
    call: list[str] = Field(default_factory=list)
    import_: list[str] = Field(default_factory=list, alias="import")
    attribute: list[str] = Field(default_factory=list)
    assign: list[str] = Field(default_factory=list)
    where: list[Condition] = Field(default_factory=list)
    value_is: Any = None
    value_in: list[str] | None = None
    files: list[str] = Field(default_factory=list)

    @field_validator("call", "import_", "attribute", "assign", "files", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> Any:
        return _as_list(v)

    @property
    def kind(self) -> str:
        return next(k for k in ("call", "import_", "attribute", "assign") if getattr(self, k))

    @property
    def has_value_is(self) -> bool:
        return "value_is" in self.model_fields_set

    @model_validator(mode="after")
    def _check(self) -> "Pattern":
        kinds = [k for k in ("call", "import_", "attribute", "assign") if getattr(self, k)]
        if len(kinds) != 1:
            raise ValueError("a pattern needs exactly one of: call, import, attribute, assign")
        if self.where and kinds[0] != "call":
            raise ValueError("'where' is only allowed on call patterns")
        if kinds[0] == "assign":
            if self.has_value_is == (self.value_in is not None):
                raise ValueError("an assign pattern needs exactly one of: value_is, value_in")
        elif self.has_value_is or self.value_in is not None:
            raise ValueError("value_is / value_in are only allowed on assign patterns")
        return self


class AstRule(RuleMeta):
    patterns: list[Pattern] = Field(min_length=1)


class AstRuleFile(_Strict):
    version: int
    rules: list[AstRule] = Field(min_length=1)


class TokenPattern(_Strict):
    name: str
    regex: str
    sources: list[str] = Field(min_length=1)

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"bad regex {v!r}: {exc}") from exc
        return v


class SecretsFile(_Strict):
    version: int
    rules: list[RuleMeta]
    token_patterns: list[TokenPattern] = Field(min_length=1)
    secret_name_regex: str
    ignored_name_suffixes: list[str] = Field(default_factory=list)
    ignored_name_prefixes: list[str] = Field(default_factory=list)
    min_length: int = Field(default=4, ge=1)
    compare_name_regex: str
    ignored_values: list[str] = Field(default_factory=list)
    ignored_value_regexes: list[str] = Field(default_factory=list)
    placeholder_values: list[str] = Field(default_factory=list)
    placeholder_regexes: list[str] = Field(default_factory=list)

    @field_validator("placeholder_values", "ignored_values", mode="before")
    @classmethod
    def _as_strings(cls, v: Any) -> Any:
        return [str(x) for x in v] if isinstance(v, list) else v

    @field_validator("secret_name_regex", "compare_name_regex")
    @classmethod
    def _name_compiles(cls, v: str) -> str:
        re.compile(v)
        return v

    @field_validator("placeholder_regexes", "ignored_value_regexes")
    @classmethod
    def _placeholders_compile(cls, v: list[str]) -> list[str]:
        for rx in v:
            re.compile(rx)
        return v

    @model_validator(mode="after")
    def _needs_rules(self) -> "SecretsFile":
        ids = {r.id for r in self.rules}
        missing = {"CG-SEC-001", "CG-SEC-002", "CG-SEC-003"} - ids
        if missing:
            raise ValueError(f"missing rules: {', '.join(sorted(missing))}")
        return self


class PackagesFile(_Strict):
    version: int
    rules: list[RuleMeta]

    @model_validator(mode="after")
    def _needs_rules(self) -> "PackagesFile":
        missing = {"CG-PKG-001", "CG-OSV-001"} - {r.id for r in self.rules}
        if missing:
            raise ValueError(f"missing rules: {', '.join(sorted(missing))}")
        return self


class ImportMapFile(_Strict):
    version: int
    map: dict[str, str | None]


def _https_only(v: list[str]) -> list[str]:
    for url in v:
        if not url.startswith("https://"):
            raise ValueError(f"source must be an https:// link, got '{url}'")
    return v


def _compiles(name: str, value: str) -> None:
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"{name}: bad regex {value!r}: {exc}") from exc


# --- Logic-flaw rules (rules/logic_flaws.yaml) ---

LOGIC_CHECKS = (
    "missing_authentication",
    "missing_authorization",
    "idor",
    "unrestricted_upload",
    "mass_assignment",
    "cors_wildcard_credentials",
    "drf_open_viewset",
)


class LogicRule(RuleMeta):
    """A logic-flaw rule: either AST patterns (same format as insecure_settings.yaml) or a named
    check in codeguard/rulechecks/logic.py, which reads its word lists from `signals`."""

    check: str | None = None
    patterns: list[Pattern] = Field(default_factory=list)

    @model_validator(mode="after")
    def _one_kind(self) -> "LogicRule":
        if (self.check is None) == (not self.patterns):
            raise ValueError("a logic rule needs exactly one of: check, patterns")
        if self.check is not None and self.check not in LOGIC_CHECKS:
            raise ValueError(f"unknown check '{self.check}' (known: {', '.join(LOGIC_CHECKS)})")
        return self


class LogicSignals(_Strict):
    """Word lists the logic checks use to recognise logins, roles and sensitive actions.
    Every *_regex is matched case-insensitively; every *_calls / *_names list holds dotted-name
    patterns ("*" = anything), compared with the full names the AST checks resolve."""

    auth_decorator_regex: str
    role_decorator_regex: str
    auth_names: list[str] = Field(min_length=1)
    auth_attribute_regex: str
    role_regex: str
    public_route_regex: str
    sensitive_route_regex: str
    admin_route_regex: str
    write_calls: list[str] = Field(min_length=1)
    destructive_calls: list[str] = Field(min_length=1)
    sql_write_regex: str
    sql_destructive_regex: str
    fetch_calls: list[str] = Field(min_length=1)
    id_param_regex: str
    ownership_regex: str
    upload_check_regex: str
    upload_check_calls: list[str] = Field(min_length=1)
    db_dependency_regex: str

    @model_validator(mode="after")
    def _regexes_compile(self) -> "LogicSignals":
        for name, value in self:
            if name.endswith("_regex"):
                _compiles(name, value)
        return self


class LogicFile(_Strict):
    version: int
    signals: LogicSignals
    rules: list[LogicRule] = Field(min_length=1)


# --- Taint check (rules/sinks.yaml and rules/taint.yaml) ---

INPUT_KINDS = ("web", "cli", "stdin", "env", "file")


class SinkPattern(_Strict):
    call: list[str] = Field(min_length=1)
    args: list[int] = Field(default_factory=list)  # argument positions that must not carry user input
    kwargs: list[str] = Field(default_factory=list)  # keyword names that must not carry user input
    where: list[Condition] = Field(default_factory=list)

    @field_validator("call", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> Any:
        return _as_list(v)

    @model_validator(mode="after")
    def _needs_target(self) -> "SinkPattern":
        if not self.args and not self.kwargs:
            raise ValueError("a sink pattern needs 'args' or 'kwargs'")
        return self


class SinkRule(RuleMeta):
    from_: list[str] = Field(alias="from", min_length=1)  # which kinds of input count for this sink
    patterns: list[SinkPattern] = Field(default_factory=list)
    # Only report when the input is built into text that holds an HTML tag ("<p>" + name).
    html_only: bool = False
    # Also check what a Flask view returns (Flask sends a returned string as a text/html page).
    flask_return: bool = False

    @field_validator("from_")
    @classmethod
    def _kinds(cls, v: list[str]) -> list[str]:
        bad = [k for k in v if k not in INPUT_KINDS]
        if bad:
            raise ValueError(f"unknown input kind(s): {', '.join(bad)} (known: {', '.join(INPUT_KINDS)})")
        return v

    @model_validator(mode="after")
    def _needs_sink(self) -> "SinkRule":
        if not self.patterns and not self.flask_return:
            raise ValueError("a sink rule needs patterns (or flask_return)")
        return self


class SinksFile(_Strict):
    version: int
    rules: list[SinkRule] = Field(min_length=1)


class TaintSource(_Strict):
    id: str
    kind: str
    title: str
    taint: bool = True  # False: listed as an entry point only, never followed by the taint check
    names: list[str] = Field(default_factory=list)  # dotted names (attributes or calls) that give input
    whole_body: list[str] = Field(default_factory=list)  # the names among them that give the whole body
    request_param: list[str] = Field(default_factory=list)  # attributes of a view's `request` parameter
    route_params: bool = False  # the parameters of a route function
    param_decorators: list[str] = Field(default_factory=list)  # decorators that make parameters input
    sources: list[str] = Field(min_length=1)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in INPUT_KINDS:
            raise ValueError(f"unknown input kind '{v}' (known: {', '.join(INPUT_KINDS)})")
        return v

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        return _https_only(v)


class Sanitizer(_Strict):
    call: list[str] = Field(min_length=1)
    clears: list[str] = Field(min_length=1)  # CWE group IDs this makes safe, or "all"
    sources: list[str] = Field(min_length=1)

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        return _https_only(v)


class Validators(_Strict):
    """Checks that, used as an `if` test before the sink, count as validating the value."""

    call: list[str] = Field(default_factory=list)
    name_regex: str
    sources: list[str] = Field(min_length=1)

    @field_validator("name_regex")
    @classmethod
    def _regex(cls, v: str) -> str:
        _compiles("name_regex", v)
        return v

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        return _https_only(v)


class TaintFile(_Strict):
    version: int
    sources: list[TaintSource] = Field(min_length=1)
    sanitizers: list[Sanitizer] = Field(min_length=1)
    propagators: list[str] = Field(min_length=1)
    validators: Validators

    @model_validator(mode="after")
    def _unique(self) -> "TaintFile":
        ids = [s.id for s in self.sources]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"source id used twice: {', '.join(dupes)}")
        return self


class Rulebook(BaseModel):
    """Everything in rules/ that the rule checks need."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    deprecated: AstRuleFile
    settings: AstRuleFile
    secrets: SecretsFile
    packages: PackagesFile
    import_map: ImportMapFile
    logic: LogicFile
    sinks: SinksFile
    taint: TaintFile

    def all_rules(self) -> list[RuleMeta]:
        """The rule checks (detector "rule_check"). The taint check's rules are in taint_rules()."""
        return [
            *self.packages.rules,
            *self.deprecated.rules,
            *self.settings.rules,
            *self.secrets.rules,
            *self.logic.rules,
        ]

    def taint_rules(self) -> list[SinkRule]:
        return list(self.sinks.rules)

    def rule(self, rule_id: str) -> RuleMeta:
        return next(r for r in [*self.all_rules(), *self.taint_rules()] if r.id == rule_id)


def _load(path: Path, model: type[BaseModel]) -> Any:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuleFileError(f"Rule file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise RuleFileError(f"{path.name} is not valid YAML: {exc}") from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise RuleFileError(f"{path.name}: {where}: {first['msg']}") from exc


def load_rulebook(rules_dir: Path) -> Rulebook:
    book = Rulebook(
        deprecated=_load(rules_dir / "deprecated_apis.yaml", AstRuleFile),
        settings=_load(rules_dir / "insecure_settings.yaml", AstRuleFile),
        secrets=_load(rules_dir / "secrets.yaml", SecretsFile),
        packages=_load(rules_dir / "packages.yaml", PackagesFile),
        import_map=_load(rules_dir / "import_map.yaml", ImportMapFile),
        logic=_load(rules_dir / "logic_flaws.yaml", LogicFile),
        sinks=_load(rules_dir / "sinks.yaml", SinksFile),
        taint=_load(rules_dir / "taint.yaml", TaintFile),
    )
    seen: set[str] = set()
    for rule in [*book.all_rules(), *book.taint_rules()]:
        if rule.id in seen:
            raise RuleFileError(f"Rule id {rule.id} is used twice in rules/")
        seen.add(rule.id)
    return book


@lru_cache(maxsize=4)
def _cached(path_str: str) -> Rulebook:
    return load_rulebook(Path(path_str))


def get_rulebook(rules_dir: Path | None = None) -> Rulebook:
    return _cached(str(rules_dir or get_settings().rules_dir))
