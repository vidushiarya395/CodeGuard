"""The YAML rule files are valid, every rule has a source, and docs/RULE_SOURCES.md lists them all."""

import shutil

import pytest

from codeguard.config import REPO_ROOT
from codeguard.cwe import get_cwe_groups
from codeguard.rulechecks.loader import RuleFileError, load_rulebook

RULE_SOURCES = REPO_ROOT / "docs" / "RULE_SOURCES.md"


def test_every_rule_has_https_sources(rulebook):
    for rule in rulebook.all_rules():
        assert rule.sources, rule.id
        assert all(s.startswith("https://") for s in rule.sources), rule.id


def test_every_rule_is_documented_with_its_sources(rulebook):
    doc = RULE_SOURCES.read_text(encoding="utf-8")
    for rule in rulebook.all_rules():
        assert rule.id in doc, f"{rule.id} is missing from docs/RULE_SOURCES.md"
        assert rule.cwe in doc, f"{rule.cwe} ({rule.id}) is missing from docs/RULE_SOURCES.md"
        for src in rule.sources:
            assert src in doc, f"source of {rule.id} missing from docs/RULE_SOURCES.md: {src}"
    for pattern in rulebook.secrets.token_patterns:
        assert pattern.name in doc, pattern.name
        for src in pattern.sources:
            assert src in doc, f"source of token pattern '{pattern.name}' missing: {src}"


def test_every_rule_cwe_has_a_named_group(rulebook):
    groups = get_cwe_groups()
    for rule in rulebook.all_rules():
        assert rule.cwe in groups.by_cwe, f"{rule.id}: {rule.cwe} is not in rules/cwe_groups.yaml"


def test_import_map_covers_the_required_examples(rulebook):
    m = rulebook.import_map.map
    assert m["cv2"] == "opencv-python"
    assert m["yaml"] == "PyYAML"
    assert m["sklearn"] == "scikit-learn"


@pytest.fixture
def rules_copy(tmp_path):
    dest = tmp_path / "rules"
    shutil.copytree(REPO_ROOT / "rules", dest)
    return dest


def _edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_rule_without_source_is_rejected(rules_copy):
    _edit(
        rules_copy / "deprecated_apis.yaml",
        "    sources:\n      - https://docs.python.org/3/library/tempfile.html#tempfile.mktemp\n"
        "      - https://cwe.mitre.org/data/definitions/377.html\n",
        "    sources: []\n",
    )
    with pytest.raises(RuleFileError, match="deprecated_apis.yaml"):
        load_rulebook(rules_copy)


def test_unknown_key_is_rejected(rules_copy):
    _edit(rules_copy / "insecure_settings.yaml", "        value_is: false\n", "        value_iss: false\n")
    with pytest.raises(RuleFileError, match="insecure_settings.yaml"):
        load_rulebook(rules_copy)


def test_duplicate_rule_id_is_rejected(rules_copy):
    _edit(rules_copy / "deprecated_apis.yaml", "id: CG-DEP-002", "id: CG-DEP-001")
    with pytest.raises(RuleFileError, match="used twice"):
        load_rulebook(rules_copy)


def test_broken_rules_are_reported_not_raised(rules_copy, tmp_path, settings, fake_index):
    from dataclasses import replace

    from codeguard.agents.ai_mistake_finder import run_rule_checks
    from codeguard.models import ToolState

    (rules_copy / "secrets.yaml").write_text("version: [", encoding="utf-8")
    code = tmp_path / "a.py"
    code.write_text("x = 1\n", encoding="utf-8")
    outcomes = run_rule_checks(code, settings=replace(settings, rules_dir=rules_copy), index=fake_index)
    assert all(o.run.state == ToolState.FAILED for o in outcomes)
    assert "secrets.yaml" in outcomes[0].run.message
