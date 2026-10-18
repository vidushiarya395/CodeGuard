"""Every rule has one vulnerable and one safe example, and both behave as expected.

The list of rules comes from the YAML files, so a new rule without examples fails this test.
"""

import pytest

from codeguard.agents.ai_mistake_finder import run_rule_checks
from codeguard.models import Detector, ToolState
from codeguard.rulechecks.loader import get_rulebook

from conftest import EXAMPLES, FakeIndex

RULE_EXAMPLES = EXAMPLES / "rules"
RULE_IDS = [r.id for r in get_rulebook().all_rules()]


def _findings(folder):
    outcomes = run_rule_checks(folder, index=FakeIndex())
    for o in outcomes:
        assert o.run.state == ToolState.OK, (o.run.tool, o.run.message)
        assert not o.run.file_errors, o.run.file_errors
    return [f for o in outcomes for f in o.findings]


def test_there_are_rules():
    assert len(RULE_IDS) >= 20


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_has_one_vulnerable_and_one_safe_file(rule_id):
    for kind in ("vulnerable", "safe"):
        folder = RULE_EXAMPLES / rule_id / kind
        files = [p for p in folder.iterdir() if p.is_file()] if folder.is_dir() else []
        assert len(files) == 1, f"{rule_id}: expected exactly one file in {folder}"


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_vulnerable_example_is_found(rule_id):
    findings = [f for f in _findings(RULE_EXAMPLES / rule_id / "vulnerable") if rule_id in f.evidence.rule_ids]
    assert findings, f"{rule_id} did not fire on its vulnerable example"
    f = findings[0]
    rule = get_rulebook().rule(rule_id)
    assert f.cwe == rule.cwe
    assert f.detectors == [Detector.RULE_CHECK]
    assert f.evidence.matched_code, "every finding carries the real code as evidence"
    assert set(rule.sources) <= set(f.evidence.references)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_safe_example_has_no_rule_findings(rule_id):
    # Stricter than needed: the safe file must not trigger *any* rule, not just its own.
    findings = _findings(RULE_EXAMPLES / rule_id / "safe")
    assert findings == [], [(f.evidence.rule_ids, f.file, f.line_start) for f in findings]
