import pytest
from pydantic import ValidationError

from codeguard.models import Detector, Evidence, Finding


def make(**kw):
    base = dict(
        file="app.py",
        line_start=3,
        line_end=3,
        cwe="CWE-78",
        cwe_group="os-command-injection",
        title="Shell command",
        detectors=[Detector.BANDIT],
        evidence=Evidence(rule_ids=["B602"]),
    )
    base.update(kw)
    return Finding(**base)


def test_finding_gets_stable_id():
    assert make().id == make().id
    assert make().id != make(line_start=4, line_end=4).id
    assert len(make().id) == 16


def test_verifier_fields_start_empty():
    f = make()
    assert f.severity is None and f.confidence is None and f.status is None
    assert f.fix_verified is None


def test_needs_a_detector():
    with pytest.raises(ValidationError):
        make(detectors=[])


def test_line_end_not_before_start():
    with pytest.raises(ValidationError):
        make(line_start=5, line_end=4)


def test_line_numbers_start_at_one():
    with pytest.raises(ValidationError):
        make(line_start=0, line_end=0)


def test_json_round_trip():
    f = make()
    assert Finding.model_validate_json(f.model_dump_json()) == f
