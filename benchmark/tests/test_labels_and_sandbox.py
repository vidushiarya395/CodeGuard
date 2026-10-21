"""Labelling rules and the sandbox's Docker command (Docker itself is not started here)."""

from benchmark import labels, sandbox
from benchmark.sandbox import SuiteResult

PASS = SuiteResult(True, "done")
FAIL = SuiteResult(False, "test", "AssertionError", "boom")
CRASH = SuiteResult(False, "load", "ImportError", "no module")


def test_sample_labels():
    assert labels.label_sample({"fp": PASS, "sp": FAIL})[0] == labels.VULNERABLE
    assert labels.label_sample({"fp": PASS, "sp": PASS})[0] == labels.SAFE
    # Code that does not do the job is left out, whatever the security tests say.
    assert labels.label_sample({"fp": FAIL, "sp": FAIL})[0] == labels.NOT_FUNCTIONAL
    assert labels.label_sample({"fp": CRASH, "sp": PASS})[0] == labels.NOT_FUNCTIONAL


def test_task_is_usable_only_when_its_tests_separate_the_references():
    ok = {"fp": PASS, "sp": PASS}
    assert labels.task_usable(ok, {"fp": PASS, "sp": FAIL}) == (True, "ok")
    usable, reason = labels.task_usable(ok, {"fp": PASS, "sp": PASS})
    assert not usable and "insecure reference passes Test-SP" in reason
    usable, reason = labels.task_usable({"fp": CRASH, "sp": PASS}, {"fp": PASS, "sp": FAIL})
    assert not usable and "secure reference fails Test-FP" in reason


def test_docker_command_isolates_the_container():
    cmd = sandbox.docker_command("img:1", "cg-bench-x")
    joined = " ".join(cmd)
    assert "--network none" in joined
    assert "--read-only" in cmd and "--rm" in cmd
    assert "--cap-drop ALL" in joined and "no-new-privileges" in joined
    assert "--memory" in cmd and "--pids-limit" in cmd and "--user 65534:65534" in joined
    # Nothing from the laptop is mounted into the container.
    assert not any(a in ("-v", "--volume", "--mount") for a in cmd)
    assert cmd[-1] == "img:1"


def test_image_tag_follows_the_image_files():
    tag = sandbox.image_tag()
    assert tag.startswith("codeguard-bench-sandbox:") and len(tag.split(":")[1]) == 12
