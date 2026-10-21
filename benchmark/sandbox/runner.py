"""Runs inside the sandbox container only. Never run this on the host.

Reads one job from stdin:
    {"code": "...", "entry_point": "name", "tests": {"fp": "def check(candidate): ...", ...}, "timeout_s": 10}
and prints one JSON line with the outcome of each test suite:
    {"fp": {"passed": true, ...}, "sp": {"passed": false, "stage": "test", "error_type": "AssertionError", ...}}

Each suite runs in its own fresh Python process and its own empty working folder, with a time
limit, so one suite cannot affect another. As in CodeSecEval's own evaluation notebook, the test
code runs in the candidate's namespace (tests may patch the candidate's globals) and then calls
check(candidate). Unlike the notebook, no fake stand-ins are installed for missing packages: the
real, pinned packages from requirements.txt are used.
"""

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile

MAX_ERROR_CHARS = 300

BOOT = r"""
import json, sys
code_path, test_path, entry, marker = sys.argv[1:5]
del sys.argv[1:]
stage = "load"
try:
    # Like an imported module: generated code may use __file__ (e.g. to find a templates folder).
    ns = {"__name__": "candidate", "__file__": code_path, "__builtins__": __builtins__}
    with open(code_path, encoding="utf-8") as fh:
        source = fh.read()
    exec(compile(source, "candidate.py", "exec"), ns)
    stage = "entry"
    candidate = ns[entry]
    if not callable(candidate):
        raise TypeError("entry point is not callable")
    stage = "test"
    with open(test_path, encoding="utf-8") as fh:
        test = fh.read()
    exec(compile(test, "test.py", "exec"), ns)
    ns["check"](candidate)
    out = {"passed": True, "stage": "done"}
except BaseException as exc:
    out = {"passed": False, "stage": stage, "error_type": type(exc).__name__, "error": str(exc)[:%d]}
sys.stdout.flush()
sys.__stdout__.write("\n" + marker + json.dumps(out) + "\n")
sys.__stdout__.flush()
""" % MAX_ERROR_CHARS


def run_suite(code, entry, test, timeout_s):
    job_dir = tempfile.mkdtemp(prefix="job-", dir="/tmp")
    src_dir = os.path.join(job_dir, "src")
    work_dir = os.path.join(job_dir, "work")
    os.makedirs(src_dir)
    os.makedirs(work_dir)
    code_path = os.path.join(src_dir, "candidate.py")
    test_path = os.path.join(src_dir, "test.py")
    with open(code_path, "w", encoding="utf-8") as fh:
        fh.write(code)
    with open(test_path, "w", encoding="utf-8") as fh:
        fh.write(test)
    marker = "@@RESULT-" + secrets.token_hex(8) + "@@"
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", BOOT, code_path, test_path, entry, marker],
        cwd=work_dir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.communicate()
        return {"passed": False, "stage": "timeout", "error_type": "Timeout", "error": f"over {timeout_s} s"}
    for line in reversed(stdout.decode("utf-8", "replace").splitlines()):
        if line.startswith(marker):
            try:
                return json.loads(line[len(marker):])
            except ValueError:
                break
    return {
        "passed": False,
        "stage": "crash",
        "error_type": "NoResult",
        "error": f"the test process exited with code {proc.returncode} without a result",
    }


def main():
    job = json.loads(sys.stdin.read())
    timeout_s = float(job.get("timeout_s", 10))
    results = {}
    for name, test in job["tests"].items():
        results[name] = run_suite(job["code"], job["entry_point"], test, timeout_s)
    sys.stdout.write(json.dumps(results) + "\n")


if __name__ == "__main__":
    main()
