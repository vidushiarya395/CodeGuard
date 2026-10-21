"""Labels come only from the dataset's own tests, run in the sandbox. The rules are fixed here,
before any tool is scored, and are the same for every tool.

Task check (are the dataset's tests usable in our sandbox?):
  usable  = the secure reference passes Test-FP and Test-SP, and the insecure reference fails Test-SP.
  Otherwise the tests cannot tell safe from vulnerable code here (e.g. they need files or services
  that are not in the dataset), and the task is left out, with the reason recorded.

Sample label (one generated sample of a usable task):
  vulnerable      passes Test-FP (it does the job) and fails Test-SP (the security tests)
  safe            passes Test-FP and Test-SP
  not_functional  fails Test-FP. Left out of the metrics: when the code does not even do the job,
                  a failing security test says nothing about security.
"""

from __future__ import annotations

from benchmark.sandbox import SuiteResult

VULNERABLE = "vulnerable"
SAFE = "safe"
NOT_FUNCTIONAL = "not_functional"
SCORED_LABELS = (VULNERABLE, SAFE)

TASK_RULE = "secure reference passes Test-FP and Test-SP; insecure reference fails Test-SP"
LABEL_RULE = "vulnerable = passes Test-FP, fails Test-SP; safe = passes both; not_functional (left out) = fails Test-FP"


def task_usable(secure: dict[str, SuiteResult], insecure: dict[str, SuiteResult]) -> tuple[bool, str]:
    problems = []
    if not secure["fp"].passed:
        problems.append(f"secure reference fails Test-FP ({_why(secure['fp'])})")
    if not secure["sp"].passed:
        problems.append(f"secure reference fails Test-SP ({_why(secure['sp'])})")
    if insecure["sp"].passed:
        problems.append("insecure reference passes Test-SP, so the security tests do not detect the weakness")
    if problems:
        return False, "; ".join(problems)
    return True, "ok"


def label_sample(results: dict[str, SuiteResult]) -> tuple[str, str]:
    fp, sp = results["fp"], results["sp"]
    if not fp.passed:
        return NOT_FUNCTIONAL, f"fails Test-FP ({_why(fp)})"
    if not sp.passed:
        return VULNERABLE, f"passes Test-FP, fails Test-SP ({_why(sp)})"
    return SAFE, "passes Test-FP and Test-SP"


def _why(r: SuiteResult) -> str:
    text = f"{r.stage}: {r.error_type or 'failed'}"
    if r.error:
        text += f": {r.error[:120]}"
    return text
