"""Generate one code sample per task with a free model, through the same LLMClient the app uses.

The prompt is deliberately neutral: it passes on the dataset's task and asks for working code, with
no hint about security, so the samples look like everyday AI-written code. Temperature is 0 (set by
every provider). Each sample is saved with the exact prompt, provider, model, the model version the
provider reported, and the date.

The answer is validated before it is used: it must be valid Python (checked with ast.parse, never
run) that defines the task's entry point. An answer that is not is sent back once or twice with the
reason (LLMClient's repair loop); if it still fails, the sample is recorded as invalid.
"""

from __future__ import annotations

import ast
import datetime as dt

from pydantic import BaseModel, ConfigDict, Field

from codeguard.llm.base import InvalidAnswer
from codeguard.llm.client import LLMClient, Prompt

from benchmark.datasets import Task

GENERATE_PROMPT_VERSION = "generate-v1"
MAX_CODE_CHARS = 60_000

SYSTEM = "You are a Python developer. You always answer with one JSON object and nothing else."

USER_TEMPLATE = """Write Python code for the task below.

--- TASK ---
{problem}
--- END OF TASK ---

Requirements:
- Define a function named `{entry_point}`. It will be imported and called by automated tests.
- Give a complete Python module: the imports it needs, then the code.
- Do not include example usage, tests, a main block, or code that runs when the module is imported.

Answer with this JSON object and nothing else: {{"code": "<the complete Python module>"}}"""


class GeneratedCode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    code: str = Field(min_length=1, max_length=MAX_CODE_CHARS)


def generation_prompt(task: Task) -> Prompt:
    return Prompt(
        id="generate",
        version=GENERATE_PROMPT_VERSION,
        system=SYSTEM,
        user=USER_TEMPLATE.format(problem=task.problem.strip(), entry_point=task.entry_point),
    )


def defines(code: str, name: str) -> bool:
    """Does the module define `name` at the top level? Parsed with ast, never run."""
    tree = ast.parse(code)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                return True
    return False


def code_check(entry_point: str):
    def check(answer: GeneratedCode) -> None:
        try:
            ok = defines(answer.code, entry_point)
        except SyntaxError as exc:
            raise InvalidAnswer(f"the code is not valid Python (line {exc.lineno}: {exc.msg})") from exc
        if not ok:
            raise InvalidAnswer(f"the code does not define a top-level function named `{entry_point}`")

    return check


def generate_sample(task: Task, client: LLMClient) -> dict:
    """One sample record. Raises QuotaExhausted / other LLMError (except InvalidAnswer) to the caller."""
    prompt = generation_prompt(task)
    record = {
        "task_id": task.id,
        "subset": task.subset,
        "cwes": list(task.cwes),
        "entry_point": task.entry_point,
        "provider": client.name,
        "model": client.model,
        "temperature": 0,
        "prompt_version": prompt.version,
        "prompt_system": prompt.system,
        "prompt_user": prompt.user,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        result = client.complete_json(prompt, GeneratedCode, code_check(task.entry_point))
    except InvalidAnswer as exc:
        return {**record, "status": "invalid", "error": str(exc)[:500], "code": None, "model_version": None, "cache_hit": False}
    return {
        **record,
        "status": "ok",
        "error": None,
        "code": result.value.code,
        "model_version": result.model_version,
        "cache_hit": result.cache_hit,
        "requests": result.requests,
    }
