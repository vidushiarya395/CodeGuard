"""Run a dataset's own tests against a piece of code, inside Docker only.

This is the only place in CodeGuard where code from a dataset or from an AI model is run, and it is
always run in a throw-away container started with:
  --network none                    no internet, no local network
  --read-only, --tmpfs /tmp         the image cannot be changed; only a small /tmp is writable
  --memory, --cpus, --pids-limit    a runaway test cannot exhaust the laptop
  --cap-drop ALL, no-new-privileges, unprivileged user
  no volume mounts                  the code arrives on stdin, so the container sees none of our files
and a time limit per test suite (inside) plus one for the whole container (outside, then killed).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import subprocess
from dataclasses import dataclass

from benchmark.paths import SANDBOX_DIR

IMAGE_NAME = "codeguard-bench-sandbox"
SUITE_TIMEOUT_S = 10  # per test suite; CodeSecEval's notebook uses 5 s on bare metal
CONTAINER_OVERHEAD_S = 60  # container start-up, on top of the suite time limits
MEMORY = "512m"
PIDS_LIMIT = 128
_IMAGE_FILES = ("Dockerfile", "requirements.txt", "runner.py")


class SandboxError(RuntimeError):
    """Docker itself failed (not the code under test). The result is not saved, so it is retried."""


def image_tag() -> str:
    """The tag changes whenever the image's files change, so an old image is never used by mistake."""
    h = hashlib.sha256()
    for name in _IMAGE_FILES:
        h.update(name.encode() + b"\0" + (SANDBOX_DIR / name).read_bytes() + b"\0")
    return f"{IMAGE_NAME}:{h.hexdigest()[:12]}"


def docker_problem() -> str | None:
    """None if Docker is ready, otherwise what to do about it."""
    if shutil.which("docker") is None:
        return "Docker is not installed. Install Docker Desktop (free for personal and education use)."
    try:
        proc = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "Docker did not answer. Start Docker Desktop and wait until it says it is running."
    if proc.returncode != 0:
        return "Docker is installed but not running. Start Docker Desktop and try again."
    return None


def ensure_image() -> str:
    """Build the sandbox image if it is not there yet. Returns its tag."""
    problem = docker_problem()
    if problem:
        raise SandboxError(problem)
    tag = image_tag()
    have = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=60)
    if have.returncode != 0:
        build = subprocess.run(["docker", "build", "-t", tag, str(SANDBOX_DIR)], timeout=1800)
        if build.returncode != 0:
            raise SandboxError(f"could not build the sandbox image {tag}")
    return tag


def docker_command(tag: str, container_name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "-i",
        "--name", container_name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "--memory", MEMORY, "--memory-swap", MEMORY,
        "--cpus", "1",
        "--pids-limit", str(PIDS_LIMIT),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",
        tag,
    ]  # fmt: skip


@dataclass(frozen=True)
class SuiteResult:
    passed: bool
    stage: str  # load / entry / test / done / timeout / crash
    error_type: str | None = None
    error: str | None = None

    @classmethod
    def from_json(cls, data: dict) -> "SuiteResult":
        return cls(
            passed=bool(data.get("passed")),
            stage=str(data.get("stage", "")),
            error_type=data.get("error_type"),
            error=data.get("error"),
        )

    def to_json(self) -> dict:
        return {"passed": self.passed, "stage": self.stage, "error_type": self.error_type, "error": self.error}


def run_tests(tag: str, code: str, entry_point: str, tests: dict[str, str], timeout_s: int = SUITE_TIMEOUT_S) -> dict[str, SuiteResult]:
    """Run each test suite against `code` in one sandbox container. Raises SandboxError if Docker fails."""
    job = json.dumps({"code": code, "entry_point": entry_point, "tests": tests, "timeout_s": timeout_s})
    name = f"cg-bench-{secrets.token_hex(6)}"
    limit = timeout_s * len(tests) + CONTAINER_OVERHEAD_S
    try:
        proc = subprocess.run(docker_command(tag, name), input=job.encode("utf-8"), capture_output=True, timeout=limit)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=60)
        raise SandboxError(f"the sandbox container did not finish within {limit} s and was stopped") from exc
    lines = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        data = json.loads(lines[-1])
        return {k: SuiteResult.from_json(data[k]) for k in tests}
    except (IndexError, ValueError, KeyError, TypeError) as exc:
        err = proc.stderr.decode("utf-8", "replace").strip()[-300:]
        raise SandboxError(f"the sandbox gave no result (exit code {proc.returncode}): {err}") from exc
