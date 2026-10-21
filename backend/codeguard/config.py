"""Settings, read from environment variables (and the root .env file).

Every value has a safe default, so the app works without a .env file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# backend/codeguard/config.py -> repository root is two folders up from the package.
REPO_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(REPO_ROOT / ".env", override=False)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Free Semgrep Community rule packs from the Semgrep registry (https://semgrep.dev/explore).
DEFAULT_SEMGREP_CONFIGS = (
    "p/python",
    "p/security-audit",
    "p/owasp-top-ten",
    "p/flask",
    "p/django",
    "p/jwt",
    "p/command-injection",
    "p/sql-injection",
)


def _semgrep_configs() -> tuple[str, ...]:
    """CODEGUARD_SEMGREP_CONFIGS (comma-separated). The older single-pack setting
    CODEGUARD_SEMGREP_CONFIG is still honoured when the new one is not set."""
    raw = os.getenv("CODEGUARD_SEMGREP_CONFIGS", "").strip() or os.getenv("CODEGUARD_SEMGREP_CONFIG", "").strip()
    packs = tuple(dict.fromkeys(p.strip() for p in raw.split(",") if p.strip()))
    return packs or DEFAULT_SEMGREP_CONFIGS


@dataclass(frozen=True)
class Settings:
    rules_dir: Path = field(
        default_factory=lambda: Path(os.getenv("CODEGUARD_RULES_DIR") or REPO_ROOT / "rules")
    )
    # Optional explicit path to the semgrep executable. Empty = auto-detect.
    semgrep_path: str = field(default_factory=lambda: os.getenv("CODEGUARD_SEMGREP_PATH", "").strip())
    # Semgrep rule packs, run together in one Semgrep call.
    semgrep_configs: tuple[str, ...] = field(default_factory=lambda: _semgrep_configs())
    scanner_timeout_s: int = field(default_factory=lambda: _int_env("CODEGUARD_SCANNER_TIMEOUT", 120))
    max_paste_lines: int = field(default_factory=lambda: _int_env("CODEGUARD_MAX_PASTE_LINES", 2000))
    # PyPI and OSV answers are cached here.
    cache_dir: Path = field(default_factory=lambda: Path(os.getenv("CODEGUARD_CACHE_DIR") or REPO_ROOT / ".cache"))
    # Seconds to wait for one PyPI or OSV request.
    net_timeout_s: int = field(default_factory=lambda: _int_env("CODEGUARD_NET_TIMEOUT", 10))
    # True = never call PyPI or OSV; only cached answers are used.
    offline: bool = field(default_factory=lambda: _bool_env("CODEGUARD_OFFLINE"))

    # --- AI provider (see codeguard/llm). Keys have repr=False so they never show up in a printout. ---
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "gemini").strip().lower() or "gemini")
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip(), repr=False)
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "").strip())
    # Gemini requests per day. 0 = the default in codeguard/llm/providers.py (18, just under the free ~20).
    gemini_rpd: int = field(default_factory=lambda: _int_env("GEMINI_RPD", 0))
    groq_api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", "").strip(), repr=False)
    groq_model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL", "").strip())
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "").strip() or "http://localhost:11434"
    )
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "").strip())
    # False = skip the LLM checklist review and the open question (rule checks and scanners still run).
    llm_review: bool = field(default_factory=lambda: _bool_env("CODEGUARD_LLM_REVIEW", True))
    # 0 = use the provider's default free-tier limit (see codeguard/llm/providers.py).
    llm_rpm: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_RPM", 0))
    llm_rpd: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_RPD", 0))
    llm_timeout_s: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_TIMEOUT", 90))
    llm_max_retries: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_MAX_RETRIES", 4))
    # The LLM review looks at no more than this many Python files per scan (free-tier limits).
    llm_max_files: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_MAX_FILES", 20))
    # ...and no more than this many parts of files (a small file is one part; a bigger one is split
    # by function and class). Each part costs two AI requests (checklist + open question).
    llm_max_units: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_MAX_UNITS", 15))
    # Files up to this many lines are reviewed whole; bigger files are split by function and class.
    llm_unit_lines: int = field(default_factory=lambda: _int_env("CODEGUARD_LLM_UNIT_LINES", 150))


def get_settings() -> Settings:
    return Settings()
