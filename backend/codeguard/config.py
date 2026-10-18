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


@dataclass(frozen=True)
class Settings:
    rules_dir: Path = field(
        default_factory=lambda: Path(os.getenv("CODEGUARD_RULES_DIR") or REPO_ROOT / "rules")
    )
    # Optional explicit path to the semgrep executable. Empty = auto-detect.
    semgrep_path: str = field(default_factory=lambda: os.getenv("CODEGUARD_SEMGREP_PATH", "").strip())
    semgrep_config: str = field(
        default_factory=lambda: os.getenv("CODEGUARD_SEMGREP_CONFIG", "p/python").strip() or "p/python"
    )
    scanner_timeout_s: int = field(default_factory=lambda: _int_env("CODEGUARD_SCANNER_TIMEOUT", 120))
    max_paste_lines: int = field(default_factory=lambda: _int_env("CODEGUARD_MAX_PASTE_LINES", 2000))
    # PyPI and OSV answers are cached here.
    cache_dir: Path = field(default_factory=lambda: Path(os.getenv("CODEGUARD_CACHE_DIR") or REPO_ROOT / ".cache"))
    # Seconds to wait for one PyPI or OSV request.
    net_timeout_s: int = field(default_factory=lambda: _int_env("CODEGUARD_NET_TIMEOUT", 10))
    # True = never call PyPI or OSV; only cached answers are used.
    offline: bool = field(default_factory=lambda: _bool_env("CODEGUARD_OFFLINE"))


def get_settings() -> Settings:
    return Settings()
