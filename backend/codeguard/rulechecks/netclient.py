"""PyPI and OSV lookups with a disk cache in .cache/.

Only package names and versions are sent: never any code. Answers are cached, so a package is
looked up once and later scans (and scans without internet) reuse the answer.

When the network is down the client raises NetworkDown once and then fails fast for the rest
of the scan, so a scan without internet does not wait for a timeout per package.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from codeguard import __version__

PYPI_URL = "https://pypi.org/pypi/{name}/json"
OSV_URL = "https://api.osv.dev/v1/query"
USER_AGENT = f"CodeGuard/{__version__} (security checker; package existence and advisory lookups)"

DAY = 24 * 3600
TTL_PYPI_EXISTS = 7 * DAY
TTL_PYPI_MISSING = 1 * DAY  # a missing name can be registered at any time, so re-check daily
TTL_OSV = 1 * DAY

_VALID_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$")


class NetworkDown(Exception):
    """The service could not be reached at all (no internet, DNS failure, timeout)."""


class LookupFailed(Exception):
    """The service answered, but not usefully (server error, rate limit, bad JSON)."""


def canonical_name(name: str) -> str:
    """PEP 503 normalization: PyYAML, pyyaml and py-yaml... become one name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_valid_name(name: str) -> bool:
    return bool(_VALID_NAME.match(canonical_name(name)))


class PackageIndex(Protocol):
    def pypi_exists(self, name: str) -> bool: ...

    def osv_vulns(self, name: str, version: str) -> list[dict[str, Any]]: ...


class JsonCache:
    """One small JSON file per answer. File names are hashes, so untrusted names never become paths."""

    def __init__(self, root: Path):
        self.root = root

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
        return self.root / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str) -> tuple[Any, float] | None:
        """Return (value, age in seconds) or None."""
        try:
            data = json.loads(self._path(namespace, key).read_text(encoding="utf-8"))
            if data.get("key") != key:
                return None
            return data["value"], time.time() - float(data["saved_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def put(self, namespace: str, key: str, value: Any) -> None:
        path = self._path(namespace, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps({"key": key, "saved_at": time.time(), "value": value}), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass  # a cache that cannot be written only makes the next scan slower


class HttpPackageIndex:
    def __init__(self, cache_dir: Path, timeout_s: int = 10, offline: bool = False):
        self.cache = JsonCache(cache_dir)
        self.timeout_s = timeout_s
        self.offline = offline
        self._down_reason: str | None = "offline mode is on" if offline else None
        self._lock = threading.Lock()

    @property
    def down_reason(self) -> str | None:
        return self._down_reason

    # --- PyPI ---

    def pypi_exists(self, name: str) -> bool:
        key = canonical_name(name)
        cached = self.cache.get("pypi", key)
        if cached is not None:
            exists, age = cached
            if age < (TTL_PYPI_EXISTS if exists else TTL_PYPI_MISSING):
                return bool(exists)
        url = PYPI_URL.format(name=urllib.parse.quote(key, safe=""))
        try:
            self._request("GET", url)
            exists = True
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise LookupFailed(f"PyPI answered HTTP {exc.code}") from exc
            exists = False
        except NetworkDown:
            if cached is not None:
                return bool(cached[0])  # an old answer is better than none
            raise
        self.cache.put("pypi", key, exists)
        return exists

    # --- OSV ---

    def osv_vulns(self, name: str, version: str) -> list[dict[str, Any]]:
        key = f"{canonical_name(name)}=={version}"
        cached = self.cache.get("osv", key)
        if cached is not None and cached[1] < TTL_OSV:
            return list(cached[0])
        body = {"package": {"name": canonical_name(name), "ecosystem": "PyPI"}, "version": version}
        try:
            raw = self._request("POST", OSV_URL, body)
        except urllib.error.HTTPError as exc:
            raise LookupFailed(f"OSV answered HTTP {exc.code}") from exc
        except NetworkDown:
            if cached is not None:
                return list(cached[0])  # an old answer is better than none
            raise
        try:
            vulns = json.loads(raw).get("vulns") or []
        except (ValueError, AttributeError) as exc:
            raise LookupFailed("OSV returned something that is not JSON") from exc
        # Keep only what the report needs, so the cache stays small.
        slim = [
            {
                "id": str(v.get("id", "")),
                "summary": str(v.get("summary") or "")[:200],
                "aliases": [str(a) for a in (v.get("aliases") or [])][:5],
            }
            for v in vulns
            if isinstance(v, dict) and v.get("id")
        ]
        self.cache.put("osv", key, slim)
        return slim

    # --- HTTP ---

    def _request(self, method: str, url: str, body: dict | None = None) -> bytes:
        if self._down_reason:
            raise NetworkDown(self._down_reason)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return resp.read(5_000_000)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            with self._lock:
                if not self._down_reason:
                    self._down_reason = f"could not reach {urllib.parse.urlsplit(url).netloc} ({reason})"
            raise NetworkDown(self._down_reason) from exc
