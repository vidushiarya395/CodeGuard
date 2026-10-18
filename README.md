# CodeGuard

A web app and command-line tool that checks AI-written Python code for security holes.
CodeGuard only **reads** code; it never runs the code it scans.

> Status: Phase 2. The Standard Scanner (Semgrep + Bandit), the rule checks of the AI-Mistake
> Finder (hallucinated packages, known-vulnerable versions, deprecated/unsafe functions,
> hard-coded secrets, insecure settings), the `codeguard scan` CLI, the API (`/api/health`,
> `/api/scan`) and the web app shell are working. Findings are raw results; verification,
> severity and explanations come in later phases.

## Folder layout

| Folder | What is in it |
|--------|---------------|
| `backend/` | Python package `codeguard`: scanners, agents, CLI, API, tests |
| `frontend/` | Web app (React + TypeScript + Vite + Tailwind CSS + shadcn/ui) |
| `rules/` | All rules and tables as YAML (see `rules/README.md`) |
| `benchmark/` | Research benchmark scripts (later phases) |
| `docs/` | Documentation, including `RULE_SOURCES.md` (the source for every rule) |

## What you need (all free)

- **Python 3.11 or newer** (`python --version`)
- **Node.js LTS** (`node --version`, v22 or newer)
- Internet the first time Semgrep runs a scan (it downloads the `p/python` rules), and for the
  package checks (PyPI and OSV). Without internet those checks are marked `skipped`; everything
  else still runs.

## One-time setup (Windows PowerShell)

Run these from the repository root (the folder with this README).

```powershell
# 1. Python environment for the app
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e "backend[dev]"

# 2. Semgrep in its own environment
#    (Semgrep needs older versions of some libraries than FastAPI does, so they can't share .venv)
python -m venv .venv-semgrep
.\.venv-semgrep\Scripts\python -m pip install --upgrade pip
.\.venv-semgrep\Scripts\python -m pip install --only-binary=semgrep semgrep==1.179.0

# 3. Settings (optional; every value has a default)
Copy-Item .env.example .env

# 4. Frontend
cd frontend
npm install
cd ..
```

If `python` points to an Anaconda install that is older than 3.11, use the full path to a newer
Python for steps 1 and 2 (for example `C:\Python313\python.exe -m venv .venv`).

Bandit is installed automatically in step 1 because it is a dependency of `codeguard`.
CodeGuard finds Semgrep in `.venv-semgrep` by itself. To use a different Semgrep, set
`CODEGUARD_SEMGREP_PATH` in `.env`.

## Run it

Use two PowerShell windows, both opened in the repository root.

**Window 1: API** (http://127.0.0.1:8100)

```powershell
.\.venv\Scripts\python -m uvicorn codeguard.api:app --host 127.0.0.1 --port 8100 --reload
```

**Window 2: web app** (http://127.0.0.1:5180)

```powershell
cd frontend
npm run dev
```

CodeGuard uses ports 8100 and 5180 instead of the common 8000 and 5173, so it does not clash with
other local projects. The web app forwards `/api/...` calls to the API.

**Command line**

```powershell
.\.venv\Scripts\codeguard scan backend\tests\examples\vulnerable
.\.venv\Scripts\codeguard scan some_file.py --json
.\.venv\Scripts\codeguard scan some_folder --offline   # never contact PyPI / OSV
```

Activating the environment first (`.\.venv\Scripts\Activate.ps1`) lets you type just `codeguard`.
If PowerShell blocks the activate script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

## Tests

```powershell
cd backend
..\.venv\Scripts\python -m pytest
cd ..\frontend
npm run build
```

Tests marked `integration` run the real Semgrep and Bandit. They are skipped when a tool is not
installed, and the Semgrep one needs internet. To run only the offline tests:
`..\.venv\Scripts\python -m pytest -m "not integration"`.

## API

| Method | Path | What it does |
|--------|------|--------------|
| GET | `/api/health` | `{"status": "ok", "version": "..."}` |
| POST | `/api/scan` | Body `{"code": "...", "filename": "app.py"}` (filename optional). Returns the findings and the status of each scanner. Code over 2,000 lines is rejected with HTTP 422. |

Interactive API docs: http://127.0.0.1:8100/docs

## Rule checks (no AI)

Besides Semgrep and Bandit, every scan runs five rule checks. Each one appears as its own row
in the scan output:

| Check | What it finds | Rules |
|-------|---------------|-------|
| `rule:packages` | Imported or listed packages that do not exist on PyPI (invented by an AI tool) | CG-PKG-001 |
| `rule:vulnerable-versions` | Pinned versions (`name==1.2.3`) with known vulnerabilities in OSV | CG-OSV-001 |
| `rule:deprecated-apis` | Deprecated or unsafe functions | CG-DEP-001 to 009 |
| `rule:secrets` | Hard-coded and placeholder secrets (values are masked in the report) | CG-SEC-001 to 003 |
| `rule:insecure-settings` | `verify=False`, `debug=True` and similar | CG-SET-001 to 007 |

All rules are YAML files in `rules/`; their sources are in `docs/RULE_SOURCES.md`.
The package checks send only package names and versions to PyPI and OSV, never code. Answers
are cached in `.cache/` (a day to a week), so repeated scans are fast and work offline.

## When a scanner is missing or fails

A scan never crashes because a tool is missing. Each scan reports every tool's state:
`ok`, `missing`, `failed` (with the tool's error), `timeout` (after 120 s by default) or
`skipped` (PyPI / OSV could not be reached, or `--offline`). The other tools' findings are
still shown.

### If Semgrep does not work on Windows (free WSL option)

Semgrep's native Windows support is still in beta. If it fails on your laptop, run it inside
WSL (Windows Subsystem for Linux), which is free:

1. In an **administrator** PowerShell: `wsl --install` and restart when asked (installs Ubuntu).
2. Open Ubuntu and run:
   ```bash
   sudo apt update && sudo apt install -y python3-venv
   python3 -m venv ~/semgrep-venv
   ~/semgrep-venv/bin/pip install semgrep
   ```
3. Run CodeGuard from inside Ubuntu too (clone or open the repo there, then follow the setup above
   with Linux paths, e.g. `.venv/bin/python`), and set `CODEGUARD_SEMGREP_PATH=/home/<you>/semgrep-venv/bin/semgrep`
   in `.env`.
