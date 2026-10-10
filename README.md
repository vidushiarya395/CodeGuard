# CodeGuard

A web app and command-line tool that checks AI-written Python code for security holes.
CodeGuard only **reads** code; it never runs the code it scans.

> Status: Phase 1. The Standard Scanner (Semgrep + Bandit), the `codeguard scan` CLI, the API
> (`/api/health`, `/api/scan`) and the web app shell are working. Findings are raw scanner
> results; verification, severity and explanations come in later phases.

## Folder layout

| Folder | What is in it |
|--------|---------------|
| `backend/` | Python package `codeguard`: scanners, agents, CLI, API, tests |
| `frontend/` | Web app (React + TypeScript + Vite + Tailwind CSS + shadcn/ui) |
| `rules/` | All rules and tables as YAML (e.g. `cwe_groups.yaml`) |
| `benchmark/` | Research benchmark scripts (later phases) |
| `docs/` | Documentation |

## What you need (all free)

- **Python 3.11 or newer** (`python --version`)
- **Node.js LTS** (`node --version`, v22 or newer)
- Internet the first time Semgrep runs a scan (it downloads the `p/python` rules)

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

## When a scanner is missing or fails

A scan never crashes because a tool is missing. Each scan reports every tool's state:
`ok`, `missing`, `failed` (with the tool's error) or `timeout` (after 120 s by default).
The other tool's findings are still shown.

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
