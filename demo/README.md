# Demo suite

Ten small Python apps in the style AI assistants typically write, for showing CodeGuard live.
They were written for CodeGuard and are not taken from CodeSecEval or CWEval. **These are demo
results, not research results**: the apps and their expected lists were written by the same
person, and the findings are raw (no Verifier yet). Research numbers come from `benchmark/` only.

| App | What it is |
|-----|-----------|
| `flask_blog` | Flask blog with accounts (Flask-Login, SQLAlchemy) |
| `fastapi_todo` | FastAPI todo API with no accounts |
| `django_notes` | Django notes app: function views, `urls.py`, `settings.py` |
| `drf_shop` | Django REST framework view sets, serializers, django-cors-headers |
| `upload_service` | Flask file sharing: upload, download, delete |
| `backup_cli` | Command-line backup tool (argparse, subprocess, YAML) |
| `price_scraper` | requests + BeautifulSoup CLI scraper with a Flask preview server |
| `jwt_api` | Flask API with JWT tokens and a `token_required` decorator |
| `pastebin` | Flask pastebin with sqlite3, Flask-WTF and a preferences cookie |
| `inventory_api` | FastAPI app written carefully: mostly here to show what must stay quiet |

Each app has an `expected.yaml`:

- `vulnerabilities`: the real problems (file, line, CWE, and what is wrong). `also_cwe` lists
  other CWE labels tools commonly use for the same problem (e.g. MD5 passwords: CWE-916, often
  reported as CWE-327).
- `quiet`: lines where a finding of that CWE would be a false alarm, with the reason.

## Run it

From the repository root, in PowerShell:

```powershell
.\.venv\Scripts\python.exe demo\run_demo.py                 # no AI review (uses no AI quota)
.\.venv\Scripts\python.exe demo\run_demo.py --llm           # also the AI review (provider from .env)
.\.venv\Scripts\python.exe demo\run_demo.py --app flask_blog --show-extra
.\.venv\Scripts\python.exe demo\run_demo.py --json demo-results.json
```

For each app it prints **found** (an expected problem with a finding in the same file, within 2
lines, in the same CWE group), **missed**, **extra** (findings that match no expected problem;
many are Semgrep or Bandit using another CWE label for the same issue) and **noise** (an extra
finding on a line that must stay quiet). The apps are only read, never run.
