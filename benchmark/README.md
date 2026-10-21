# benchmark/

Scripts that download the public datasets, generate code samples, label them, run every tool
and compute the results for the research paper. They import the same `codeguard` package the
app uses.

Downloaded data goes in `benchmark/external/` and run output in `benchmark/runs/`; neither is
committed. The fixed calibration / test split is in `benchmark/splits/` and is committed.

## Pilot (Phase 4): CodeSecEval, calibration split only

```powershell
.\.venv\Scripts\Activate.ps1
python -m benchmark.pilot run       # every step, in order
python -m benchmark.pilot status    # how far it has got
python -m pytest benchmark/tests    # the benchmark's own tests (no Docker, no AI calls)
```

Needs Docker Desktop running. The AI provider is the one in `.env` (`LLM_PROVIDER`); it both
generates the samples and does the LLM review. Output goes to
`benchmark/runs/pilot-codeseceval/<provider>-<model>/`, so runs with different models never mix.

| Step | What it does |
|---|---|
| `download` | CodeSecEval from Hugging Face at a pinned commit; SHA-256 of every file checked |
| `split` | 20 % calibration / 80 % test, seed 42, written once to `splits/codeseceval.json` |
| `refcheck` | runs each task's secure and insecure reference solutions in the sandbox; a task is used only if the secure one passes both test suites and the insecure one fails the security suite |
| `generate` | one sample per usable task, temperature 0, neutral prompt; prompt, model, version and date saved |
| `label` | runs the dataset's `Test-FP` and `Test-SP` on each sample in the sandbox: vulnerable / safe / not functional (left out) |
| `scan` | scans each labelled sample with CodeGuard (Semgrep, Bandit, rule checks, LLM review) |
| `evaluate` | writes `metrics.csv`, `metrics_by_group.csv`, `per_sample.csv` and `run.json` |

Every step saves one file per task and skips what is done. When a free daily AI limit is reached,
the step stops with exit code 3; run the same command the next day and it carries on.

When `evaluate` scores a saved scan, each finding's CWE group is looked up again from its CWE in
today's `rules/cwe_groups.yaml` (the same way for every tool), so a result never depends on the
day the scan was made.

### Re-scanning the same samples (Phase 4.5)

A tag keeps a second set of scans and results next to the original ones. Samples and labels are
shared, so both runs score exactly the same samples with the same labels.

```powershell
$env:LLM_PROVIDER = "groq"   # the same reviewer as the original pilot run
python -m benchmark.pilot --tag v2 scan       # scans-v2/
python -m benchmark.pilot --tag v2 evaluate   # metrics-v2.csv, per_sample-v2.csv, run-v2.json, ...
python -m benchmark.pilot compare --new v2    # original next to v2, per-group flag counts, scan times
```

`compare` refuses to run if the two runs score different samples or labels. It also re-scores the
original run and checks it reproduces the saved `metrics.csv`. It writes
`compare-original-vs-v2-*.csv`. Its numbers are measured on the same calibration samples that
motivated the changes, so they are a calibration check, not a test-split result.

## Sandbox

`sandbox/` builds a Docker image (Python 3.11 plus pinned packages the tasks import). Each test
run is a new container with no network, a read-only file system, memory / CPU / process limits,
all capabilities dropped, an unprivileged user, and no mounted folders: the code arrives on stdin.
Code from the dataset or from an AI model is never run anywhere else.
