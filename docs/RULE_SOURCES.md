# Rule sources

Every rule CodeGuard's rule checks use (Agent 2, no AI), with its CWE and the published source
it is based on. Each source is a MITRE CWE page, official documentation, a standard (RFC / PEP)
or a peer-reviewed paper. No rule exists without a source.

The rules themselves live in `rules/*.yaml`; this file is kept in sync by a test
(`backend/tests/test_rule_files.py`), which fails if a rule, its CWE or one of its sources is
missing here. Every rule also has one vulnerable and one safe example file in
`backend/tests/examples/rules/<RULE-ID>/`, which the tests scan
(`backend/tests/test_rule_examples.py`).

CWE groups (which CWEs count as the "same problem") are in `rules/cwe_groups.yaml`; every CWE
ID there links to `https://cwe.mitre.org/data/definitions/<id>.html`.

## Packages (`rules/packages.yaml`)

| Rule | What it catches | CWE | Sources |
|------|-----------------|-----|---------|
| CG-PKG-001 | An imported package, a `requirements*.txt` entry or a `pip install` name that does not exist on PyPI ("hallucinated" package; an attacker could register the name) | CWE-829 | MITRE CWE-829: https://cwe.mitre.org/data/definitions/829.html <br> Spracklen et al., "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs", USENIX Security 2025: https://arxiv.org/abs/2406.10279 <br> PyPI JSON API (404 = no such project): https://docs.pypi.org/api/json/ |
| CG-OSV-001 | A pinned version (`name==1.2.3`) with publicly known vulnerabilities | CWE-1395 | MITRE CWE-1395: https://cwe.mitre.org/data/definitions/1395.html <br> OSV API, `POST /v1/query`: https://google.github.io/osv.dev/post-v1-query/ <br> OWASP Top 10 2021, A06 Vulnerable and Outdated Components: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/ |

`rules/import_map.yaml` (import name → PyPI name, e.g. `cv2` → `opencv-python`) is a lookup
table, not a rule. Each entry can be checked on the project's PyPI page,
`https://pypi.org/project/<name>/`. Name comparison follows PEP 503 normalization:
https://peps.python.org/pep-0503/#normalized-names

## Deprecated or unsafe functions (`rules/deprecated_apis.yaml`)

| Rule | What it catches | CWE | Sources |
|------|-----------------|-----|---------|
| CG-DEP-001 | `tempfile.mktemp()` (race between choosing and creating the file) | CWE-377 | Python docs: https://docs.python.org/3/library/tempfile.html#tempfile.mktemp <br> MITRE CWE-377: https://cwe.mitre.org/data/definitions/377.html |
| CG-DEP-002 | `ssl.wrap_socket()` (deprecated 3.7, removed 3.12; no certificate or host name check by default) | CWE-295 | Python 3.11 docs: https://docs.python.org/3.11/library/ssl.html#ssl.wrap_socket <br> What's new in Python 3.12: https://docs.python.org/3/whatsnew/3.12.html#ssl <br> MITRE CWE-295: https://cwe.mitre.org/data/definitions/295.html |
| CG-DEP-003 | `ssl.PROTOCOL_SSLv2`, `PROTOCOL_SSLv3`, `PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1` | CWE-327 | Python docs: https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLSv1 <br> RFC 8996, Deprecating TLS 1.0 and TLS 1.1: https://www.rfc-editor.org/rfc/rfc8996 <br> MITRE CWE-327: https://cwe.mitre.org/data/definitions/327.html |
| CG-DEP-004 | `yaml.load()` / `yaml.load_all()` without a safe loader, `yaml.unsafe_load()` | CWE-502 | PyYAML, yaml.load(input) deprecation: https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation <br> MITRE CWE-502: https://cwe.mitre.org/data/definitions/502.html |
| CG-DEP-005 | `cgi.escape()` (does not escape quotes; removed in 3.8) | CWE-79 | Python 3.7 docs: https://docs.python.org/3.7/library/cgi.html#cgi.escape <br> What's new in Python 3.8: https://docs.python.org/3/whatsnew/3.8.html#api-and-feature-removals <br> MITRE CWE-79: https://cwe.mitre.org/data/definitions/79.html |
| CG-DEP-006 | `import telnetlib` (cleartext protocol; removed in 3.13) | CWE-319 | PEP 594: https://peps.python.org/pep-0594/#telnetlib <br> MITRE CWE-319: https://cwe.mitre.org/data/definitions/319.html |
| CG-DEP-007 | `eval()` / `exec()` on anything that is not a plain constant | CWE-95 | Python docs, eval: https://docs.python.org/3/library/functions.html#eval <br> Python docs, ast.literal_eval: https://docs.python.org/3/library/ast.html#ast.literal_eval <br> MITRE CWE-95: https://cwe.mitre.org/data/definitions/95.html |
| CG-DEP-008 | `tarfile` `extractall()` / `extract()` without `filter=` | CWE-22 | Python docs, extraction filters: https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter <br> PEP 706: https://peps.python.org/pep-0706/ <br> MITRE CWE-22: https://cwe.mitre.org/data/definitions/22.html |
| CG-DEP-009 | ECB cipher mode (PyCryptodome `MODE_ECB`, cryptography `modes.ECB`) | CWE-327 | cryptography docs (ECB warning): https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.ECB <br> PyCryptodome docs, ECB mode: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode <br> MITRE CWE-327: https://cwe.mitre.org/data/definitions/327.html |

## Insecure settings (`rules/insecure_settings.yaml`)

| Rule | What it catches | CWE | Sources |
|------|-----------------|-----|---------|
| CG-SET-001 | `verify=False` in requests / httpx, `session.verify = False`, `ssl=False` / `verify_ssl=False` in aiohttp, `cert_reqs="CERT_NONE"` in urllib3 | CWE-295 | Requests docs: https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification <br> HTTPX docs: https://www.python-httpx.org/advanced/ssl/ <br> aiohttp docs: https://docs.aiohttp.org/en/stable/client_advanced.html#ssl-control-for-tcp-sockets <br> urllib3 docs: https://urllib3.readthedocs.io/en/stable/advanced-usage.html#certificate-verification <br> MITRE CWE-295: https://cwe.mitre.org/data/definitions/295.html |
| CG-SET-002 | `ssl._create_unverified_context`, `check_hostname = False`, `verify_mode = ssl.CERT_NONE` | CWE-295 | PEP 476: https://peps.python.org/pep-0476/ <br> Python docs, check_hostname: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname <br> Python docs, CERT_NONE: https://docs.python.org/3/library/ssl.html#ssl.CERT_NONE <br> MITRE CWE-295: https://cwe.mitre.org/data/definitions/295.html |
| CG-SET-003 | Flask debug mode: `app.run(debug=True)`, `app.debug = True`, `app.config["DEBUG"] = True` | CWE-489 | Flask docs, debugging: https://flask.palletsprojects.com/en/stable/debugging/ <br> Flask quickstart, debug mode: https://flask.palletsprojects.com/en/stable/quickstart/#debug-mode <br> MITRE CWE-489: https://cwe.mitre.org/data/definitions/489.html |
| CG-SET-004 | `DEBUG = True` in a Django settings file | CWE-489 | Django settings, DEBUG: https://docs.djangoproject.com/en/stable/ref/settings/#debug <br> Django deployment checklist: https://docs.djangoproject.com/en/stable/howto/deployment/checklist/#debug <br> MITRE CWE-489: https://cwe.mitre.org/data/definitions/489.html |
| CG-SET-005 | JWT decoded without signature check (`options={"verify_signature": False}`, `verify=False`) | CWE-347 | PyJWT docs: https://pyjwt.readthedocs.io/en/stable/usage.html#reading-the-claimset-without-validation <br> RFC 8725, JWT Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725#section-3.1 <br> MITRE CWE-347: https://cwe.mitre.org/data/definitions/347.html |
| CG-SET-006 | Paramiko `AutoAddPolicy` / `WarningPolicy` (accepts unknown SSH host keys) | CWE-295 | Paramiko docs: https://docs.paramiko.org/en/stable/api/client.html#paramiko.client.AutoAddPolicy <br> MITRE CWE-295: https://cwe.mitre.org/data/definitions/295.html |
| CG-SET-007 | Jinja2 `autoescape=False` | CWE-79 | Jinja docs, autoescaping: https://jinja.palletsprojects.com/en/stable/api/#autoescaping <br> MITRE CWE-79: https://cwe.mitre.org/data/definitions/79.html |

## Secrets (`rules/secrets.yaml`)

| Rule | What it catches | CWE | Sources |
|------|-----------------|-----|---------|
| CG-SEC-001 | Text in a known secret-token format, anywhere in the file (see the token formats below) | CWE-798 | MITRE CWE-798: https://cwe.mitre.org/data/definitions/798.html <br> OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |
| CG-SEC-002 | A string constant stored under a secret-like name (variable, attribute, config key, dict key, keyword argument), compared with one (`password == "..."`), or used as an `os.getenv` fallback | CWE-798 | MITRE CWE-798: https://cwe.mitre.org/data/definitions/798.html <br> MITRE CWE-259 (hard-coded password): https://cwe.mitre.org/data/definitions/259.html <br> OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |
| CG-SEC-003 | The same places, holding a placeholder or guessable default (`"your-api-key-here"`, `"changeme"`, `os.getenv("SECRET_KEY", "dev")`) | CWE-798 | MITRE CWE-798: https://cwe.mitre.org/data/definitions/798.html <br> MITRE CWE-1392 (use of default credentials): https://cwe.mitre.org/data/definitions/1392.html <br> OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |

### Token formats used by CG-SEC-001

| Token format | Source for the format |
|--------------|-----------------------|
| AWS access key ID | AWS IAM docs, unique ID prefixes (`AKIA`, `ASIA`): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids |
| GitHub token | GitHub docs, token formats (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`): https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats <br> GitHub engineering blog: https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/ |
| GitHub fine-grained token | GitHub docs, token formats (`github_pat_`): https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats |
| Slack token | Slack docs, token types (`xoxb-`, `xoxp-`, ...): https://api.slack.com/authentication/token-types |
| Stripe live secret key | Stripe docs, API keys (`sk_live_`, `rk_live_`): https://docs.stripe.com/keys |
| Google API key | Gitleaks default rule set (`AIza` prefix, 39 characters): https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml |
| Private key (PEM) | RFC 7468, textual encoding of private keys: https://www.rfc-editor.org/rfc/rfc7468#section-10 and https://www.rfc-editor.org/rfc/rfc7468#section-11 |

### How the secret checks avoid false alarms

These choices are written down so they can be questioned and tested:

- Names are matched on whole word parts (`api_key`, `client_secret`, `access_token`), so
  `tokenizer`, `keyboard` or `max_tokens` never count.
- Names that describe a secret rather than hold one are skipped by their last part
  (`password_field`, `token_url`, `API_KEY_ENV`). Names of language-model tokenizer settings
  are skipped by their first part (`eos_token`, `pad_token`).
- Values that are environment-variable names (`"OPENAI_API_KEY"`), format templates
  (`"Bearer {}"`), sentences, file paths or shorter than 4 characters are not reported as
  hard-coded secrets. Neither are booleans written as text (`"true"`), redaction masks
  (`"********"`), regular expressions, or a label equal to its own name (`apiKey = "apiKey"`).
- Comparisons (`x == "..."`) are only checked for password-like names, because parsers compare
  generic names such as `token` with strings all the time.
- Secret values are masked in every report (`Tr0u********`).

These exceptions were found by running the rule checks over 23 widely used open-source
libraries (requests, Flask, FastAPI, pydantic, pygments, ...) and reading every finding. Each
false alarm found that way has a regression test in `backend/tests/test_secrets.py` or
`backend/tests/test_packages.py`.
