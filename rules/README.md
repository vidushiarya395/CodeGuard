# rules/

Every rule, checklist, map and table CodeGuard uses lives here as YAML, so it can be read and
changed without touching code. Every file is validated when it is loaded; a typo gives a clear
error naming the file. The source for every rule is in `docs/RULE_SOURCES.md`.

| File | What it is |
|------|------------|
| `cwe_groups.yaml` | Narrow CWE groups. Two findings can only be "the same problem" if their CWEs are in the same group. |
| `packages.yaml` | CG-PKG-001 (package does not exist on PyPI) and CG-OSV-001 (pinned version with known vulnerabilities). |
| `import_map.yaml` | Import name to PyPI name (`cv2` to `opencv-python`), so real packages are not reported as missing. |
| `deprecated_apis.yaml` | CG-DEP-001 to CG-DEP-009: deprecated or unsafe functions (`tempfile.mktemp`, `yaml.load`, `eval`, ...). |
| `insecure_settings.yaml` | CG-SET-001 to CG-SET-007: insecure settings (`verify=False`, `debug=True`, ...). |
| `secrets.yaml` | CG-SEC-001 to CG-SEC-003: hard-coded and placeholder secrets, token formats, and the lists that keep false alarms down. |

## Adding a rule

1. Add it to the right YAML file with an `id`, `title`, `cwe`, `message`, `fix_hint` and at
   least one `sources` link (MITRE CWE, official documentation, an RFC/PEP or a paper).
2. Add it, its CWE and its sources to `docs/RULE_SOURCES.md`.
3. Add `backend/tests/examples/rules/<RULE-ID>/vulnerable/<file>` and `.../safe/<file>`.
4. Run the tests. They fail if any of the three steps above is missing.
