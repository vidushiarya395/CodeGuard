# rules/

Every rule, checklist, map and table CodeGuard uses lives here as YAML, so it can be read and
changed without touching code.

| File | What it is |
|------|------------|
| `cwe_groups.yaml` | Narrow CWE groups. Two findings can only be "the same problem" if their CWEs are in the same group. |

More files are added in later phases. Sources for every rule will be listed in `docs/RULE_SOURCES.md`.
