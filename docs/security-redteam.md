# Security red-team suite

`tests/redteam/` runs adversarial inputs against the real defences on every `pytest` run.

| Surface | Corpus | Result |
|---|---|---|
| SQL connector (`SQLSafetyValidator`) | 32 malicious payloads (DDL/DML, stacked queries, comment tricks, allowlist bypass via aliases / comma joins / subqueries / CTEs / schema qualification, file and sleep functions) | all rejected |
| SQL connector, legitimate queries | 6 queries incl. joins, aliases, CTE chains | all accepted and row-bounded |
| Prompt-injection detector | 7 attack prompts | all blocked |
| Prompt-injection detector, benign | 6 prompts | none blocked |
| PII sanitiser | email, SSN, Luhn-valid card, API key in nested output | none survive |

## Findings fixed while building the suite

- `SELECT * FROM secrets AS s` bypassed the table allowlist: any word followed by `AS` was treated as a CTE name. CTE names are now only recognised in `WITH name AS (` / `, name AS (` position.
- Comma joins (`FROM orders, secrets`) were not checked beyond the first table. All comma-separated tables are now extracted.
- File-read, sleep and blob-allocation functions (`pg_read_file`, `sleep`, `benchmark`, `readfile`, `randomblob`, ...) were not denied.

## Known gaps (tracked as strict `xfail`)

The prompt-injection detector is a heuristic pattern matcher. It misses persona jailbreaks ("You are now DAN"), leetspeak obfuscation, "forget everything above", markdown-header instructions and translate-then-ignore wrappers (5 of 12 attack prompts in the combined corpus). Treat it as one layer: ingress guardrails do not replace tool-level RBAC, the SQL validator, and output redaction. When the detector is improved, the matching `xfail` flips to a failure so this list is updated deliberately.
