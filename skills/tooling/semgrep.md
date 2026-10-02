---
name: semgrep
description: Exact Semgrep CLI structure, metrics-off scanning, scoped ruleset selection, and automation-safe output patterns for whitebox source code analysis in CTF/HTB engagements.
kali_tools: [semgrep]
time:
  quick: 1–5m (p/default, scoped directory, quiet)
  standard: 5–20m (p/default + language packs, full workspace)
  deep: 20–60m (p/owasp-top-ten + p/secrets + language packs, pro engine if available)
github_fallbacks:
  semgrep: returntocorp/semgrep
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "semgrep rule packs that found sinks in similar stacks"
- "semgrep findings confirmed exploitable HTB"
- "semgrep false positive patterns to filter"
- "whitebox source code language stack identifiers"

## Viability Gate

| Budget | Mode |
|--------|------|
| < 10m  | `semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet --jobs 4 --timeout 20 /workspace` |
| 10m–1h | Add language/framework packs matching the stack; use `--severity ERROR` to focus on high-confidence sinks first |
| 1h+    | `p/owasp-top-ten` + `p/secrets` + stack-specific packs; try `--pro` if available; sweep sub-directories individually for deeper focus |

## Quick Reference

```bash
# Agent-safe baseline
semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet --jobs 4 --timeout 20 /workspace

# High-severity focused pass
semgrep scan --config p/default --severity ERROR --metrics=off --json --output semgrep_high.json --quiet /workspace

# OWASP-oriented scan
semgrep scan --config p/owasp-top-ten --metrics=off --sarif --output semgrep.sarif --quiet /workspace

# Language/framework-specific rules
semgrep scan --config p/python --config p/secrets --metrics=off --json --output semgrep_python.json --quiet /workspace

# Scoped directory scan
semgrep scan --config p/default --metrics=off --json --output semgrep_api.json --quiet /workspace/services/api
```

# Semgrep CLI Playbook

Official docs:
- https://semgrep.dev/docs/cli-reference
- https://semgrep.dev/docs/getting-started/cli
- https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro

Canonical syntax:
`semgrep scan [flags]`

High-signal flags:
- `--config <rule_or_ruleset>` ruleset, registry pack, local rule file, or directory
- `--metrics=off` disable telemetry and metrics reporting
- `--json` JSON output
- `--sarif` SARIF output
- `--output <file>` write findings to file
- `--severity <level>` filter by severity
- `--error` return non-zero exit when findings exist
- `--quiet` suppress progress noise
- `--jobs <n>` parallel workers
- `--timeout <seconds>` per-file timeout
- `--exclude <pattern>` exclude path pattern
- `--include <pattern>` include path pattern
- `--exclude-rule <rule_id>` suppress specific rule
- `--baseline-commit <sha>` only report findings introduced after baseline
- `--pro` enable Pro engine if available
- `--oss-only` force OSS engine only

Agent-safe baseline for automation:
`semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet --jobs 4 --timeout 20 /workspace`

Common patterns:
- Default security scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet /workspace`
- High-severity focused pass:
  `semgrep scan --config p/default --severity ERROR --metrics=off --json --output semgrep_high.json --quiet /workspace`
- OWASP-oriented scan:
  `semgrep scan --config p/owasp-top-ten --metrics=off --sarif --output semgrep.sarif --quiet /workspace`
- Language- or framework-specific rules:
  `semgrep scan --config p/python --config p/secrets --metrics=off --json --output semgrep_python.json --quiet /workspace`
- Scoped directory scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep_api.json --quiet /workspace/services/api`
- Pro engine check or run:
  `semgrep scan --config p/default --pro --metrics=off --json --output semgrep_pro.json --quiet /workspace`

Critical correctness rules:
- Always include `--metrics=off`; Semgrep sends telemetry by default.
- Always provide an explicit `--config`; do not rely on vague or implied defaults.
- Prefer `--json --output <file>` or `--sarif --output <file>` for machine-readable downstream processing.
- Keep the target path explicit; use an absolute or clearly scoped workspace path instead of `.` when possible.
- If Pro availability matters, check it explicitly with a bounded command before assuming cross-file analysis exists.

Usage rules:
- Start with `p/default` unless the task clearly calls for a narrower pack.
- Add focused packs such as `p/secrets`, `p/python`, or `p/javascript` only when they match the target stack.
- Use `--quiet` in automation to reduce noisy logs.
- Use `--jobs` and `--timeout` explicitly for reproducible runtime behavior.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If scans are too slow, narrow the target path and reduce the active rulesets before changing engine settings.
- If scans time out, increase `--timeout` modestly or lower `--jobs`.
- If output is too broad, scope `--config`, add `--severity`, or exclude known irrelevant paths.
- If Pro mode fails, rerun with `--oss-only` or without `--pro` and note the loss of cross-file coverage.

If uncertain, query web_search with:
`site:semgrep.dev semgrep <flag> cli`

## After You Finish (Memory)

Call `memory_record_task_outcome` recording:
- Which rule packs produced confirmed exploitable findings vs. false positives
- The language/framework stack and which config was most relevant
- Any rule IDs worth suppressing via `--exclude-rule` on similar future targets
- Whether Pro engine added meaningful cross-file findings beyond OSS mode
