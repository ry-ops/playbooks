---
name: nuclei
description: Exact Nuclei command structure, template selection, and bounded high-throughput execution controls for CTF/HTB vulnerability scanning.
kali_tools: [nuclei, httpx, subfinder]
time:
  quick: 1–3m (critical/high severity, auto-scan)
  standard: 5–15m (full severity range, tag-driven)
  deep: 15–60m (explicit template directories, all severities)
github_fallbacks:
  nuclei: projectdiscovery/nuclei
  nuclei-templates: projectdiscovery/nuclei-templates
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "nuclei template tags HTB findings"
- "nuclei CVE templates that fired on boxes"
- "nuclei false positive misconfig patterns"
- "nuclei OAST interactsh HTB restrictions"

## Viability Gate

| Budget | Mode |
|--------|------|
| < 10m  | `nuclei -u <url> -s critical,high -as -ni -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -silent -j -o nuclei_quick.jsonl` |
| 10m–1h | `nuclei -l targets.txt -as -s critical,high,medium -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o nuclei.jsonl` |
| 1h+    | `nuclei -l targets.txt -tags cve,misconfig,exposure,default-login -s critical,high,medium,low -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_deep.jsonl` |

## Quick Reference

```bash
# Agent-safe baseline
nuclei -l targets.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o nuclei.jsonl

# No OAST (when outbound callbacks aren't allowed)
nuclei -l targets.txt -as -s critical,high -ni -stats -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_no_oast.jsonl

# Tag-driven run
nuclei -l targets.txt -tags cve,misconfig -s critical,high,medium -silent

# Explicit templates
nuclei -l targets.txt -t http/cves/ -t dns/ -rl 30 -c 10 -bs 10 -j -o nuclei_templates.jsonl
```

# Nuclei CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli
- https://github.com/projectdiscovery/nuclei

Canonical syntax:
`nuclei [flags]`

High-signal flags:
- `-u, -target <url>` single target
- `-l, -list <file>` targets file
- `-im, -input-mode <mode>` list/burp/jsonl/yaml/openapi/swagger
- `-t, -templates <path|tag>` explicit template path(s)
- `-tags <tag1,tag2>` run by tag
- `-s, -severity <critical,high,...>` severity filter
- `-as, -automatic-scan` tech-mapped automatic scan
- `-ni, -no-interactsh` disable OAST/interactsh requests
- `-rl, -rate-limit <n>` global request rate cap
- `-c, -concurrency <n>` template concurrency
- `-bs, -bulk-size <n>` hosts in parallel per template
- `-timeout <seconds>` request timeout
- `-retries <n>` retries
- `-stats` periodic scan stats output
- `-silent` findings-only output
- `-j, -jsonl` JSONL output
- `-o <file>` output file

Agent-safe baseline for automation:
`nuclei -l targets.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o nuclei.jsonl`

Common patterns:
- Focused severity scan:
  `nuclei -u https://target.tld -s critical,high -silent -o nuclei_high.txt`
- List-driven controlled scan:
  `nuclei -l targets.txt -as -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl`
- Tag-driven run:
  `nuclei -l targets.txt -tags cve,misconfig -s critical,high,medium -silent`
- Explicit templates:
  `nuclei -l targets.txt -t http/cves/ -t dns/ -rl 30 -c 10 -bs 10 -j -o nuclei_templates.jsonl`
- Deterministic non-OAST run:
  `nuclei -l targets.txt -as -s critical,high -ni -stats -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_no_oast.jsonl`

Critical correctness rules:
- Provide a template selection method (`-as`, `-t`, or `-tags`); avoid unscoped broad runs.
- Keep `-rl`, `-c`, and `-bs` explicit for predictable resource use.
- Use `-ni` when outbound interactsh/OAST traffic is not expected or not allowed.
- Use structured output (`-j -o <file>`) for automation.

Usage rules:
- Start with severity/tags/templates filters to keep runs explainable.
- Keep retries conservative (`-retries 1`) unless transport instability is proven.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If performance degrades, lower `-c/-bs` before lowering `-rl`.
- If findings are unexpectedly empty, verify template selection (`-as` vs explicit `-t/-tags`).
- If scan duration grows, reduce target set and enforce stricter template/severity filters.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io nuclei <flag> running`

## After You Finish (Memory)

Call `memory_record_task_outcome` recording:
- Which template tags/severities produced signal vs. noise on this target type
- Whether `-ni` was required (and why)
- Any specific CVE or misconfig templates that fired and were confirmed real
- Rate/concurrency settings that worked well for this target's tolerance
