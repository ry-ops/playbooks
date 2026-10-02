---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and sandbox-safe bounded scan patterns for CTF/HTB engagements.
kali_tools: [nmap, naabu]
time:
  quick: 30s–2m (top-100 ports, T4)
  standard: 2–5m (top-1000 ports + service detection)
  deep: 5–20m (all TCP ports + NSE scripts, scoped)
github_fallbacks:
  nmap: nmap/nmap
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "nmap timing bypass filtered ports"
- "nmap NSE scripts service fingerprint"
- "past nmap HTB open port discoveries"
- "nmap host discovery workarounds"

## Viability Gate

| Budget | Mode |
|--------|------|
| < 10m  | `nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s <host>` |
| 10m–1h | Two-pass: discovery with `--top-ports 1000` then enrichment with `-sV -sC` on open ports |
| 1h+    | Full `-p-` sweep followed by `-sV -sC --script-timeout 60s` on all open ports |

## Quick Reference

```bash
# Agent-safe baseline
nmap -n -Pn --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>

# Service/version enrichment on discovered ports
nmap -n -Pn -sV -sC -p 22,80,443 --script-timeout 30s --host-timeout 3m -oA nmap_services <host>

# No-root fallback (TCP connect scan)
nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>

# Important ports only (minimal noise)
nmap -n -Pn -p 22,80,443,8080,8443 --open -T4 --max-retries 1 --host-timeout 90s <host>
```

# Nmap CLI Playbook

Official docs:
- https://nmap.org/book/man-briefoptions.html
- https://nmap.org/book/man.html
- https://nmap.org/book/man-performance.html

Canonical syntax:
`nmap [Scan Type(s)] [Options] {target specification}`

High-signal flags:
- `-n` skip DNS resolution
- `-Pn` skip host discovery when ICMP/ping is filtered
- `-sS` SYN scan (root/privileged)
- `-sT` TCP connect scan (no raw-socket privilege)
- `-sV` detect service versions
- `-sC` run default NSE scripts
- `-p <ports>` explicit ports (`-p-` for all TCP ports)
- `--top-ports <n>` quick common-port sweep
- `--open` show only hosts with open ports
- `-T<0-5>` timing template (`-T4` common)
- `--max-retries <n>` cap retransmissions
- `--host-timeout <time>` give up on very slow hosts
- `--script-timeout <time>` bound NSE script runtime
- `-oA <prefix>` output in normal/XML/grepable formats

Agent-safe baseline for automation:
`nmap -n -Pn --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>`

Common patterns:
- Fast first pass:
  `nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Very small important-port pass:
  `nmap -n -Pn -p 22,80,443,8080,8443 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Service/script enrichment on discovered ports:
  `nmap -n -Pn -sV -sC -p <comma_ports> --script-timeout 30s --host-timeout 3m -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>`

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning: discovery pass, then enrichment pass.
- Always set a timeout boundary with `--host-timeout`; add `--script-timeout` whenever NSE scripts are involved.
- Keep discovery scans tight: use explicit important ports or a small `--top-ports` profile unless broader coverage is explicitly required.
- In sandboxed runs, avoid exhaustive sweeps (`-p-`, very high `--top-ports`, or wide host ranges) unless explicitly required.
- Do not spam traffic; start with the smallest port set that can answer the question.
- Prefer `naabu` for broad port discovery; use `nmap` for scoped verification/enrichment.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Prefer `-p 22,80,443,8080,8443` or `--top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`-p` or smaller `--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`

## After You Finish (Memory)

Call `memory_record_task_outcome` recording:
- Which port set revealed the key service (e.g., top-100 was sufficient vs. needed top-1000)
- Whether `-Pn` was required to see the host
- Which NSE scripts returned useful fingerprinting data
- Any timing adjustments needed for this target's network behavior
