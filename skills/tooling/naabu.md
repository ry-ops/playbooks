---
name: naabu
description: Naabu port-scanning syntax with host input, scan-type, verification, and rate controls for fast broad port discovery in CTF/HTB engagements.
kali_tools: [naabu, nmap]
time:
  quick: 30s–2m (top-100 ports, connect scan)
  standard: 2–5m (top-1000 ports, verified)
  deep: 5–20m (full port range or multi-host sweep)
github_fallbacks:
  naabu: projectdiscovery/naabu
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "naabu port discoveries HTB non-standard ports"
- "naabu connect vs SYN scan privilege requirements"
- "port sweep results similar target IP ranges"
- "naabu verify false positives filtered ports"

## Viability Gate

| Budget | Mode |
|--------|------|
| < 10m  | `naabu -host target.tld -top-ports 100 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent` |
| 10m–1h | `naabu -list hosts.txt -top-ports 1000 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl` then pipe discovered ports to `nmap` enrichment |
| 1h+    | Full port sweep: `-p -` with conservative `-rate 100` across host list; use SYN scan (`sudo naabu ... -scan-type syn`) if root available |

## Quick Reference

```bash
# Agent-safe baseline
naabu -list hosts.txt -top-ports 100 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl

# Focused web-ports sweep
naabu -list hosts.txt -p 80,443,8080,8443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent

# Single-host quick check
naabu -host target.tld -p 22,80,443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify

# Root SYN mode (if available)
sudo naabu -list hosts.txt -top-ports 100 -scan-type syn -rate 500 -c 25 -timeout 1000 -retries 1 -verify -silent
```

# Naabu CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/naabu/usage
- https://docs.projectdiscovery.io/opensource/naabu/running
- https://github.com/projectdiscovery/naabu

Canonical syntax:
`naabu [flags]`

High-signal flags:
- `-host <host>` single host
- `-list, -l <file>` hosts list
- `-p <ports>` explicit ports (supports ranges)
- `-top-ports <n|full>` top ports profile
- `-exclude-ports <ports>` exclusions
- `-scan-type <s|c|syn|connect>` SYN or CONNECT scan
- `-Pn` skip host discovery
- `-rate <n>` packets per second
- `-c <n>` worker count
- `-timeout <ms>` per-probe timeout in milliseconds
- `-retries <n>` retry attempts
- `-proxy <socks5://host:port>` SOCKS5 proxy
- `-verify` verify discovered open ports
- `-j, -json` JSONL output
- `-silent` compact output
- `-o <file>` output file

Agent-safe baseline for automation:
`naabu -list hosts.txt -top-ports 100 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl`

Common patterns:
- Top ports with controlled rate:
  `naabu -list hosts.txt -top-ports 100 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -o naabu.txt`
- Focused web-ports sweep:
  `naabu -list hosts.txt -p 80,443,8080,8443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent`
- Single-host quick check:
  `naabu -host target.tld -p 22,80,443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify`
- Root SYN mode (if available):
  `sudo naabu -list hosts.txt -top-ports 100 -scan-type syn -rate 500 -c 25 -timeout 1000 -retries 1 -verify -silent`

Critical correctness rules:
- Use `-scan-type connect` when running without root/privileged raw socket access.
- Always set `-timeout` explicitly; it is in milliseconds.
- Set `-rate` explicitly to avoid unstable or noisy scans.
- `-timeout` is in milliseconds, not seconds.
- Keep port scope tight: prefer explicit important ports or a small `-top-ports` value unless broader coverage is explicitly required.
- Do not spam traffic; start with the smallest useful port set and conservative rate/worker settings.
- Prefer `-verify` before handing ports to follow-up scanners.

Usage rules:
- Keep host discovery behavior explicit (`-Pn` or default discovery).
- Use `-j -o <file>` for automation pipelines.
- Prefer `-p 22,80,443,8080,8443` or `-top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for normal flow unless absolutely necessary.

Failure recovery:
- If privileged socket errors occur, switch to `-scan-type c`.
- If scans are slow or lossy, lower `-rate`, lower `-c`, and tighten `-p`/`-top-ports`.
- If many hosts appear down, compare runs with and without `-Pn`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io naabu <flag> usage`

## After You Finish (Memory)

Call `memory_record_task_outcome` recording:
- Which non-standard ports were open (anything beyond 22/80/443 is high-signal)
- Whether `-Pn` was needed to detect the host
- Whether SYN vs. connect scan made a difference for this target
- Port list to hand off to `nmap -sV -sC` for service enrichment
