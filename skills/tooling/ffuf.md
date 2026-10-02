---
name: ffuf
description: ffuf fuzzing syntax with matcher/filter strategy and non-interactive defaults for directory, parameter, vhost, and body fuzzing in CTF/HTB engagements.
kali_tools: [ffuf, dirsearch, wordlists]
time:
  quick: 1–3m (top wordlist, 200 req/s)
  standard: 5–15m (medium wordlist, calibrated filters)
  deep: 15–60m (large wordlist, recursive, vhost sweep)
github_fallbacks:
  ffuf: ffuf/ffuf
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "ffuf wordlist discoveries HTB boxes"
- "ffuf vhost fuzzing results"
- "ffuf filter calibration for this target type"
- "directory fuzzing findings similar targets"

## Viability Gate

| Budget | Mode |
|--------|------|
| < 10m  | `ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive` |
| 10m–1h | Medium wordlist (e.g., `raft-medium-directories.txt`), `-of json -o ffuf.json`, add `-recursion -recursion-depth 2` if top hits look promising |
| 1h+    | Large wordlist (e.g., `directory-list-2.3-big.txt`), vhost sweep in parallel, POST body fuzzing on interesting endpoints |

## Quick Reference

```bash
# Agent-safe baseline
ffuf -w wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o ffuf.json

# Basic path fuzzing (faster)
ffuf -w /path/wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive

# Vhost fuzzing
ffuf -w vhosts.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive

# POST body fuzzing
ffuf -w payloads.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -noninteractive

# Recursive discovery
ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive
```

# ffuf CLI Playbook

Official docs:
- https://github.com/ffuf/ffuf

Canonical syntax:
`ffuf -w <wordlist> -u <url_with_FUZZ> [flags]`

High-signal flags:
- `-u <url>` target URL containing `FUZZ`
- `-w <wordlist>` wordlist input (supports `KEYWORD` mapping via `-w file:KEYWORD`)
- `-mc <codes>` match status codes
- `-fc <codes>` filter status codes
- `-fs <size>` filter by body size
- `-ac` auto-calibration
- `-t <n>` threads
- `-rate <n>` request rate
- `-timeout <seconds>` HTTP timeout
- `-x <proxy_url>` upstream proxy (HTTP/SOCKS)
- `-ignore-body` skip downloading response body
- `-noninteractive` disable interactive console mode
- `-recursion` and `-recursion-depth <n>` recursive discovery
- `-H <header>` custom headers
- `-X <method>` and `-d <body>` for non-GET fuzzing
- `-o <file> -of <json|ejson|md|html|csv|ecsv>` structured output

Agent-safe baseline for automation:
`ffuf -w wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o ffuf.json`

Common patterns:
- Basic path fuzzing:
  `ffuf -w /path/wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive`
- Vhost fuzzing:
  `ffuf -w vhosts.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive`
- Parameter value fuzzing:
  `ffuf -w values.txt -u 'https://target.tld/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive`
- POST body fuzzing:
  `ffuf -w payloads.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -noninteractive`
- Recursive discovery:
  `ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive`
- Proxy-instrumented run:
  `ffuf -w wordlist.txt -u https://target.tld/FUZZ -x http://127.0.0.1:48080 -mc 200,301,302,403 -ac -noninteractive`

Critical correctness rules:
- `FUZZ` must appear exactly at the mutation point in URL/header/body.
- If using `-w file:KEYWORD`, that same `KEYWORD` must be present in URL/header/body.
- Always include `-noninteractive` in agent/script execution to prevent ffuf console mode from swallowing subsequent shell commands.
- Save structured output with `-of json -o <file>` for deterministic parsing.

Usage rules:
- Prefer explicit matcher/filter strategy (`-mc`/`-fc`/`-fs`) over default-only output.
- Start conservative (`-rate`, `-t`) and scale only if target tolerance is known.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If ffuf drops into interactive mode, send `C-c` and rerun with `-noninteractive`.
- If response noise is too high, tighten `-mc/-fc/-fs` instead of increasing load.
- If runtime is too long, lower `-rate/-t` and tighten scope.

If uncertain, query web_search with:
`site:github.com/ffuf/ffuf <flag> README`

Alternate tool for path/file enumeration: `dirsearch -u <url> -e php,html,js,json`
ships with curated wordlists, sane defaults, and built-in recursion. Reach
for ffuf when you need surgical fuzzing of any input position (header,
body, vhost) or precise filter control; reach for dirsearch for a quick
broad sweep with no setup.

## After You Finish (Memory)

Call `memory_record_task_outcome` recording:
- Which wordlists produced results (name + path)
- Whether vhost fuzzing found anything and what the response size delta was
- Filter calibration values that reduced noise on this target (`-fs`, `-fc` sizes)
- Any interesting paths discovered that warranted follow-up
