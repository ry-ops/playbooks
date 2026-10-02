---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure — with mr.robot memory hooks and viability gating
kali_tools: curl, nmap, nuclei, trufflehog, gitleaks, ffuf
time:
  quick: 15m
  standard: 1h
  deep: 4h
github_fallbacks:
  trufflehog: trufflesecurity/trufflehog
  gitleaks: zricethezav/gitleaks
---

# Information Disclosure

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "information disclosure DVCS git source exposure"
- "debug endpoint actuator metrics exposed"
- "source map webpack client bundle secrets"
- "credential leak config file exposed"
- "past information disclosure findings [target tech]"

Review recalled approaches — previous engagements may have found specific backup file patterns, known-vulnerable framework debug paths, or cloud storage bucket naming conventions for this target.

## Viability Gate

| Budget | Approach |
|--------|----------|
| < 15m  | Hit the three fastest artifact classes: (1) `/.git/HEAD` and `/.git/config` for DVCS exposure, (2) `/actuator`, `/actuator/env`, `/.env`, `/phpinfo.php`, `/api-docs`, `/swagger.json` for config/schema leaks, (3) scan response headers for `Server`, `X-Powered-By`, `X-AspNet-Version`. Use nuclei with `exposure` tags or a short ffuf wordlist. |
| 15m–1h | Full artifact sweep (DVCS, backups, source maps, API docs, debug endpoints), controlled error triggering, differential oracle across roles, version-to-CVE mapping for any versions disclosed. |
| 1h+    | Deep: reconstruct source from DVCS objects, extract secrets with trufflehog/gitleaks, full observability endpoint sweep, cloud storage probing, cross-channel comparison (REST vs GraphQL vs WebSocket vs mobile), complete exploitation chains from disclosed data. |

Hardware note: trufflehog on large repos can be RAM-intensive. nuclei scans should use `-rate-limit` to avoid triggering WAFs. ffuf is lightweight.

## Tool Inventory

```bash
which curl nmap nuclei trufflehog gitleaks ffuf
```

Missing a tool? → `arcade_report_blocker("[tool] not installed for information-disclosure")`

Or install from GitHub:
- `trufflehog`: `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin` (trufflesecurity/trufflehog)
- `gitleaks`: `git clone https://github.com/zricethezav/gitleaks && cd gitleaks && make build` (zricethezav/gitleaks)

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Direct disclosure of secrets that provide broad privileged control, with successful use validated where safe
- **High**: Direct disclosure of highly sensitive data, cross-tenant data, or credentials with serious demonstrated access
- **Medium**: Unauthorized access to a limited set of genuinely restricted data, or a fully validated chain from the disclosure to a concrete security consequence
- **Low**: Limited unauthorized disclosure with modest sensitivity and no serious direct consequence
- **Informational / no report**: Public or intended client data, generic headers, internal names or private addresses, versions without a reachable exploit, and source maps or diagnostics that expose no secrets or restricted source

Do not assign Confidentiality Low merely because information helps reconnaissance. CVSS C:L requires actual access to restricted information. If a path, hostname, version, source map, schema, or debug value only suggests a possible second vulnerability, either validate that complete chain and score its demonstrated outcome or leave C:N and omit the vulnerability report.

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Testing Methodology

1. **Build channel map** — Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** — Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** — Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** — DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** — Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

### Quick ffuf artifact sweep
```bash
# Backup and config file sweep
ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -t 50

# Source map and bundle discovery
ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  -e .map,.bak,.old,.swp,.orig,.env -mc 200
```

### nuclei disclosure scan
```bash
nuclei -u https://TARGET -t exposures/ -t misconfiguration/ -rate-limit 50
```

### trufflehog on extracted DVCS
```bash
# After pulling git objects from /.git/
git clone https://TARGET/.git/ extracted_repo 2>/dev/null || \
  python3 git_dumper.py https://TARGET/.git/ extracted_repo
trufflehog filesystem extracted_repo/ --json
```

### gitleaks on local repo
```bash
gitleaks detect --source=extracted_repo/ --report-format=json --report-path=leaks.json
```

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification
6. Map each non-None CVSS impact metric to evidence of actual restricted disclosure, modification, or service interruption

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop — proof should be minimal and reversible

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.

## After You Finish (Memory)

Call `memory_record_task_outcome` with:
```json
{
  "approach": "list which artifact classes were found (DVCS, backups, source maps, debug endpoints, config files, API schemas); note the framework/stack versions disclosed",
  "learned": "which paths fired; what credentials or secrets were exposed; which version-to-CVE chains were viable; what was already hardened",
  "tools": "nuclei for automated surface scan, ffuf for artifact discovery, trufflehog/gitleaks for secret extraction from DVCS, curl for targeted probes"
}
```
