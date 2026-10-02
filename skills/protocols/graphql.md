---
name: graphql
description: GraphQL security testing covering introspection, resolver injection, batching attacks, and authorization bypass
kali_tools: curl, python3, nuclei
time:
  quick: 15m
  standard: 1h
  deep: 3h
github_fallbacks:
  clairvoyance: nikitastupin/clairvoyance
  graphw00f: dolevf/graphw00f
---

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "GraphQL authorization bypass past findings [target]"
- "GraphQL IDOR resolver gaps"
- "introspection disabled schema recovery"
- "federation subgraph auth bypass"

## Viability Gate

| Budget | Approach |
|--------|----------|
| < 15m  | Probe endpoint with `{__typename}`, attempt introspection, test unauthenticated access to key queries; graphw00f fingerprint |
| 15m–1h | Full schema mapping (introspection or inference), principal matrix, field-level IDOR with aliases, federation `_entities` probe |
| 1h+    | Depth/complexity analysis, cursor manipulation, subscription auth, persisted query replay, federation SDL enumeration, WAF evasion |

## Tool Inventory

```bash
which curl python3 nuclei
# graphw00f: fingerprint GraphQL engine
python3 -c "import graphw00f" 2>/dev/null || echo "graphw00f: not installed (see github_fallbacks)"
# clairvoyance: schema recovery without introspection
python3 -c "import clairvoyance" 2>/dev/null || echo "clairvoyance: not installed (see github_fallbacks)"
```

Missing? → `arcade_report_blocker` or install:
```bash
pip install graphw00f
# clairvoyance
git clone https://github.com/nikitastupin/clairvoyance && pip install -r clairvoyance/requirements.txt
```

---

# GraphQL

Security testing for GraphQL APIs. Focus on resolver-level authorization, field/edge access control, batching abuse, and federation trust boundaries.

## Attack Surface

**Operations**
- Queries, mutations, subscriptions
- Persisted queries / Automatic Persisted Queries (APQ)

**Transports**
- HTTP POST/GET with `application/json` or `application/graphql`
- WebSocket: graphql-ws, graphql-transport-ws protocols
- Multipart for file uploads

**Schema Features**
- Introspection (`__schema`, `__type`)
- Directives: `@defer`, `@stream`, custom auth directives (@auth, @private)
- Custom scalars: Upload, JSON, DateTime
- Relay: global node IDs, connections/cursors, interfaces/unions

**Architecture**
- Federation (Apollo, GraphQL Mesh): `_service`, `_entities`
- Gateway vs subgraph authorization boundaries

## Reconnaissance

**Endpoint Discovery**
```
POST /graphql         {"query":"{__typename}"}
POST /api/graphql     {"query":"{__typename}"}
POST /v1/graphql      {"query":"{__typename}"}
POST /gql             {"query":"{__typename}"}
GET  /graphql?query={__typename}
```

Check for GraphiQL/Playground exposure with credentials enabled (cross-origin with cookies can leak data via postMessage bridges).

**Schema Acquisition**

If introspection enabled:
```graphql
{__schema{types{name fields{name args{name}}}}}
```

If disabled, infer schema via:
- `__typename` probes on candidate fields
- Field suggestion errors (submit near-miss names to harvest suggestions)
- "Expected one of" errors revealing enum values
- Type coercion errors exposing field structure
- Error taxonomy: different codes for "unknown field" vs "unauthorized field" reveal existence
- **clairvoyance** for automated schema recovery: `python3 -m clairvoyance -u https://target/graphql -o schema.json`

**Schema Mapping**

Map: root operations, object types, interfaces/unions, directives, custom scalars. Identify sensitive fields: email, tokens, roles, billing, API keys, admin flags, file URLs. Note cascade paths where child resolvers may skip auth under parent assumptions.

## Key Vulnerabilities

### Authorization Bypass

**Field-Level IDOR**

Test with aliases comparing owned vs foreign objects in single request:
```graphql
query {
  own: order(id:"OWNED_ID") { id total owner { email } }
  foreign: order(id:"FOREIGN_ID") { id total owner { email } }
}
```

**Edge/Child Resolver Gaps**

Parent resolver checks auth, child resolver assumes it's already validated:
```graphql
query {
  user(id:"FOREIGN") {
    id
    privateData { secrets }  # Child may skip auth check
  }
}
```

**Relay Node Resolution**

Decode base64 global IDs, swap type/id pairs:
```graphql
query {
  node(id:"VXNlcjoxMjM=") { ... on User { email } }
}
```
Ensure per-type authorization is enforced inside resolvers. Verify connection filters (owner/tenant) apply before pagination; cursor tampering should not cross ownership boundaries.

**Mutation Bypass**
- Probe mutations for partial updates bypassing validation (JSON Merge Patch semantics)
- Test mutations that accept extra fields passed to downstream logic

### Batching & Alias Abuse

**Enumeration via Aliases**
```graphql
query {
  u1:user(id:"1"){email}
  u2:user(id:"2"){email}
  u3:user(id:"3"){email}
}
```
Bypasses per-request rate limits; exposes per-field vs per-request auth inconsistencies.

**Array Batching**

If supported (non-standard), submit multiple operations to achieve partial failures and bypass limits.

### Input Manipulation

**Type Confusion**
```
{id: 123}      vs {id: "123"}
{id: [123]}    vs {id: null}
{id: 0}        vs {id: -1}
```

**Duplicate Keys**
```json
{"id": 1, "id": 2}
```
Parser precedence varies; may bypass validation. Also test default argument values.

**Extra Fields**

Send unexpected keys in input objects; backends may pass them to resolvers or downstream logic.

### OneOf Inputs

Discover `@oneOf` input types through the schema or `__Type.isOneOf`. They require exactly one non-null field, with every other field omitted. Test both inline literals and variables with zero fields, two selectors, and an extra null-valued selector; all must fail coercion. Then test authorization independently for each valid selector (ID, username, organization/email), since schema exclusivity does not ensure identical tenant checks in each resolver branch. Confirm the deployed implementation supports OneOf before treating acceptance as a specification violation ([GraphQL September 2025](https://spec.graphql.org/September2025/#sec-OneOf-Input-Objects)).

### Cursor Manipulation

Decode cursors (usually base64) to:
- Manipulate offsets/IDs
- Skip filters
- Cross ownership boundaries

### Directive Abuse

**@defer/@stream**
```graphql
query {
  me { id }
  ... @defer { adminPanel { secrets } }
}
```
May return gated data in incremental delivery. Confirm server supports incremental delivery.

**Custom Directives**

@auth, @private and similar directives often annotate intent but do not enforce—verify actual checks in each resolver path.

### Complexity Attacks

**Fragment Bombs**
```graphql
fragment x on User { friends { ...x } }
query { me { ...x } }
```
Test depth/complexity limits, query cost analyzers, timeouts.

**Wide Selection Sets**

Abuse selection sets and fragments to force overfetching of sensitive subfields.

### Federation Exploitation

**SDL Exposure**
```graphql
query { _service { sdl } }
```

**Entity Materialization**
```graphql
query {
  _entities(representations:[
    {__typename:"User", id:"TARGET_ID"}
  ]) { ... on User { email roles } }
}
```
Gateway may enforce auth; subgraph resolvers may not. Look for cross-subgraph IDOR via inconsistent ownership checks.

### Subscription Security

- Authorization at handshake only, not per-message
- Subscribe to other users' channels via filter args
- Cross-tenant event leakage
- Abuse filter args in subscription resolvers to reference foreign IDs

### Persisted Query Abuse

- APQ hashes leaked from client bundles
- Replay privileged operations with attacker variables
- Hash bruteforce for common operations
- Validate hash→operation mapping enforces principal and operation allowlists

### CORS & CSRF

- Cookie-auth with GET queries enables CSRF on mutations via query parameters
- GraphiQL/Playground cross-origin with credentials leaks data
- Missing SameSite and origin validation

### File Uploads

GraphQL multipart spec:
- Multiple Upload scalars
- Filename/path traversal tricks
- Unexpected content-types, oversize chunks
- Server-side ownership/scoping for returned URLs

## WAF Evasion

**Query Reshaping**
- Comments and block strings (`"""..."""`)
- Unicode escapes
- Alias/fragment indirection
- JSON variables vs inline args
- GET vs POST vs `application/graphql`

**Fragment Splitting**

Split fields across fragments and inline spreads to avoid naive signatures:
```graphql
fragment a on User { email }
fragment b on User { password }
query { me { ...a ...b } }
```

## Bypass Techniques

**Transport Switching**
```
Content-Type: application/json
Content-Type: application/graphql
Content-Type: multipart/form-data
GET with query params
```

**Timing & Rate Limits**
- HTTP/2 multiplexing and connection reuse to widen timing windows
- Batching to bypass rate limits

**Naming Tricks**
- Case/underscore variations
- Unicode homoglyphs (server-dependent)
- Aliases masking sensitive field names

**Cache Confusion**
- CDN caching without Vary on Authorization
- Variable manipulation affecting cache keys
- Redirects and 304/206 behaviors leaking partial responses

## Testing Methodology

1. **Fingerprint** - Identify endpoints, transports, stack (Apollo, Hasura, etc.) via graphw00f, GraphiQL exposure
2. **Schema mapping** - Introspection or clairvoyance inference to build complete type graph
3. **Principal matrix** - Collect tokens for unauth, user, premium, admin roles with at least one valid object ID per subject
4. **Field sweep** - Test each resolver with owned vs foreign IDs via aliases in same request
5. **Transport parity** - Verify same auth on HTTP, WebSocket, persisted queries
6. **Federation probe** - Test `_service` and `_entities` for subgraph auth gaps
7. **Edge cases** - Cursors, @defer/@stream, subscriptions, file uploads

## Validation Requirements

- Paired requests (owner vs non-owner) showing unauthorized access
- Resolver-level bypass: parent checks present, child field exposes data
- Transport parity proof: HTTP and WebSocket for same operation
- Federation bypass: `_entities` accessing data without subgraph auth
- Minimal payloads with exact selection sets and variable shapes
- Document exact resolver paths that missed enforcement

## After You Finish (Memory)

Call `memory_record_task_outcome` with:
- **approach**: introspection vs clairvoyance inference, principal matrix coverage, federation testing
- **learned**: which resolver layers skipped auth, alias batching effectiveness, WAF bypass techniques that worked
- **tools**: graphw00f engine fingerprint accuracy; clairvoyance schema recovery quality vs introspection
