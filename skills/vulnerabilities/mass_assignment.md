---
name: mass-assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters — with mr.robot memory hooks and viability gating
kali_tools: curl, burpsuite, python3, ffuf
time:
  quick: 15m
  standard: 1h
  deep: 3h
github_fallbacks: {}
---

# Mass Assignment

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It commonly leads to privilege escalation, ownership changes, and unauthorized state transitions in modern APIs and GraphQL.

## Before You Start (Memory)

Call `memory_recall_for_task` with queries like:
- "mass assignment privilege escalation isAdmin role"
- "mass assignment ownership takeover userId tenantId"
- "GraphQL mass assignment input type hidden fields"
- "Rails strong parameters Laravel fillable mass assignment"
- "past mass assignment findings [target framework]"

Review recalled approaches — previous work may have identified the ORM framework, found specific field names that worked, or noted which endpoints have missing allowlists.

## Viability Gate

| Budget | Approach |
|--------|----------|
| < 15m  | On the registration or profile update endpoint, add `"isAdmin": true`, `"role": "admin"`, and `"verified": true` to the JSON body alongside legitimate fields. Immediately GET the profile or user object and check if the fields persisted. One endpoint, one injection, high-yield check. |
| 15m–1h | Build a sensitive-field dictionary (role, isAdmin, permissions, ownerId, plan, verified, flags, limits), inject against registration + profile update + any create/update endpoints, test both JSON body and form-encoded, check for ownership/tenant field injection on resource operations. |
| 1h+    | Deep: GraphQL mutation field fuzzing via introspection, nested object/relation writes, batch endpoint per-item check bypass, race-condition reorder attacks, ORM-specific deep nesting (Rails `accepts_nested_attributes_for`, DRF writable nested serializers), mobile/SDK hidden field discovery, content-type switching sweep. |

Hardware note: All tools (curl, burpsuite, python3, ffuf) are lightweight. No significant RAM/CPU constraints.

## Tool Inventory

```bash
which curl burpsuite python3 ffuf
```

Missing a tool? → `arcade_report_blocker("[tool] not installed for mass-assignment")`

All tools are standard Kali. For automated field fuzzing, ffuf can sweep field names against a wordlist. No major GitHub fallbacks required.

### Quick field injection with curl
```bash
# Registration endpoint — inject admin field
curl -s -X POST https://TARGET/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"Test1234!","email":"test@test.com","isAdmin":true,"role":"admin"}' | jq .

# Profile update — inject privilege field
curl -s -X PUT https://TARGET/api/profile \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer TOKEN' \
  -d '{"displayName":"test","isAdmin":true,"role":"admin","plan":"enterprise"}' | jq .
```

## Attack Surface

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Reconnaissance

### Surface Map

- Controllers with automatic binding (e.g., request.json → model)
- GraphQL input types mirroring models; admin/staff tools exposed via API
- OpenAPI/GraphQL schemas: uncover hidden fields or enums
- Client bundles and mobile apps: inspect forms and mutation payloads for field names

### Parameter Strategies

- Flat fields: `isAdmin`, `role`, `roles[]`, `permissions[]`, `status`, `plan`, `tier`, `premium`, `verified`, `emailVerified`
- Ownership/tenancy: `userId`, `ownerId`, `accountId`, `organizationId`, `tenantId`, `workspaceId`
- Limits/quotas: `usageLimit`, `seatCount`, `maxProjects`, `creditBalance`
- Feature flags/gates: `features`, `flags`, `betaAccess`, `allowImpersonation`
- Billing: `price`, `amount`, `currency`, `prorate`, `nextInvoice`, `trialEnd`

### Shape Variants

- Alternate shapes: arrays vs scalars; nested JSON; objects under unexpected keys
- Dot/bracket paths: `profile.role`, `profile[role]`, `settings[roles][]`
- Duplicate keys and precedence: `{"role":"user","role":"admin"}`
- Sparse/patch formats: JSON Patch/JSON Merge Patch; try adding forbidden paths

### Encodings and Channels

- Content-types: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- GraphQL: add suspicious fields to input objects; overfetch response to detect changes
- Batch/bulk: arrays of objects; verify per-item allowlists not skipped

## Key Vulnerabilities

### Privilege Escalation

- Set role/isAdmin/permissions during signup/profile update
- Toggle admin/staff flags where exposed

### Ownership Takeover

- Change ownerId/accountId/tenantId to seize resources
- Move objects across users/tenants

### Feature Gate Bypass

- Enable premium/beta/feature flags via flags/features fields
- Raise limits/seatCount/quotas

### Billing and Entitlements

- Modify plan/price/prorate/trialEnd or creditBalance
- Bypass server recomputation

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope

## Advanced Techniques

### GraphQL Specific

- Field-level authz missing on input types: attempt forbidden fields in mutation inputs
- Combine with aliasing/batching to compare effects
- Use fragments to overfetch changed fields immediately after mutation

```graphql
# Inject isAdmin field into mutation and overfetch
mutation UpdateProfile($input: ProfileInput!) {
  updateProfile(input: $input) {
    id
    username
    isAdmin
    role
    plan
  }
}
# Variables: {"input": {"displayName": "test", "isAdmin": true, "role": "admin"}}
```

### ORM Framework Edges

- **Rails**: strong parameters misconfig or deep nesting via `accepts_nested_attributes_for`
- **Laravel**: $fillable/$guarded misuses; `guarded=[]` opens all; casts mutating hidden fields
- **Django REST Framework**: writable nested serializer, read_only/extra_kwargs gaps, partial updates
- **Mongoose/Prisma**: schema paths not filtered; `select:false` doesn't prevent writes; upsert defaults

### Parser and Validator Gaps

- Validators run post-bind and do not cover extra fields
- Unknown fields silently dropped in response but persisted underneath
- Inconsistent allowlists between mobile/web/gateway; alt encodings bypass validation pipeline

## Bypass Techniques

### Content-Type Switching

- Switch JSON ↔ form-encoded ↔ multipart ↔ text/plain; some code paths only validate one

### Key Path Variants

- Dot/bracket/object re-shaping to reach nested fields through different binders

### Batch Paths

- Per-item checks skipped in bulk operations
- Insert a single malicious object within a large batch

### Race and Reorder

- Race two updates: first sets forbidden field, second normalizes
- Final state may retain forbidden change

## Testing Methodology

1. **Identify endpoints** — Create/update endpoints and GraphQL mutations
2. **Capture responses** — Observe returned fields to build candidate list
3. **Build sensitive-field dictionary** — Per resource: role, isAdmin, ownerId, status, plan, limits, flags
4. **Inject candidates** — Alongside legitimate updates across transports and encodings
5. **Compare state** — Before/after diffs across roles
6. **Test variations** — Nested objects, arrays, alternative shapes, duplicate keys, batch operations

### ffuf field name discovery
```bash
# Fuzz field names against an update endpoint
# Create a wordlist of common sensitive fields
cat > /tmp/mass_fields.txt << 'EOF'
isAdmin
role
roles
admin
staff
superuser
permissions
verified
emailVerified
plan
premium
tier
userId
ownerId
accountId
tenantId
organizationId
workspaceId
usageLimit
creditBalance
seatCount
features
flags
betaAccess
status
active
EOF

# Probe each field (adjust endpoint/format as needed)
while read field; do
  result=$(curl -s -X PUT https://TARGET/api/profile \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer TOKEN' \
    -d "{\"displayName\":\"test\",\"$field\":true}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$field','NOT_IN_RESPONSE'))" 2>/dev/null)
  echo "$field => $result"
done < /tmp/mass_fields.txt
```

## Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value
3. Demonstrate consistency across at least two encodings or channels
4. For nested/bulk, show that protected fields are written within child objects or array elements
5. Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility

## False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input
- Fields marked read-only and enforced consistently across encodings
- Only UI-side changes with no persisted effect

## Impact

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

## Pro Tips

1. Build a sensitive-field dictionary per resource and fuzz systematically
2. Always try alternate shapes and encodings; many validators are shape/CT-specific
3. For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields
4. Inspect SDKs/mobile apps for hidden field names and nested write examples
5. Prefer minimal PoCs that prove durable state changes; avoid UI-only effects

## Summary

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute — especially nested or batch inputs — as untrusted until validated against an allowlist and caller scope.

## After You Finish (Memory)

Call `memory_record_task_outcome` with:
```json
{
  "approach": "list which endpoints were tested (registration/update/GraphQL mutation), which field names fired, which ORM framework was identified, which encodings were tried",
  "learned": "specific field names that worked; whether nested/batch paths bypassed allowlists; which content-type switch was effective; what server-side recomputation prevented exploitation",
  "tools": "curl for field injection, burpsuite for request editing and response diffing, python3 for automated before/after comparison, ffuf for field name wordlist sweeps"
}
```
