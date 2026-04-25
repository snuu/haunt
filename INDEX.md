# Haunt — Vulnerability Index

Maps each checklist category to its skill slug. Read this at the start of every HauntMode session.

## HOW TO USE
1. Scan EVERY category below against the request characteristics.
2. For each category that APPLIES or MAYBE: invoke the listed skill.
3. "APPLIES" means ANY signal matches — err on the side of inclusion.
4. After evaluation, execute the full analysis defined in HAUNT_CHECKLIST.md.

---

## 01 — SQL INJECTION
**Applies when:** any user-supplied input reaches a database query; parameters in URL/body/headers; numeric IDs; search fields; login forms; ORDER BY / sort params; any error messages referencing SQL syntax.
**Skill:** `sqli`

---

## 02 — NOSQL INJECTION
**Applies when:** MongoDB/CouchDB/Redis indicators; JSON body with field queries; `$where`, `$gt`, `$regex` in params; login endpoints; `application/json` content-type; NoSQL error messages.
**Skill:** `nosqli`

---

## 03 — COMMAND INJECTION
**Applies when:** parameters passed to system commands; file conversion/processing endpoints; ping/nslookup/traceroute functionality; filename parameters; any input that could reach a shell; OS command outputs in response.
**Skill:** `cmdi`

---

## 04 — XSS (REFLECTED / STORED / DOM)
**Applies when:** any user input reflected in HTML response; search boxes; comment fields; username/profile fields; error messages echoing input; URL parameters rendered client-side; `innerHTML` / `document.write` patterns; `text/html` responses.
**Skill:** `xss`

---

## 05 — CSRF
**Applies when:** state-changing actions (POST/PUT/DELETE/PATCH); forms without or with predictable CSRF tokens; cookie-based sessions; endpoints that perform actions on behalf of the user; no `SameSite` cookie attribute; weak `Origin`/`Referer` validation.
**Skill:** `csrf`

---

## 06 — IDOR / BROKEN ACCESS CONTROL
**Applies when:** numeric or predictable object IDs in URLs/params/body; `/api/users/123`, `/documents?id=`, `/profile?uid=`; references to other users' resources; encoded object references; mass assignment candidates; horizontal/vertical privilege escalation surfaces.
**Skill:** `idor`

---

## 07 — SSRF
**Applies when:** URL parameters (url=, path=, dest=, redirect=, uri=, src=, href=, fetch=); image/file fetching by URL; webhook endpoints; PDF generators; import-from-URL features; internal network indicators; cloud metadata responses.
**Skill:** `ssrf`

---

## 08 — SSTI (SERVER-SIDE TEMPLATE INJECTION)
**Applies when:** template engine signals (Jinja2, Twig, Freemarker, Smarty, Pebble, Velocity, Thymeleaf, Mako); user input reflected without encoding in rendered pages; `{{`, `${`, `<#` in responses; error messages showing template context; "Hello [input]" style responses.
**Skill:** `ssti`

---

## 09 — FILE INCLUSION (LFI / RFI)
**Applies when:** path/file parameters (`page=`, `file=`, `template=`, `view=`, `lang=`, `include=`); directory traversal attempts; PHP app indicators; `../` patterns; file extension in params; `.php`, `.html`, `.txt` in values.
**Skill:** `lfi`

---

## 10 — FILE UPLOAD
**Applies when:** any file upload endpoint; multipart/form-data; `filename=` in Content-Disposition; file type/extension validation; image upload; document import; avatar/profile picture upload.
**Skill:** `file-upload`

---

## 11 — HTTP REQUEST SMUGGLING (CL.TE / TE.CL / TE.TE / H2)
**Applies when:** HTTP/1.1 or HTTP/2 requests going through a proxy/load balancer; `Transfer-Encoding: chunked`; conflicting `Content-Length` headers; front-end/back-end architecture indicators; any request that passes through multiple HTTP parsers.
**Skill:** `request-smuggling`

---

## 12 — CRLF INJECTION / HTTP RESPONSE SPLITTING
**Applies when:** user input reflected in HTTP response headers; redirect parameters; `Location:` headers; `Set-Cookie:` with user input; URL parameters echoed in headers; log files.
**Skill:** `crlf`

---

## 13 — WEB CACHE POISONING / HOST HEADER ATTACKS
**Applies when:** caching headers present (`X-Cache`, `CF-Cache-Status`, `Age`, `Cache-Control`); `Host` header accepted and reflected; `X-Forwarded-Host` / `X-Forwarded-For` headers; password reset flows; CDN/proxy infrastructure; unkeyed header inputs.
**Skill:** `cache-poisoning`

---

## 14 — SESSION PUZZLING / SESSION FIXATION / WEAK SESSION IDs
**Applies when:** session tokens in URL params; predictable/short session IDs; session tokens set before authentication; multi-step flows using shared session variables; session data exposed in responses.
**Skill:** `session-attacks`

---

## 15 — AUTHENTICATION BYPASS / JWT / BRUTE FORCE
**Applies when:** login endpoints; JWT tokens (`eyJ` prefix); `Authorization: Bearer` header; password reset flows; 2FA/MFA endpoints; remember-me tokens; predictable token patterns; weak secret indicators.
**Skill:** `auth-bypass`

---

## 16 — DESERIALIZATION
**Applies when:** serialized object formats in cookies/body/headers (`O:`, `rO0`, `AAEAAAD`, `eyJ` with `$type`/`__type`); Java `.ser` magic bytes (`AC ED`); PHP `O:4:` patterns; .NET `__type` fields; base64 encoded blobs that decode to serialized formats.
**Skill:** `deserialization`

---

## 17 — XPATH INJECTION
**Applies when:** XML-based backends; SOAP services; XPath query indicators in errors; authentication endpoints querying XML data stores; parameters that could influence XPath expressions.
**Skill:** `xpath`

---

## 18 — LDAP INJECTION
**Applies when:** LDAP directory backends; Active Directory / LDAP authentication; `(uid=`, `(cn=`, `(mail=` patterns; enterprise SSO/directory-backed login forms; user search functionality.
**Skill:** `ldap`

---

## 19 — PDF GENERATION / HTML INJECTION
**Applies when:** report/invoice/PDF export functionality; Puppeteer/wkhtmltopdf/PhantomJS indicators; user-controlled content in generated documents; HTML-to-PDF pipelines; server-side rendering of user input.
**Skill:** `pdf-injection`

---

## 20 — PROTOTYPE POLLUTION
**Applies when:** JavaScript/Node.js backends; JSON body with `__proto__` / `constructor` / `prototype` keys; merge/clone/extend utility functions; `application/json` POST to config-setting endpoints; client-side JS with DOM invader; npm package indicators.
**Skill:** `prototype-pollution`

---

## 21 — RACE CONDITIONS / TIMING ATTACKS
**Applies when:** gift card / coupon redemption; funds transfer endpoints; rate-limited actions (login, OTP, reset); discount application; unique constraint enforcement; any "check then act" flow where timing could allow double-execution.
**Skill:** `race-conditions`

---

## 22 — TYPE JUGGLING
**Applies when:** PHP applications; loose comparison operators likely (`==` vs `===`); hash comparison in login/token validation; numeric vs string type coercion; magic hash values (`0e` prefix); JSON type confusion.
**Skill:** `type-juggling`

---

## 23 — PARAMETER LOGIC BUGS
**Applies when:** multi-step workflows; price/discount calculations; optional parameters that affect business logic; null/undefined handling; boundary conditions; validation that happens client-side but not server-side; parameters that interact in unexpected ways.
**Skill:** `param-logic`

---

## 24 — WEBSOCKET ATTACKS
**Applies when:** `Upgrade: websocket` header; `ws://` or `wss://` connections; real-time features (chat, live updates, notifications); WebSocket upgrade requests in Burp; bidirectional communication endpoints.
**Skill:** `websocket`

---

## 25 — SECOND-ORDER ATTACKS
**Applies when:** stored user input used later in a different context; username/profile fields processed in background jobs; data imported then used by another feature; two-step operations where step 1 stores and step 2 executes.
**Skill:** `second-order`

---

## 26 — CORS MISCONFIGURATIONS
**Applies when:** `Access-Control-Allow-Origin` header present; cross-origin API calls; `Origin:` header in request; CORS preflight (`OPTIONS` with `Access-Control-Request-*`); APIs serving JS frontends; wildcard origins.
**Skill:** `cors`

---

## 27 — HTTP VERB TAMPERING
**Applies when:** GET/POST requests to endpoints that may accept other methods; authentication/authorization enforced on specific methods only; PUT/DELETE/PATCH not tested; WebDAV indicators; REST APIs.
**Skill:** `verb-tampering`

---

## 28 — SSI INJECTION / ESI INJECTION / XSLT INJECTION
**Applies when:** Apache/Nginx serving `.shtml` or `.stm`; ESI headers (`Surrogate-Control`, `Surrogate-Capability`); XSLT transformations; XML processing pipelines; template-like `<!--#` patterns in responses; Varnish/Squid caching proxies.
**Skill:** `ssi-esi-xslt`

---

## 29 — API / SOAP / GRAPHQL / REST
**Applies when:** `/api/`, `/v1/`, `/v2/`, `/graphql`, `/soap`, WSDL endpoints; `SOAPAction` header; `application/json` or `application/xml`; REST APIs; API keys in headers; OpenAPI/Swagger docs; WSDL discovery.
**Skill:** `api-attacks`

---

## 30 — OPEN REDIRECT
**Applies when:** `redirect=`, `next=`, `return=`, `url=`, `goto=`, `redir=` parameters; `Location:` header following user input; OAuth callback URLs; post-login redirect parameters.
**Skill:** `open-redirect`

---

## 31 — INFORMATION DISCLOSURE
**Applies when:** verbose error messages; stack traces; debug endpoints (`/debug`, `/trace`, `/_profiler`); `.git`, `.env`, `backup.zip` accessible; HTTP headers leaking server/framework versions; commented-out HTML source; `/robots.txt` disclosures; API docs exposure.
**Skill:** `info-disclosure`

---

## 32 — WORDPRESS
**Applies when:** `/wp-admin`, `/wp-login.php`, `/wp-content/`, `/wp-includes/`; `WordPress` in response headers/source; `X-Pingback` header; `xmlrpc.php` accessible; WP-specific cookies.
**Skill:** `wordpress`

---

## 33 — DNS REBINDING
**Applies when:** SSRF filters blocking by IP but not hostname; time-of-check to time-of-use gaps in IP validation; localhost/internal access controls based on DNS; long-running connections.
**Skill:** `dns-rebinding`

---

## 34 — AJP / REVERSE PROXY MISCONFIGURATIONS
**Applies when:** Apache/Nginx reverse proxy; AJP port 8009; Tomcat backend; proxy headers (`X-Forwarded-*`, `X-Real-IP`); internal port exposure; Ghostcat indicators.
**Skill:** `ajp-proxy`

---

## 35 — MASS ASSIGNMENT / PARAMETER POLLUTION
**Applies when:** JSON body sent to create/update endpoints; user registration or profile update; any endpoint that maps request body directly to an object/model; fields visible in GET response that aren't in the POST/PUT form; `role`, `admin`, `isAdmin`, `verified`, `balance`, `price` fields anywhere.
**Skill:** `mass-assignment`

---

## 36 — XXE (XML EXTERNAL ENTITY)
**Applies when:** XML body (`Content-Type: application/xml`, `text/xml`); SOAP requests; file upload accepting `.xml`, `.svg`, `.docx`, `.xlsx`; any format that wraps XML (Office docs, SVG); JSON APIs that also accept XML; SAML authentication tokens.
**Skill:** `xxe`

---

## 37 — BUSINESS LOGIC FLOW ATTACKS
**Applies when:** multi-step processes (checkout, account setup, password reset, onboarding); features with prerequisites (must verify email before X); time-gated features; anything with a "coming soon" or access-controlled state; discount/coupon application; quantity/price fields.
**Skill:** `business-logic`

---
