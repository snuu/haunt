---
name: session-attacks
description: Session security attacks — weak session IDs, session fixation, session puzzling (premature population, common variable reuse, account takeover), cookie attribute analysis, session token in URL, and second-order session issues. Use when HauntMode flags session management as APPLIES/MAYBE, when analyzing Set-Cookie headers, or when testing multi-step flows for state confusion vulnerabilities.
---

# Session Attacks — Session Security & Puzzling

This skill covers the full spectrum of session-layer vulnerabilities: cookie attribute hygiene, weak/predictable session IDs, session fixation, and session puzzling (premature population, shared session variables across flows). Read top to bottom on first invocation; jump to the relevant section for follow-up runs.

---

## 1. Triggers — when this skill applies

- Any `Set-Cookie` header visible in Burp — check attributes immediately
- Session token that looks short, patterned, or incrementing
- Login flow that issues a cookie before authentication completes
- Password reset / registration flows that span multiple steps (`/reset_1.php`, `/reset_2.php`, `/reset_3.php`)
- Redirect on failed login that carries state (e.g., `?failed=1` with a username in the error)
- A URL containing the session ID (`token=`, `PHPSESSID=` in query string)
- Session token that decodes to structured data (base64 → `user=admin;role=user`)
- Any app where two different flows (e.g., registration and password reset) might share a `Phase` or `Username` session variable

---

---

## 3. 30-second triage

On every new target, immediately check these before anything else:

**Step 1 — Cookie attribute checklist:**
```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=target.com; Max-Age=3600
```

| Attribute | Good | Bad / Flag it |
|---|---|---|
| `HttpOnly` | Present | Missing — cookie readable by JS → XSS → session theft |
| `Secure` | Present | Missing — cookie sent over HTTP → sniffable on same network |
| `SameSite` | `Strict` or `Lax` | `None` without `Secure`, or unset → CSRF via cross-site requests |
| `Expires`/`Max-Age` | Short-lived | Very long / persistent — sessions don't expire |
| `Path` | `/` or restricted path | Over-broad or misconfigured |
| `Domain` | Exact domain | `.target.com` with leading dot — all subdomains share the cookie |

**Step 2 — Token structure check:**
```bash
echo -n "<token>" | base64 -d 2>/dev/null
echo -n "<token>" | xxd -r -p 2>/dev/null
```
If it decodes to `user=X;role=Y` or similar structured data — flag immediately (see §6).

**Step 3 — Entropy check:**
Collect 5–10 tokens by logging in repeatedly. Compare them. Look for:
- Fixed prefix/suffix with only a few random middle chars
- Incrementing numeric IDs (`141233`, `141234`, `141237`)
- Tokens shorter than 16 bytes (32 hex chars)
- Patterns in Burp Sequencer (send login request to Sequencer → capture 1000 tokens → analyze)

**Step 4 — Session ID in URL:**
Check if the session ID appears as a URL query parameter (`?PHPSESSID=`, `?token=`, `?sid=`). If yes, it leaks via `Referer` header to any external resource loaded on the page.

---

## 4. Cookie attribute findings — quick reporting

Missing `HttpOnly`: chain with XSS for session theft. Impact: account takeover.
Missing `Secure`: session can be intercepted on HTTP. Flag as informational unless HTTP endpoint exists.
`SameSite=None` without good reason: CSRF risk. Cross-reference with `csrf` skill.
Persistent cookie with very long expiry: sessions survive browser close, increases window for theft.

---

## 5. Weak session ID — entropy analysis

**Minimum bar (OWASP):** 16 bytes of truly random data = 128 bits entropy. At least 64 bits of effective entropy.

**Manual check:** Collect multiple tokens, diff them:
```bash
# Collect tokens by scripting repeated logins, one per line
sort tokens.txt | uniq -d   # repeated tokens = zero entropy, critical
```

**Burp Sequencer:** Right-click login response → Send to Sequencer → start live capture → collect 1000+ tokens → Analyze. Look for: effective entropy < 64 bits, character position analysis showing fixed positions.

**Short ID brute force** — if token is 4 chars `[a-z0-9]`:
```
[RUN THIS]
crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o /tmp/session_wordlist.txt
ffuf -u https://target.com/profile.php -b 'sessionID=FUZZ' -w /tmp/session_wordlist.txt -fc 302 -t 10
```
Filter 302 (redirected to login = invalid). A 200 with content = valid hijacked session.

**Predictable / patterned token:** If the token is structured like `2c0c58b2...XXXX...92b9f9` where only 4 chars change:
```
[RUN THIS]
crunch 4 4 "abcdefghijklmnopqrstuvwxyz0123456789" -o /tmp/rand4.txt
# Prepend/append fixed parts in ffuf -b header
ffuf -u https://target.com/profile.php -b 'session=2c0c58b27c71a2ec5bf2b4FUZZ92b9f9' -w /tmp/rand4.txt -fc 302 -t 5
```

**Encoded session token (no signature):** Decode, modify role/user field, re-encode:
```bash
echo -n "<token>" | base64 -d
# Output: user=htb-stdnt;role=user
echo -n 'user=htb-stdnt;role=admin' | base64
# Use the output as the new cookie value
```
For hex-encoded:
```bash
echo -n "<hextoken>" | xxd -r -p
echo -n 'user=htb-stdnt;role=admin' | xxd -p
```

---

## 6. Session fixation

**What it is:** The server accepts a session ID supplied by the client (via URL or cookie) and reuses it post-login. Attacker sends victim a URL with an attacker-controlled token; once victim logs in, attacker uses the same token.

**Test:**
1. Visit app — note the assigned `PHPSESSID` value (from `Set-Cookie` or URL param `token=`)
2. Craft URL: `https://target.com/login?PHPSESSID=AttackerSpecifiedValue` or `?token=AttackerSpecifiedValue`
3. Load that URL in a fresh browser. Check — does the app honor the supplied value and set `PHPSESSID=AttackerSpecifiedValue`?
4. If yes → session fixation confirmed.

**Exploitation chain:**
1. Attacker obtains a valid pre-auth session from the app.
2. Attacker sends victim: `https://target.com/login?token=AttackerKnownValue`
3. Victim logs in normally.
4. Attacker uses `AttackerKnownValue` as their session cookie → full ATO.

**Indicator in source code (reference pattern):**
```php
} else {
    setcookie("PHPSESSID", $_GET["token"]);  // vulnerability: accepts token from URL
}
```

**To confirm:** Check cookie value in DevTools after visiting the crafted URL. If `PHPSESSID` = `AttackerSpecifiedValue`, it's exploitable.

---

## 7. Session puzzling — premature session population

**What it is:** The server stores session variables (e.g., `Username`, `Active=true`) before the login check completes. If the login fails, the redirect to `?failed=1` is what cleans them up. Dropping the redirect keeps the populated session variables, bypassing auth.

**Detection signal:** Failed login redirects to `?failed=1` but the error page includes the username typed in the login form (meaning the username was stored in session to display it). Confirm by sending `GET /login.php?failed=1` without a session cookie — if the username disappears from the error message, session variables were used.

**Exploitation steps:**
1. Send a POST to `/login.php` with `username=admin&password=wrongpassword` in Burp.
2. Server responds with `302 Location: /login.php?failed=1` and sets a session cookie.
3. **Drop the redirect.** Do NOT follow it. Take the session cookie from step 2.
4. Directly `GET /profile.php` (or whatever the post-login page is) using that session cookie.
5. If the app checks `$_SESSION['Username']` or `$_SESSION['Active']` to determine auth, and those were already set before the password check, you are authenticated as `admin`.

**Burp steps:** In Proxy, turn off "Follow redirects". Intercept the POST login response → copy the `Set-Cookie` value → manually send `GET /profile.php` with that cookie.

---

## 8. Session puzzling — common session variable reuse (auth bypass)

**What it is:** A multi-step password reset (or other flow) sets the same session variable that the login check uses to determine authentication. Trigger the reset for `admin` → navigate directly to the protected page.

**Detection:** Map all multi-step flows. For each, strip the session cookie and re-send the second/third step request — if the server redirects you to login without the cookie, the flow uses session variables. Then check: does the password reset step 1 (`/reset_1.php`) set a `Username` variable? Does `/profile.php` check only for `isset($_SESSION['Username'])`?

**Exploitation steps:**
1. Click "Forgot Password?" and submit `admin` as the username.
2. Do NOT answer the security question — instead, navigate directly to `/profile.php`.
3. If the app logged you in as admin, the reset step 1 populated the `Username` session variable, and the auth check just validates that it's set.

**Key PHP pattern:**
```php
// reset_1.php — sets Username in session
$_SESSION['Username'] = $_POST['Username'];

// profile.php — only checks if Username is set
if(!isset($_SESSION['Username'])) { header("Location: login.php"); exit; }
```

---

## 9. Session puzzling — cross-flow phase confusion (account takeover)

**What it is:** Two different multi-step flows (e.g., registration and password reset) use the same `Phase` session variable to track progress. Interleaving them allows skipping the security question.

**Detection:** Look for multi-step flows with matching URL structures:
- `/register_1.php`, `/register_2.php`, `/register_3.php`
- `/reset_1.php`, `/reset_2.php`, `/reset_3.php`

Confirm both use the same session-stored `Phase` variable by: starting reset step 1 for `admin`, then completing registration steps 1–2, then accessing `/reset_3.php` directly.

**Exploitation steps:**
1. POST to `/reset_1.php` with `username=admin` — this sets `$_SESSION['reset_username'] = 'admin'` and `$_SESSION['Phase'] = 2`. Take note of the session cookie.
2. Using the same session, POST to `/register_1.php` (any dummy data) — this sets `$_SESSION['Phase'] = 2`.
3. POST to `/register_2.php` (any dummy data) — this advances `$_SESSION['Phase'] = 3`.
4. POST to `/reset_3.php` with `password=NewPassword` — phase check passes (3 == 3), password is reset for admin.

**Net result:** Full account takeover of `admin` without knowing their security question answer.

---

## 10. Session token in URL

**Detection:** Look for `?PHPSESSID=`, `?session=`, `?token=`, `?sid=` in any URL. Also check if any page loads external resources (images, fonts, analytics) — if it does AND the session is in the URL, the full session token appears in `Referer` headers sent to those external hosts.

**Test:** Browse the app and check for these parameters in requests captured in Burp proxy.

**Impact:** Session leaks via Referer to third parties, browser history, server logs. Report as medium severity minimum.

---

## 11. Second-order session issues

These don't fire immediately but appear after a sequence of actions:

- **Logout doesn't destroy session:** After logout, try using the old session cookie. If the app still honors it, the session was not invalidated.
  ```bash
  curl -s -b "PHPSESSID=<old_value>" https://target.com/profile.php | grep -i "logged in"
  ```
- **Session not regenerated on privilege change:** Log in as regular user, note session ID. Escalate privileges (via IDOR, parameter mod, etc.), note session ID again. If it's the same, session fixation risks exist if the old ID was shared.
- **Session fixation → CSRF double-submit bypass:** If the app uses a double-submit cookie pattern (same random value as both CSRF cookie and request param) and session fixation exists, an attacker can fix both the session AND the CSRF cookie, then forge valid CSRF requests.
  ```
  POST /change_password
  Cookie: CSRF-Token=fixed_token; PHPSESSID=AttackerFixedSession
  POST body: new_password=pwned&CSRF-Token=fixed_token
  ```

---

## 12. Bypass techniques

- **Encoding bypass for session value:** If server validates the cookie value, try URL-encoding: `%41%74%74%61%63%6B%65%72` for `Attacker`.
- **Session variable default values:** Logout logic may set `user_id = 0` instead of destroying the session. If `user_id=0` is the admin, logging in and then logging out may authenticate you as admin.
- **Cookie scope bypass:** If cookie has `Domain=.target.com`, any subdomain (including XSS-vulnerable or attacker-controlled subdomains) can read/set the cookie.
- **Path confusion:** Narrow path cookies (`Path=/admin`) may not be sent on API paths (`/api/`) — worth checking if the API uses a different auth mechanism.

---

## 13. False-positive checks

- **Short token but no active sessions:** A 4-char token is theoretically brute-forceable but meaningless if there are no other active users. Confirm by actually finding a valid session with different content.
- **Session ID in URL but no external resources loaded:** No Referer leak if no external requests are made from that page. Still reportable but lower impact.
- **Cookie missing `Secure` flag but no HTTP endpoint:** If the app enforces HTTPS everywhere (HSTS, no HTTP listener), the missing `Secure` flag is informational only.
- **Session fixation but no `token` parameter accepted:** Verify the URL param actually sets the cookie — test this explicitly before claiming the vulnerability.
- **Same session ID in dev/staging:** Don't assume the same vuln exists in prod without confirming.

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Weak session ID (low entropy) → brute-force all active sessions | — | Mass ATO of all logged-in users |
| Session fixation → full ATO | `auth-bypass` | High-impact ATO without credential theft |
| Session puzzling (premature population) → admin auth bypass | `auth-bypass` | Admin access without credentials |
| Session variable reuse (cross-flow) → password reset ATO | `auth-bypass` | ATO of any account including admin |
| Session token missing `HttpOnly` → XSS → cookie theft | `xss` | ATO via XSS exfil |
| Session token in URL → Referer leak to analytics/CDN | `ssrf` (if fetched server-side) | Session leak to third party |
| Session fixation + double-submit CSRF token | `csrf` | CSRF protection bypass |
| Base64 session token with `role=user` → tamper to `role=admin` | `auth-bypass`, `idor` | Instant privilege escalation |
| Session not invalidated post-logout → replay attack | — | Session persistence after victim logout |

---

## 15. Reporting template

```
POTENTIAL FINDING: <Session Fixation | Weak Session ID | Session Puzzling — Premature Population | Session Puzzling — Variable Reuse | Session Token in URL | Cookie Attribute Misconfiguration>
Target: <full URL>
Parameter/Cookie: <cookie name or URL param>
Evidence:
    <e.g., "Supplied PHPSESSID=AttackerValue in URL; server echoed it back in Set-Cookie" |
     "Token decodes to user=htb-stdnt;role=user via base64 -d" |
     "Burp Sequencer: 14 bits effective entropy on 1111 samples" |
     "After logout, original session cookie still returns 200 on /profile.php">
Exploitation method:
    <step-by-step that was executed>
Impact:
    <e.g., "Full account takeover of any user without credentials" |
     "Admin panel access via phase confusion in registration + reset flow" |
     "Cookie readable by JS — XSS can exfiltrate session">
Chain potential: <list other skills/findings combined>
Next step: <e.g., "Confirm on second test account", "Build Sequencer wordlist and run ffuf", "Attempt cross-flow phase confusion against admin account">
```

---

## 16. Recon tracker vector strings

Only log if the user explicitly authorizes (CLAUDE.md hard rule):

- `session:fixation:<param>` — session fixation via named URL parameter
- `session:weak-id:entropy-<N>bits` — low entropy confirmed via Sequencer
- `session:cookie-no-httponly` — HttpOnly missing
- `session:cookie-no-secure` — Secure flag missing
- `session:cookie-samesite-none` — SameSite=None (CSRF risk)
- `session:in-url:<param>` — session token exposed in URL
- `session:puzzling:premature-population` — auth bypass via dropped redirect
- `session:puzzling:shared-var-authbypass` — reset flow populates login session var
- `session:puzzling:cross-flow-ato` — registration/reset Phase variable shared
- `session:encoded-token-no-sig` — base64/hex-encoded role data with no HMAC

---

## 17. What NOT to do

- **Do not brute-force session IDs at high concurrency against production.** Session brute-forcing is high-volume. Confirm rate limits first. Use `-t 5` or lower in ffuf.
- **Do not log real user session cookies** beyond the minimum needed to prove the vulnerability.
- **Do not test session fixation by sending fixation links to real users.** Create two test accounts to verify the full chain.
- **Do not declare "session puzzling" without confirming the session variable is actually shared.** Confirm by observing the exact session behavior — access the protected page with the session from the non-login flow and verify the response content.
- **Do not report missing cookie flags as critical in isolation** — always assess the actual exploitability (is there an XSS to exploit missing HttpOnly? is there an HTTP endpoint to exploit missing Secure?).
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not leave test sessions active** after verifying the vulnerability — note what you did and clean up if possible.
