---
name: idor
description: Insecure Direct Object Reference — horizontal/vertical privilege escalation, encoded/hashed reference bypass, mass enumeration, API IDOR, second-order IDOR, GUID/UUID enumeration. Use when HauntMode flags IDOR as APPLIES/MAYBE, when requests contain object IDs (numeric, UUID, hash, base64), or when testing access control on resource-fetching and resource-modifying endpoints.
---

# IDOR — Insecure Direct Object Reference

This skill covers identification, exploitation, mass enumeration, hash/encoding bypass, second-order IDOR, API IDOR, and privilege escalation via object reference manipulation. Read top to bottom on first invocation; jump to the relevant section on subsequent runs.

---

## 1. Triggers — when this skill applies

- URL parameters containing numeric IDs: `?uid=1`, `?id=42`, `?invoice=1337`
- Path segments with IDs: `/api/users/1`, `/documents/1337/download`, `/profile/42/edit`
- POST/PUT body containing IDs: `{"user_id": 1, "document_id": 42}`
- Any parameter with an encoded-looking value: base64 strings, MD5-style hashes in resource references
- File download endpoints where file names contain user-identifying tokens
- API endpoints returning user data where the identifier is in the URL
- Hidden form fields or AJAX calls containing other users' object references
- "Recent activity", "preview", or "cache" features that display content fetched from an ID-controlled lookup
- UUID/GUID parameters — don't assume they're unguessable; check if they are predictable or leaked via other endpoints

---

---

## 3. 30-second triage

1. Find a request with a user-controlled ID (URL param, path segment, POST body, cookie).
2. Note the current resource belongs to the logged-in user.
3. Increment or modify the ID by ±1 (or try a known second test account's ID).
4. Compare: does the response contain different data? Same response size? Different user's name/email/content?
5. If different data returned → horizontal IDOR confirmed.
6. If the modified ID causes a permission error on some endpoints but not others → access control inconsistency, investigate which operations are unprotected.

**Skip deep dive if:**
- The ID is a cryptographically random UUID and you have no other way to learn other users' UUIDs (but check whether the UUID leaks in any other response — GET /users listing, error messages, email notifications, shared links).
- Every variation returns identical content and the same response size.

---

## 4. Horizontal vs vertical escalation

**Horizontal IDOR:** Accessing another user's resources at the same privilege level.
- `GET /api/user/2` while logged in as user 1 → returns user 2's profile data
- `GET /invoices/1338` → returns another user's invoice

**Vertical IDOR (privilege escalation):** Accessing admin-only resources or performing admin-only actions.
- `GET /api/admin/users` → no auth check, returns all users
- Modifying `role`, `isAdmin`, `group`, `permissions` fields in a PUT/PATCH request → accepted without server-side validation (overlaps with mass assignment — cross-invoke that skill)
- Accessing `/admin/panel?uid=1` while uid=1 is an admin and you are uid=2

Both types may exist on the same target — test for both.

---

## 5. Detection — mapping all object references

### 5.1 URL parameters and path segments

Check every endpoint for numeric, UUID, or encoded values:
```
GET /documents?uid=1
GET /api/v1/users/42/profile
GET /download?file=Invoice_1_09_2021.pdf
POST /messages/read  {"message_id": 1337}
```

Systematically test: change the value to another valid ID, an ID you know belongs to another account (use a second test account), or just increment by 1.

### 5.2 AJAX calls and JavaScript source

Look for hidden object references in front-end JS:
```javascript
// Example from notes — API call that may not be visible in normal UI flow
$.ajax({
    url:"change_password.php",
    type: "post",
    data: {uid: user.uid, password: user.password, is_admin: is_admin},
});
```

Search JS files for: `uid`, `user_id`, `account_id`, `doc_id`, `file_id`, `/api/`, `profile/`, `invoice/`.

### 5.3 Response differential — blind IDOR signals

Even if the content looks identical, check:
- **Response body size** — different sizes indicate different data returned
- **Response timing** — significant timing difference can indicate different DB query paths
- **Field values** — subtle differences in timestamps, IDs, or names in the JSON body

If changing the ID returns a generic response but with slightly different size → enumerate and compare sizes to identify hits.

### 5.4 Cookie-based object references

Some apps pass the object reference in a cookie rather than the URL:
```
Cookie: user_id=1; role=employee; document_context=42
```
Try modifying cookie values directly.

---

## 6. Hash/base64 reference cracking methodology

When a reference looks encoded or hashed (`?file=cdd96d3cc73d1dbdaffa03cc6cd7339b`):

**Step 1 — Identify the encoding/hash type:**
- Base64: character set `A-Za-z0-9+/=`, length divisible by 4 → `echo -n VALUE | base64 -d`
- MD5: 32 hex chars → try `echo -n CANDIDATE | md5sum`
- SHA1: 40 hex chars → `echo -n CANDIDATE | sha1sum`
- SHA256: 64 hex chars

**Step 2 — Find the source value:**
- Check the front-end JS for the hashing function: search for `CryptoJS`, `md5(`, `btoa(`, `sha1(`
- Common pattern: `md5(btoa(uid))` → `echo -n UID | base64 -w 0 | md5sum | tr -d ' -'`
- Try hashing: uid alone, username, email, filename, combinations

**Step 3 — Reproduce for other values:**
```bash
# Example: reference = md5(base64(uid)), enumerate uid 1..20
for i in {1..20}; do
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    echo "uid=$i -> hash=$hash"
done
```

**Step 4 — Mass download:**
```bash
for i in {1..20}; do
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    curl -sOJ -X POST -d "contract=$hash" "https://TARGET.com/download.php"
done
```

---

## 7. Mass enumeration

When IDs are sequential integers, use ffuf or a bash loop.

**Bash loop (quick, no tools):**
```bash
for i in {1..500}; do
    result=$(curl -s -b "PHPSESSID=YOUR_SESSION" "https://TARGET.com/documents.php?uid=$i" | grep -oP "\/documents.*?\.pdf")
    [ -n "$result" ] && echo "uid=$i: $result"
done
```

**ffuf (give as [RUN THIS] block):**

[RUN THIS]
```
ffuf -u "https://TARGET.com/api/users/FUZZ" \
  -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -H "Cookie: PHPSESSID=YOUR_SESSION_HERE" \
  -H "Accept: application/json" \
  -mc 200 \
  -fs SIZE_OF_YOUR_OWN_PROFILE_RESPONSE
```

Replace `SIZE_OF_YOUR_OWN_PROFILE_RESPONSE` with the byte count of your own profile response (to filter it out). Hits with different sizes are other users' data.

**Python script for hash-based enumeration:**
```python
import hashlib, requests

URL = "https://TARGET.com/file.php"
COOKIE = {"PHPSESSID": "YOUR_SESSION_HERE"}

for file_id in range(1000):
    id_hash = hashlib.md5(str(file_id).encode()).hexdigest()
    r = requests.get(URL, params={"file": id_hash}, cookies=COOKIE)
    if "File does not exist" not in r.text and "Access denied" not in r.text:
        print(f"Found file with id: {file_id} -> {id_hash}")
```

---

## 8. API IDOR patterns

APIs are often less carefully access-controlled than UI pages. For every API endpoint:

**GET (information disclosure):**
```
GET /api/v1/users/2          → returns other user's full profile, email, UUID
GET /api/v1/orders/1338      → returns other user's order details
GET /api/v1/invoices?user=2  → filter bypass
```

**PUT/PATCH (function call — modify other user's data):**
```
PUT /api/v1/users/2
{"email": "attacker@evil.com", "full_name": "OWNED"}
```
First use GET to obtain the victim's `uuid` (IDOR info disclosure), then use it in a PUT to modify their record.

**Chain pattern — info disclosure → insecure function call:**
1. `GET /api/users/FUZZ` → find all users and their UUIDs
2. Find the admin user's UUID in the responses
3. `PUT /api/users/ADMIN_ID` with `"role": "web_admin"` in the body → check if accepted
4. If the role is accepted, refresh your cookie and access admin functionality

**Hidden fields in PUT/POST bodies that should not be user-controlled:**
- `role`, `isAdmin`, `admin`, `group_id`, `permissions`, `verified`, `active`, `balance`, `price`
- Send these extra fields in the request body — if the server accepts and applies them, that's mass assignment (invoke `mass-assignment` skill)

---

## 9. Second-order IDOR

A second-order IDOR occurs when:
1. You attempt to access resource X (direct access is blocked by access control)
2. The attempt is stored somewhere (recently-viewed, audit log, activity preview)
3. That stored reference is later rendered without a re-check of authorization

**Detection pattern:**
1. Attempt to access another user's resource (expect an "Access Denied" response)
2. Navigate to your own profile/activity feed/dashboard
3. Check if any preview, thumbnail, or cached content of the other user's resource appears

**Real example from notes:** Accessing `/file.php?file=OTHER_USER_HASH` returns "Access Denied", but the file content briefly appears in the "recently accessed" preview on `/profile.php` — the access control check only runs on `/file.php`, not on the profile page's preview query.

**Blackbox methodology:**
1. Map all features that display previews, summaries, or cached views of resources
2. For each, try accessing a resource belonging to another user via the primary endpoint (expect failure)
3. Check if any secondary display location (dashboard, notification, activity log) renders the resource without re-checking auth

---

## 10. GUID/UUID IDOR

Do not assume GUIDs are unguessable. Test:
1. Does any API response leak other users' GUIDs? (GET /api/users, team listings, shared-document participants, email notifications with IDs in links)
2. Are GUIDs version 1 (time-based, predictable sequence)? Check with: `python3 -c "import uuid; u=uuid.UUID('GUID_HERE'); print(u.version)"`
3. Does the app use UUIDs generated from sequential seeds? Try adjacent UUIDs.
4. Do public-facing share links or exported files reveal UUIDs of other users' objects?

---

## 11. Confirmation

An IDOR is confirmed when you can demonstrate access to or modification of a resource you should not have access to, using only your own authenticated session.

Best practice for reporting:
- Use two separate accounts (attacker and victim) with different UIDs
- Show the request made from Account A accessing/modifying Account B's resource
- Show the response containing Account B's private data, or demonstrate the modification took effect on Account B's profile

---

## 12. Bypass techniques — when initial tests return 403/401

- **Try different HTTP methods:** GET returns 403, try POST/PUT/PATCH to the same URL — different codepaths may have different auth checks (cross-invoke `verb-tampering` skill)
- **Swap the resource ID in the path vs body:** If `/api/users/2` is blocked, try `/api/users/1` with `{"uid": 2}` in the body
- **Add header overrides:** `X-Original-URL: /admin/users`, `X-Rewrite-URL: /api/users/2`, `X-Forwarded-For: 127.0.0.1`
- **Path traversal in ID:** `/api/users/1/../2`, `/api/users/1%2F..%2F2`
- **Wildcard:** `/api/users/*`, `/api/users/%00` — some frameworks handle null bytes oddly
- **Case variation:** `/API/USERS/2` vs `/api/users/2` — different routing may skip middleware

---

## 13. False-positive checks

- Verify the response actually contains the OTHER user's data, not just your own re-delivered. Check email addresses, names, content that is unique to the victim account.
- Confirm the ID you tested actually belongs to a different user — if you share a resource with that user (shared document, team account), access is expected.
- Some apps return HTTP 200 with an error body — check the response body, not just the status code.
- "Access Denied" in JSON with status 200 is a block, not an IDOR.
- GUID enumeration: confirm the leaked GUID was not intentionally public (public profile URLs, shared links are expected to be accessible).

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| IDOR info disclosure → leaked UUID → IDOR function call | (same skill, chain within IDOR) | Full ATO chain |
| IDOR + mass enumeration → PII dump | (standalone finding) | High/Critical depending on PII type |
| IDOR on profile field edit → inject XSS payload into victim profile | `xss` | Stored XSS in victim's profile |
| IDOR on email field → change victim email → password reset ATO | `auth-bypass` | Full account takeover |
| IDOR → read admin UUID → IDOR function call to set own role to admin | `mass-assignment` | Privilege escalation |
| IDOR via AJAX hidden endpoint → API endpoint previously unknown | `api-attacks` | Expanded attack surface |
| IDOR on file download → LFI if path traversal accepted in ID | `file-inclusion` | Server-side file read |
| Second-order IDOR → data leaks through preview/dashboard render | (standalone) | Info disclosure with escalation potential |

---

## 15. Reporting template

```
POTENTIAL FINDING: Insecure Direct Object Reference — <Horizontal | Vertical | API | Second-Order>
Target: <full URL of vulnerable endpoint>
Parameter: <parameter name + location: path/query/body/cookie>
Reference type: <sequential integer | base64 | md5 hash | UUID>
Attack account: <your test account identifier>
Victim account: <the victim account's ID or identifier accessed>
Working request:
    <exact HTTP method + URL + relevant headers + body>
Response evidence:
    <excerpt of response showing victim's private data, or confirmation of modification>
Impact:
    <e.g. "Any authenticated user can read all other users' full profiles including email and phone">
    <e.g. "Attacker can change any user's email address, enabling password reset ATO">
    <e.g. "Attacker can enumerate all 500 user invoices via sequential ID fuzzing">
Chain potential: <e.g. "UUID leaked via GET /api/users enables exploitation of PUT /api/users/:id">
Next step: <confirm scope, demonstrate mass enumeration scale, build ATO PoC if email-change IDOR>
```

---

## 16. Recon tracker vector strings

Only log if user explicitly instructs (CLAUDE.md hard rule):

- `idor:horizontal:<endpoint>` — confirmed read access to another user's resource
- `idor:vertical:<endpoint>` — confirmed escalated-privilege access
- `idor:api-get:<endpoint>` — API GET returns other users' data
- `idor:api-put:<endpoint>` — API PUT/PATCH modifies other users' data
- `idor:encoded:<algorithm>` — encoded reference cracked (note algorithm)
- `idor:second-order:<trigger>:<display>` — second-order IDOR via named display location
- `idor:mass-enum:<range>` — mass enumeration confirmed with range and count of records
- `idor:no:<endpoint>` — tested, access control working — avoid re-testing

---

## 17. What NOT to do

- Do not mass-enumerate in a way that exceeds program rate limits — re-read `program-guidelines.txt` before running loops or ffuf
- Do not access more victim data than is necessary to confirm the vulnerability — one record is sufficient to prove IDOR; do not dump the entire database
- Do not modify victim account data without restoring it — if you change an email to confirm IDOR, change it back immediately after capture of the evidence
- Do not report IDOR on intentionally public endpoints (public profiles, shared document links) without confirming the data is actually intended to be private
- Do not assume UUID = not-IDOR — always check for UUID leakage in other endpoints before dismissing
- Do not auto-log to the recon tracker without explicit user instruction
- Do not test on out-of-scope domains — verify `scope.txt` before any request
