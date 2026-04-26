---
name: js-analysis
description: JavaScript file analysis for bug bounty recon — extract API endpoints, hardcoded secrets/tokens/keys, hidden parameters, internal URLs, auth patterns, and source map exposure. Invoke during /recon for every JS file discovered, or manually when analyzing a specific JS file.
---

# JavaScript Analysis

Analyze JS files to extract attack surface that isn't visible from normal browsing. Read top to bottom on first invocation.

---

## 1. Fetching the file

```bash
curl -s "https://TARGET/path/to/file.js" -o /tmp/target.js
```

For minified bundles, also check for source maps:
```bash
curl -sI "https://TARGET/path/to/file.js.map"
```

A 200 on the `.map` file is a significant finding — source maps expose the original unminified source code including comments, variable names, and file paths. Flag it and fetch it.

---

## 2. API endpoint extraction

Grep for fetch, axios, XHR, and URL patterns:

```bash
# fetch() and axios calls
grep -oE "(fetch|axios\.(get|post|put|delete|patch))\(['\`\"][^'\`\"]*['\`\"]" /tmp/target.js

# String paths that look like API routes
grep -oE "['\`\"][/][a-zA-Z0-9/_-]{3,}['\`\"]" /tmp/target.js | sort -u

# Absolute URLs
grep -oE "https?://[a-zA-Z0-9._/-]+" /tmp/target.js | sort -u

# API version patterns
grep -oE "/api/v[0-9]+/[a-zA-Z0-9/_-]+" /tmp/target.js | sort -u

# GraphQL
grep -oiE "(query|mutation|subscription)\s+\w+" /tmp/target.js | sort -u
grep -oE "/graphql['\`\"]" /tmp/target.js
```

Flag any internal hostnames, non-production URLs (staging, dev, internal), or undocumented API paths.

---

## 3. Secrets and credentials

```bash
# Generic API key patterns
grep -oiE "(api_?key|apikey|api-key|secret|token|password|passwd|pwd|auth)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/=_-]{8,}" /tmp/target.js

# AWS
grep -oE "AKIA[0-9A-Z]{16}" /tmp/target.js
grep -oiE "aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]" /tmp/target.js

# JWT tokens (hardcoded)
grep -oE "eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*" /tmp/target.js

# Generic high-entropy strings (potential secrets)
grep -oE "['\"][a-zA-Z0-9+/]{32,}['\"]" /tmp/target.js | sort -u

# Private keys
grep -i "BEGIN.*PRIVATE KEY" /tmp/target.js

# OAuth client IDs / secrets
grep -oiE "(client_?id|client_?secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9._-]{8,}" /tmp/target.js
```

Any hardcoded credential is an immediate finding — flag it with the exact line.

---

## 4. Hidden parameters and inputs

```bash
# Parameters passed in requests
grep -oE "(['\`])([\w_-]+)=['\"]\1" /tmp/target.js | sort -u

# Form field names
grep -oiE "name=['\"][a-zA-Z0-9_-]+['\"]" /tmp/target.js | sort -u

# Object keys that look like API parameters
grep -oE "\b(userId|user_id|account_id|accountId|token|role|admin|isAdmin|verified|debug)\b" /tmp/target.js | sort -u
```

Hidden or undocumented parameters are mass assignment and IDOR candidates.

---

## 5. Internal and non-production infrastructure

```bash
# Internal hostnames
grep -oE "https?://[a-zA-Z0-9._-]+\.(internal|local|corp|intranet|staging|dev|test|qa)[a-zA-Z0-9/_-]*" /tmp/target.js

# Private IP ranges
grep -oE "https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9./]+" /tmp/target.js

# localhost / 127.x
grep -oE "https?://(localhost|127\.0\.0\.[0-9]+)" /tmp/target.js

# Non-HTTPS URLs (potential mixed content / downgrade)
grep -oE "http://[a-zA-Z0-9._/-]+" /tmp/target.js | grep -v localhost | sort -u
```

Internal URLs in client-side JS are SSRF candidates and may reveal internal architecture.

---

## 6. Auth and token handling patterns

```bash
# localStorage / sessionStorage — token storage patterns
grep -oiE "localStorage\.(setItem|getItem)\(['\"][^'\"]*token[^'\"]*['\"]" /tmp/target.js
grep -oiE "sessionStorage\.(setItem|getItem)\(['\"][^'\"]*['\"]" /tmp/target.js

# Cookie manipulation
grep -oiE "document\.cookie\s*=" /tmp/target.js

# Authorization headers being set
grep -oiE "Authorization.*Bearer" /tmp/target.js

# postMessage usage (potential DOM XSS vector)
grep -oiE "(window\.)?postMessage\s*\(" /tmp/target.js
grep -oiE "addEventListener\(['\"]message['\"]" /tmp/target.js
```

`postMessage` without origin validation is a DOM XSS / data exfiltration vector — flag for the `xss` skill.

---

## 7. Webpack / bundler analysis

If the file is a webpack bundle:

```bash
# Module list in bundle
grep -oE "\"[./a-zA-Z0-9_-]+\.(js|ts|jsx|tsx)\"" /tmp/target.js | sort -u

# Check for .map reference at the bottom
tail -3 /tmp/target.js | grep sourceMappingURL
```

If `sourceMappingURL` points to a `.map` file, fetch it:
```bash
curl -s "https://TARGET/path/to/file.js.map" | python3 -m json.tool | grep '"sources"' -A 20
```

The `sources` array in a source map lists every original file in the application — this is a full directory disclosure.

---

## 8. Dangerous sinks (DOM XSS candidates)

```bash
grep -oiE "(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*=" /tmp/target.js
grep -oiE "eval\s*\(" /tmp/target.js
grep -oiE "setTimeout\s*\(['\`]" /tmp/target.js
grep -oiE "setInterval\s*\(['\`]" /tmp/target.js
grep -oiE "location\.(href|assign|replace)\s*=" /tmp/target.js
```

Any of these receiving user-controlled input is a DOM XSS candidate — invoke the `xss` skill.

---

## 9. Output format

After analyzing a JS file, summarize:

```
JS Analysis: [filename]

Endpoints found: [list]
Secrets/tokens: [any hits — exact values redacted in summary, full value noted for reporting]
Hidden params: [list]
Internal URLs: [list]
Auth patterns: [localStorage/cookie/header observations]
DOM sinks: [list if any]
Source map: [exposed / not found]

Notable: [anything that warrants immediate follow-up]
```

Flag anything that warrants running HauntMode or invoking a specific skill.

---

## 10. Chain candidates

| Finding | Next skill | Impact |
|---|---|---|
| API endpoints not visible in Burp | HauntMode on those endpoints | Undiscovered attack surface |
| Hardcoded API key/token | `info-disclosure` | Direct credential exposure |
| Internal hostname | `ssrf` | Internal network access |
| `postMessage` without origin check | `xss` | DOM XSS / data theft |
| DOM sinks with user input | `xss` | DOM XSS |
| Source map exposed | `info-disclosure` | Full source disclosure |
| JWT token hardcoded | `auth-bypass` | Authentication bypass |
| Hidden admin/role params | `mass-assignment`, `idor` | Privilege escalation |
