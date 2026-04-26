---
description: Attack surface mapping for a program or host. Reads httpx-live.txt, pulls Burp history, fingerprints tech, discovers endpoints and JS files, and returns a prioritized target list. Usage: /recon | /recon app.target.com
---

You are running a recon pass. Arguments: $ARGUMENTS

---

## Step 0 — Setup

Read `headers.conf` if not already loaded. Read `scope.txt` so you know what's in bounds.

---

## Step 1 — Determine scope

**No arguments:** full program recon — work across all hosts in `httpx-live.txt`.

**Host argument (e.g. `app.target.com`):** focused recon on that host only.

---

## Step 2 — Build the host list

If `httpx-live.txt` exists, read it. Extract live hosts.

Pull Burp proxy history with `get_proxy_http_history` — note every unique host that appears. Add any not in httpx-live.txt to your working list (they were visited manually but may not have been in the httpx run).

Deduplicate. Filter to in-scope hosts only (check against `scope.txt`).

---

## Step 3 — Per-host fingerprinting

For each host (or the single target if argument was passed), run these curl probes. Include headers from `headers.conf` on every request.

**Headers and tech stack:**
```bash
curl -sI https://TARGET/ 
```
Note: Server, X-Powered-By, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, Set-Cookie names/flags, any custom headers. These fingerprint the stack and flag security misconfigurations.

**Quick-win paths:**
```bash
curl -s https://TARGET/robots.txt
curl -s https://TARGET/sitemap.xml
curl -s https://TARGET/.well-known/security.txt
curl -sI https://TARGET/.git/HEAD
curl -sI https://TARGET/.env
curl -sI https://TARGET/api/
curl -sI https://TARGET/graphql
curl -sI https://TARGET/swagger.json
curl -sI https://TARGET/api-docs
curl -sI https://TARGET/openapi.json
curl -sI https://TARGET/phpinfo.php
curl -sI https://TARGET/server-status
```

Flag anything that returns 200 or unexpected responses. A 200 on `.git/HEAD` or `.env` is an immediate finding — invoke the `info-disclosure` skill.

---

## Step 4 — JS file discovery and analysis

For each host, identify JavaScript files:

1. Pull the HTML source: `curl -s https://TARGET/`
2. Extract all `<script src="...">` references and inline scripts
3. Also check Burp history for any `.js` requests already captured
4. Fetch each JS file and invoke the `js-analysis` skill on it

The `js-analysis` skill will extract: API endpoints, hardcoded secrets/tokens, interesting parameters, internal URLs, and auth patterns.

---

## Step 5 — Burp history analysis

Pull Burp history for in-scope hosts. For each unique endpoint observed:

- Note the method, path, parameters, content-type, auth headers
- Flag: login/logout, password reset, registration, file upload, payment, admin, API versioning, OAuth/SSO flows, any endpoint with object IDs

Build a complete endpoint map per host.

---

## Step 6 — Output

Produce a structured recon report for `reports/recon.md` (append if exists, create if not).

Format:
```markdown
## Recon — TARGET — DATE

### Tech Stack
[headers, framework indicators, CDN, WAF if detected]

### Security Headers
[present / missing — flag missing CSP, HSTS, X-Frame-Options]

### Interesting Paths
[anything notable from quick-win probes]

### Endpoint Map
[grouped by functionality: auth, API, file ops, admin, etc.]

### JS Findings
[endpoints, secrets, tokens found in JS — see js-analysis output]

### Prioritized Targets
Ranked list of what to focus on:
1. [HIGH] endpoint — reason
2. [HIGH] endpoint — reason  
3. [MEDIUM] endpoint — reason
...

### Suggested next step
[what to run HauntMode on first]
```

Also present the prioritized targets in conversation so the user sees them immediately.

---

## Hard rules

- Only probe in-scope hosts — check scope.txt before every request
- Always include headers.conf headers on every curl
- Flag any 200 on sensitive paths (.git, .env, backup files) immediately as a potential finding
- Do not run ffuf, gobuster, or any fuzzer — those are [RUN THIS] commands for the user
- Invoke `js-analysis` skill for every JS file found — do not summarize JS manually
