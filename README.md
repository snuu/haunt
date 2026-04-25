# Haunt

![Haunt](haunt.jpeg)

A Claude Code project for bug bounty hunters. Intercept a request in Burp, paste it in — get a full 38-category vulnerability analysis with real payloads, tool commands, and chain analysis.

Haunt is built around the way bug bounty actually works: you run your own recon, browse the target manually, and capture traffic in Burp. The more context you bring — live hosts, intercepted requests, JS endpoints, error responses — the sharper the analysis. Think of it as a senior collaborator sitting next to you who knows every vuln class cold and can immediately tell you what's worth chasing in a given request.

---

## How it works

Haunt uses Claude Code's skill system to load vulnerability-specific methodology on demand. When you paste a request and trigger HauntMode, Claude:

1. Reads `INDEX.md` — maps every vuln category to its skill slug
2. Reads `HAUNT_CHECKLIST.md` — loads the full analysis protocol
3. Evaluates all 38 checklist categories against the request
4. Invokes the skill file for each applicable vulnerability
5. Produces a prioritized attack plan with exact payloads and `[RUN THIS]` tool commands

Each of the 37 skill files covers one vulnerability class end-to-end: detection, confirmation, exploitation, filter bypass techniques, tool commands, chain candidates, and a reporting template.

---

## Recommended workflow

**1. Recon first (you run these)**
```bash
subfinder -d target.com -o domains.txt
httpx -l domains.txt -o httpx-live.txt
katana -list httpx-live.txt -o endpoints.txt
```

**2. Browse manually**
Open Burp, create an account, walk through the app. Capture login flows, API calls, file uploads, profile updates, anything that looks interesting. Let Burp build a history of the target.

**3. Feed Claude**
Open Claude from your program folder. Give it `httpx-live.txt` and ask for a target prioritization. Claude reads the live hosts, maps the attack surface, and tells you what to focus on.

**4. HauntMode — deep request analysis**
Copy any request from Burp and ask Claude to run the checklist. Claude dissects every parameter, header, cookie, and body field across all 38 vuln categories, invokes the relevant skill for each, and returns a prioritized attack plan with exact payloads.

---

## Prerequisites

- [Claude Code](https://claude.ai/code) with an active subscription
- Burp Suite (Community Edition works)
- [Burp MCP server](https://github.com/PortSwigger/mcp-server) — install the extension in Burp and enable it
- An ezXSS instance for OOB blind testing — [self-host](https://github.com/ssl/ezXSS) or use a collaborator alternative
- Kali Linux or equivalent (standard pentesting tools assumed: ffuf, sqlmap, httpx, subfinder, etc.)

---

## Setup

```bash
git clone https://github.com/snuu/haunt
cd haunt
```

**Configure your OOB domain:**
Edit `CLAUDE.md` and `HAUNT_CHECKLIST.md`, replacing `YOUR_EZXSS_DOMAIN` with your ezXSS instance URL.

**Verify your tools:**
```bash
bash preflight.sh
```

---

## Starting an engagement

Scaffold a new program folder:
```bash
bash new-program.sh acme-corp
```

This creates `programs/acme-corp/` with stub files for:
- `program-guidelines.txt` — scope, rate limits, required headers, out-of-scope items
- `scope.txt` — one domain or wildcard per line
- `httpx-live.txt` — paste your httpx output here

Open `headers.conf` and fill in your required headers and rate limit:

```
X-Bugbounty: yourhandle
User-Agent: Mozilla/5.0 (BugBounty/yourhandle)

RATE_LIMIT=30
```

Claude reads this file at the start of every session and appends those headers to every request it makes. The rate limit caps how many requests per minute Claude will send — set it to whatever the program allows.

Then run httpx against your scope and open Claude from inside that folder:
```bash
cd programs/acme-corp
claude
```

Claude picks up the program context automatically.

---

## HauntMode

Copy any raw HTTP request from Burp, paste it into the conversation, and ask Claude to run the checklist:

```
POST /api/v2/user/update HTTP/1.1
Host: app.target.com
Cookie: session=abc123
Content-Type: application/json

{"username":"test","email":"test@example.com"}

run the checklist
```

Claude will:
- Dissect every parameter, header, cookie, and body field
- Fingerprint the tech stack
- Evaluate all 38 checklist categories
- Invoke the relevant skill for each applicable category
- Return a prioritized attack plan with exact payloads and chain analysis

---

## Skills

All 37 skills live in `.claude/skills/`. Each covers one vulnerability class:

`sqli` `nosqli` `cmdi` `xss` `csrf` `ssrf` `ssti` `lfi` `file-upload` `xxe` `idor` `auth-bypass` `session-attacks` `verb-tampering` `mass-assignment` `prototype-pollution` `deserialization` `crlf` `request-smuggling` `cache-poisoning` `cors` `websocket` `xpath` `ldap` `ssi-esi-xslt` `pdf-injection` `open-redirect` `race-conditions` `type-juggling` `param-logic` `business-logic` `second-order` `api-attacks` `info-disclosure` `wordpress` `dns-rebinding` `ajp-proxy`

---

## Responsible use

Haunt is for authorized security testing on programs you're enrolled in. Always verify you're within scope, respect rate limits defined in program guidelines, and follow responsible disclosure.

---

## License

MIT
