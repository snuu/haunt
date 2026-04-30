# Haunt

![Haunt](assets/haunt.jpeg)

A Claude Code project for bug bounty hunters. Intercept a request in Caido, paste it in — get a full 38-category vulnerability analysis with real payloads, tool commands, and chain analysis.

Haunt is built around the way bug bounty actually works: you run your own recon, browse the target manually, and capture traffic in Caido. The more context you bring — live hosts, intercepted requests, JS endpoints, error responses — the sharper the analysis. Think of it as a senior collaborator sitting next to you who knows every vuln class cold and can immediately tell you what's worth chasing in a given request.

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
Open Caido, create an account, walk through the app. Capture login flows, API calls, file uploads, profile updates, anything that looks interesting. Let Caido build a history of the target.

**3. Feed Claude**
Open Claude from your program folder. Give it `httpx-live.txt` and ask for a target prioritization. Claude reads the live hosts, pulls Caido proxy history via MCP, maps the attack surface, and tells you what to focus on.

**4. HauntMode — deep request analysis**
Tell Claude to pull from Caido history directly, or drop in a specific request manually. Claude dissects every parameter, header, cookie, and body field across all 38 vuln categories, invokes the relevant skill for each, and returns a prioritized attack plan with exact payloads.

---

## Prerequisites

- [Claude Code](https://claude.ai/code) with an active subscription
- [Caido](https://caido.io) with the [Vibe Hacking MCP plugin](https://github.com/caido-community/vibe-hacking) installed and running on `http://127.0.0.1:3333/mcp`
- An ezXSS instance for OOB blind XSS — [self-host](https://github.com/ssl/ezXSS) or use a collaborator alternative
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

## Caido MCP

With the Vibe Hacking MCP plugin running, Claude has direct access to Caido — no copying or exporting needed. You can ask Claude to:

- Pull proxy history and identify the most interesting requests (`query-requests`)
- Filter history by host, path, method, or status code
- Send requests directly and analyze the response (`send-request`)
- Create replay sessions for iterative testing (`create-replay-session` / `start-replay-task`)
- Auto-inject required headers on all requests via tamper rules (`create-tamper-rule`)
- Log confirmed findings into Caido's built-in tracker (`create-finding`)
- Host OOB payload files through Caido's server (`create-hosted-file`)
- Read WebSocket traffic (`list-websocket-streams` / `list-websocket-messages`)

This makes the workflow fully live — Caido captures traffic as you browse, Claude reads it directly via MCP.

---

## HauntMode

Trigger with `/hauntmode`. Three modes:

**Single request** — drop in a raw request and run:
```
/hauntmode

POST /api/v2/user/update HTTP/1.1
Host: app.target.com
Cookie: session=abc123
Content-Type: application/json

{"username":"test","email":"test@example.com"}
```

**Caido history** — pull directly from your proxy, no copying needed:
```
/hauntmode caido api.target.com POST
```
Filters by host and method. Omit either to broaden the pull.

**Batch file** — gather requests into a file separated by `---`, then:
```
/hauntmode requests.txt
```

For batch and Burp modes, HauntMode triages first — ranks requests by attack surface and interest, shows you the list, and waits for you to confirm which ones get the full treatment.

**Dupe tracking** — every analyzed request is logged to `reports/hauntmode-log.md` as a single line (`METHOD HOST PATH | findings`). Already-analyzed requests are skipped automatically so you never duplicate work across sessions.

**Volume cap** — if a Burp pull or batch file returns more than 25 unanalyzed requests, HauntMode stops and asks how many you want to tackle first. Bug bounty rewards depth over speed — work through requests in focused batches rather than burning through everything at once.

**Findings and leads** — confirmed vulnerabilities go to `reports/findings.md`, things that need follow-up go to `reports/leads.md` as one-liners. Both persist across context compactions so nothing gets lost in a long session.

---

## Reports

Every program folder gets a `reports/` directory. Claude writes to it automatically — no prompting needed:

| File | Contents |
|---|---|
| `findings.md` | Confirmed or high-confidence vulnerabilities — full detail |
| `leads.md` | One-liners for things that need follow-up but aren't confirmed yet |
| `hauntmode-log.md` | One line per analyzed request — tracks what's been covered |
| `recon.md` | Attack surface map output from `/recon` |

Tracking is always on — not just during HauntMode. If Claude spots something interesting during normal conversation it writes it too.

---

## Slash commands

| Command | What it does |
|---|---|
| `/recon` | Full attack surface mapping — reads `httpx-live.txt`, pulls Caido history, fingerprints tech, probes common paths, discovers and analyzes JS files, outputs a prioritized target list to `reports/recon.md` |
| `/recon app.target.com` | Same but focused on a single host |
| `/hauntmode` | Full 38-category analysis on a single request (pasted or from Caido history) |
| `/hauntmode caido api.target.com POST` | Pull matching requests from Caido history, triage, then analyze |
| `/hauntmode requests.txt` | Batch analysis from a file of requests separated by `---` |

---

## Skills

All 38 skills live in `.claude/skills/`. Each covers one vulnerability class:

`sqli` `nosqli` `cmdi` `xss` `csrf` `ssrf` `ssti` `lfi` `file-upload` `xxe` `idor` `auth-bypass` `session-attacks` `verb-tampering` `mass-assignment` `prototype-pollution` `deserialization` `crlf` `request-smuggling` `cache-poisoning` `cors` `websocket` `xpath` `ldap` `ssi-esi-xslt` `pdf-injection` `open-redirect` `race-conditions` `type-juggling` `param-logic` `business-logic` `second-order` `api-attacks` `info-disclosure` `wordpress` `dns-rebinding` `ajp-proxy` `js-analysis`

---

## Responsible use

Haunt is for authorized security testing on programs you're enrolled in. Always verify you're within scope, respect rate limits defined in program guidelines, and follow responsible disclosure.

---

## License

MIT
