---
description: Full 38-category vulnerability analysis on HTTP requests. Usage: /hauntmode | /hauntmode burp [host] [method] | /hauntmode <file>
---

You are running HauntMode. Arguments: $ARGUMENTS

---

## Step 0 — Setup

Read `headers.conf` if not already loaded this session. All curl commands must include those headers.

Ensure `reports/` exists. Create it if not.

---

## Step 1 — Determine mode from $ARGUMENTS

**No arguments or inline request follows:**
→ Single request mode. The request is either pasted in the message or in the Burp editor — use `get_active_editor_contents` if nothing was pasted.

**Arguments start with `burp`:**
→ Burp history mode. Parse optional filters from the remaining arguments (host, method). Examples:
- `burp` → pull all recent history
- `burp api.twilio.com` → filter by host
- `burp api.twilio.com POST` → filter by host + method
Call `get_proxy_http_history_regex` with the appropriate filter, or `get_proxy_http_history` for unfiltered.

**Arguments are a filename (e.g. `requests.txt`):**
→ Batch file mode. Read the file. Requests are separated by a line containing only `---`.

---

## Step 2 — Dupe check

Read `reports/hauntmode-log.md` if it exists.

For each request, compute its fingerprint: `METHOD HOST PATH` (strip query string, lowercase host).

- If fingerprint is already in the log: **skip it**. Do not re-run.
- If not in the log: queue it for analysis.

If all requests were already analyzed, tell the user and stop.

---

## Step 3 — Volume check (batch and Burp modes only)

Count the queued (non-duplicate) requests.

**If more than 25:**
```
That's a lot — X requests queued after skipping Y already analyzed.

Bug bounty rewards depth over speed. How many would you like to work through 
in this session? Suggested starting point: 10.
```
Wait for the user to specify a number. Take only that many from the top of the ranked list (after triage in Step 4). The rest stay unanalyzed and will be picked up next time.

**If 25 or fewer:** proceed without asking.

---

## Step 4 — Triage (batch and Burp modes only, skip for single)

For each queued request, rapid surface scan:
- Method, endpoint, parameters, content-type, auth mechanism
- Top 2-3 vuln classes most likely to apply
- Interest score: **High** (auth endpoints, file upload, SSRF candidates, API with object IDs, admin paths), **Medium** (standard CRUD, search, filters), **Low** (no params, static-ish)

Present ranked list:
```
Queued: X requests (Y skipped — already analyzed)

1. [HIGH]   POST api.target.com /api/v2/upload — file upload, URL param SSRF candidate
2. [HIGH]   PUT  api.target.com /api/v1/user/42 — IDOR + mass assignment surface
3. [MEDIUM] POST api.target.com /api/v1/search — SQLi/NoSQLi surface
...

Run full HauntMode on all, or specify which numbers? (default: High only)
```

Wait for confirmation before proceeding.

---

## Step 5 — Full HauntMode analysis

For each confirmed request, execute the full protocol:

1. `cat INDEX.md` — load the vuln index
2. `cat HAUNT_CHECKLIST.md` — load the analysis protocol
3. Dissect every parameter, header, cookie, and body field
4. Evaluate all 38 checklist categories — mark each [APPLIES] / [MAYBE] / [NO]
5. Invoke the skill for every [APPLIES] and [MAYBE] category
6. Produce structured output: request summary, applicable vulns, prioritized attack plan with exact payloads, ready-to-run tool commands

**While working through categories:** mentally accumulate two lists —
- **Leads** — [MAYBE] flags with a specific observation worth following up
- **Findings** — [APPLIES] with actual evidence

Do NOT write to files mid-analysis. Accumulate in memory, write once at the end.

---

## Step 6 — Log and report

Do all writes in one pass after the analysis is complete.

**`reports/hauntmode-log.md`** — one line per request:
```
METHOD host /path | vuln1,vuln2 or clean
```

**`reports/leads.md`** — append one line per lead (things that need follow-up but aren't confirmed). Format: `category — param/field — why it's interesting`:
```
sqli      — order_id param    — numeric, no sanitization visible, try 1'--
idor      — /api/v1/user/42   — sequential ID, test adjacent IDs with other session
csrf      — /account/delete   — no token visible, SameSite not set
```
One line maximum per lead. No prose. If nothing needs follow-up, skip this file entirely.

**`reports/findings.md`** — confirmed findings only, append:
```markdown
## [vuln class] — METHOD host/path
**Parameter:** [param]
**Evidence:** [what you observed]
**Impact:** [business impact]
**Next step:** [what to confirm/escalate]

---
```

**End-of-run summary** — always present this in conversation after writing:
```
HauntMode complete — METHOD host/path

Findings:  X confirmed → reports/findings.md
Leads:     Y to follow up → reports/leads.md
Clean:     Z categories

Top priority: [the one thing most worth chasing right now]
```

---

## Hard rules

- Never re-analyze a request already in the log unless the user explicitly says to
- Never skip a checklist category without stating why
- Always invoke the skill for each applicable category — do not work from training memory
- In batch/Burp mode, always triage and confirm before running full analysis
- If >25 requests queued, always ask before proceeding
- All curl commands must include headers from `headers.conf`
