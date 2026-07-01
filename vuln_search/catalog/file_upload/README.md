# File Upload Vulnerabilities

> Unrestricted uploads let attackers plant web shells or overwrite files. **Deep dive:** [`Troubleshooting_Guide/file_upload_bsv.md`](../../../../Troubleshooting_Guide/file_upload_bsv.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A04:2021 Insecure Design
**Status:** complete

## What it is
A file-upload vulnerability is when an application lets users upload files without adequately validating
their name, type, content, or where they are stored. If the server then serves or executes those files,
an attacker can plant a web shell or overwrite sensitive files.

## How it works
The attacker controls the file's name, declared `Content-Type`, extension, and bytes. The app does the
validating wrong: it trusts the client-supplied MIME type, checks only a blocklist of extensions, or
saves the file inside the web root where the server will execute it. Uploading a `.php`/`.jsp`/`.aspx`
file (or bypassing the filter) and then requesting it runs attacker code. Other failures include path
traversal in the filename (writing outside the intended directory), parsers that follow embedded
references (SVG/XML XXE), and polyglot files that satisfy a validator while still being executable.

## Impact
Remote code execution via a planted web shell is the headline outcome — full server compromise. Lesser
but still serious results include overwriting existing files (config, other users' content), stored XSS
via uploaded HTML/SVG, SSRF/file-read through XXE in image parsers, and denial of service through
oversized files. RCE-capable cases are critical.

## How to detect
- Upload a benign script (e.g. a `.php` printing a marker) and request the stored URL; execution of the
  marker confirms RCE.
- Probe filter logic: change the `Content-Type` header, try alternate/double extensions
  (`shell.php.jpg`, `shell.pHp`, `shell.php5`, trailing dots/spaces, null bytes), and check whether
  validation is by extension, MIME, or magic bytes.
- Watch the response/headers for the stored path; test `../` in the filename, and try SVG/XML uploads to
  surface XXE.

## Exploitation (summary)
The core move is to get an executable file into a location the server will run, defeating whatever
validation is in place. Bypasses include spoofing `Content-Type: image/jpeg` on a PHP file, abusing
blocklist gaps (`.phtml`, `.php5`, case/obfuscation), prepending valid magic bytes or `GIF89a` to make a
polyglot, exploiting `.htaccess`/server config to make a new extension executable, and using
`../`-laden filenames to write outside the upload directory. SVG uploads can carry XXE for file read or
SSRF. Once a web shell lands, request it with a `cmd` parameter to run commands.

## Defenses
1. **Validate with an allow-list** of permitted extensions and verify the actual content (magic bytes /
   server-side type detection), not the client-supplied `Content-Type`.
2. **Store uploads outside the web root** (or in object storage) and serve them via a handler that sets
   `Content-Disposition: attachment` and a benign `Content-Type` — never let the upload directory execute.
3. **Generate the stored filename** server-side (random/UUID); strip path components so attacker-supplied
   names can't traverse directories or overwrite existing files.
4. **Disable execution in the upload path** (web-server config: no PHP/CGI handlers, `.htaccess` ignored)
   and enforce size limits.
5. For image/XML uploads, re-encode or sanitize the file and disable external-entity resolution to
   neutralize SVG/XXE and polyglots.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=File+Upload+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=File+Upload+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=File+Upload+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=File+Upload+Vulnerabilities
- **OSV** — https://osv.dev/list?q=File+Upload+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `File Upload Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2017-12615` — Apache Tomcat: PUT-based JSP upload leading to remote code execution.
- `CVE-2021-22005` — VMware vCenter Server arbitrary file upload to the Analytics service, chained to RCE.
- `CVE-2018-9206` — jQuery File Upload (Blueimp) unrestricted upload, widely exploited for web shells.

## References
- PortSwigger Web Security Academy — File upload vulnerabilities.
- OWASP — File Upload Cheat Sheet.
- OWASP — Unrestricted File Upload (Testing Guide / community page).
