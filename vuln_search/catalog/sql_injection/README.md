# SQL Injection

> Untrusted input alters a SQL query, exposing or modifying the database. **Deep dive:**
> [`Troubleshooting_Guide/sql_injection.md`](../../../../Troubleshooting_Guide/sql_injection.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** SQLi · A03:2021 Injection
**Languages:** English · [Tiếng Việt](README.vi.md)
**Status:** complete

## What it is
SQL injection happens when user-supplied input is concatenated into a SQL statement instead of
being passed as a bound parameter. The database then parses attacker text as query *syntax*, so
the attacker can change what the query does — read other rows, bypass authentication, or in some
configurations read/write files and run commands.

## How it works
The app builds a query like `… WHERE id = '` + input + `'`. Supplying `' OR '1'='1` makes the
predicate always-true; `' UNION SELECT username,password FROM users-- ` appends a second result
set. Variants:
- **In-band / UNION** — data returned directly in the response.
- **Blind boolean** — infer data from true/false differences in responses.
- **Blind time-based** — `SLEEP(5)` / `pg_sleep(5)` to infer data from response delay.
- **Out-of-band** — exfiltrate via DNS/HTTP when the in-band channel is closed.

## Impact
Full read (and often write) access to application data; authentication bypass; in some stacks
file read/write and RCE (`xp_cmdshell`, `INTO OUTFILE`, stacked queries). Frequently a
breach-grade, critical-severity finding.

## How to detect
- A single quote `'` triggers a 500 / SQL error or changes results.
- Boolean payloads (`' AND 1=1--` vs `' AND 1=2--`) flip the response.
- Time payloads add a measurable, controllable delay.
- Numeric contexts react to `1`, `1-0`, `1*1` arithmetic.

## Exploitation (summary)
Find the injection point and context (string vs numeric, quote style), determine the column
count (`ORDER BY` / `UNION SELECT NULL,…`), then extract via UNION or blind inference. Automate
with `sqlmap` once a vector is confirmed. Full payload sets are in the deep-dive note.

## Defenses
1. **Parameterized queries / prepared statements** everywhere (the real fix).
2. ORMs used safely — no raw-string interpolation into queries.
3. Least-privilege DB accounts; disable dangerous features (stacked queries, `xp_cmdshell`).
4. Allow-list input validation; WAF as defense-in-depth, never the primary control.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=SQL+Injection (add product + version)
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=SQL+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=SQL+Injection (filter Type=webapps)
- **GitHub Advisories** — https://github.com/advisories?query=sql+injection
- **OSV** — https://osv.dev/list?q=sql%20injection (open-source packages)
- **Community** — r/netsec, HackerOne Hacktivity (`weakness:"SQL Injection"`), vendor PSIRT blogs.
- _Query tip: pivot from the product fingerprint found during recon, e.g._
  `"<CMS name> <version>" SQL injection`.

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2023-34362` — MOVEit Transfer SQL injection, mass-exploited by Cl0p for data theft.
- `CVE-2021-27101` — Accellion FTA SQL injection, used in widespread breaches.
- _Canonical pre-CVE example: countless ASP/PHP apps c.2005–2010; cf. "Bobby Tables", xkcd 327._

## References
- PortSwigger Web Security Academy — SQL injection.
- OWASP — SQL Injection Prevention Cheat Sheet.
