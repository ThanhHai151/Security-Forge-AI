# <Vulnerability name>

> One-line definition of the class. **Deep dive:** link to the full technique note in
> `../../../Troubleshooting_Guide/<file>.md` · **Skill:** `../../../ai_framework/skills/`

**Aliases / OWASP:** other names · OWASP category (e.g. A03:2021 Injection)
**Status:** stub | draft | complete

## What it is
Plain-language definition a reader can grasp in two sentences.

## How it works
The mechanism: what the attacker controls, what the app does wrong, why it breaks.

## Impact
What an attacker gains (data, RCE, account takeover, …) and typical severity.

## How to detect
Signals during testing — responses, errors, timing, headers — that say "look here".

## Exploitation (summary)
The shape of an attack. Keep it short; the deep-dive note has full payloads.

## Defenses
The fixes, in priority order. This section is what `defense/` inverts to audit a target.

## Finding CVEs from scratch
Where and how to hunt real-world instances of this class:
- **NVD** — https://nvd.nist.gov/vuln/search (keyword: the class + product/version)
- **CVE.org** — https://www.cve.org/ (canonical CVE records)
- **Exploit-DB** — https://www.exploit-db.com/search (working PoCs)
- **GitHub Security Advisories** — https://github.com/advisories (filter by ecosystem)
- **OSV** — https://osv.dev/ (open-source package vulns)
- **Community** — r/netsec, r/AskNetsec, X/Twitter infosec, vendor blogs, HackerOne reports
- Query tips specific to this class.

## Notable CVEs
- `CVE-YYYY-NNNNN` — one-line what/where (illustrative; verify against NVD before citing).

## References
- Authoritative external links (PortSwigger, OWASP, RFCs).
