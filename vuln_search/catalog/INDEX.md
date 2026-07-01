# Vulnerability Dictionary — catalog index

A browsable, searchable dictionary of web-vulnerability classes. Each entry is a one-folder
**dictionary card** (`<slug>/README.md`): what the class is, how it works, impact, detection,
exploitation summary, defenses, and a **"Finding CVEs from scratch"** section pointing at NVD,
CVE.org, Exploit-DB, GitHub Advisories, OSV, and community sources (r/netsec, HackerOne, vendor
blogs). Each card links to its **deep-dive note** in
[`../../Troubleshooting_Guide/`](../../../Troubleshooting_Guide/) and to the matching skill.

New entries: copy [`ENTRY_TEMPLATE.md`](ENTRY_TEMPLATE.md) into `<slug>/README.md`.
Status legend: ✅ complete · 🟡 stub (headings + CVE-search links, prose pending). **🇻🇳** = a
Vietnamese `README.vi.md` exists. Bilingual conventions: [`docs/SKILLS_AND_I18N.md`](../../docs/SKILLS_AND_I18N.md)
(English canonical, `*.vi.md` sibling, one language loaded at a time).

## Injection
- ✅ 🇻🇳 [SQL Injection](sql_injection/README.md)
- ✅ [NoSQL Injection](nosql_injection/README.md)
- ✅ [OS Command Injection](os_command_injection/README.md)
- ✅ [Server-Side Template Injection (SSTI)](ssti/README.md)
- ✅ [XML External Entity (XXE)](xxe/README.md)
- ✅ [Path Traversal](path_traversal/README.md)

## Client-side
- ✅ 🇻🇳 [Cross-Site Scripting (XSS)](xss/README.md)
- ✅ [DOM-Based Vulnerabilities](dom_based/README.md)
- ✅ [Cross-Site Request Forgery (CSRF)](csrf/README.md)
- ✅ [Clickjacking](clickjacking/README.md)
- ✅ [CORS Misconfiguration](cors/README.md)
- ✅ [Prototype Pollution](prototype_pollution/README.md)

## Authentication & identity
- ✅ [Authentication Vulnerabilities](broken_authentication/README.md)
- ✅ [JWT Attacks](jwt/README.md)
- ✅ [OAuth 2.0 Vulnerabilities](oauth/README.md)
- ✅ [Access Control Vulnerabilities](broken_access_control/README.md)

## Server-side & infrastructure
- ✅ 🇻🇳 [Server-Side Request Forgery (SSRF)](ssrf/README.md)
- ✅ [HTTP Host Header Attacks](http_host_header/README.md)
- ✅ [HTTP Request Smuggling](http_request_smuggling/README.md)
- ✅ [Web Cache Deception](web_cache_deception/README.md)
- ✅ [Web Cache Poisoning](web_cache_poisoning/README.md)

## APIs & modern
- ✅ [API Testing & Security](api_security/README.md)
- ✅ [GraphQL API Vulnerabilities](graphql/README.md)
- ✅ [WebSocket Vulnerabilities](websockets/README.md)
- ✅ [Web LLM / Prompt Injection](llm_attacks/README.md)

## Other
- ✅ [File Upload Vulnerabilities](file_upload/README.md)
- ✅ [Race Conditions](race_condition/README.md)
- ✅ [Information Disclosure](information_disclosure/README.md)
- ✅ [Insecure Deserialization](insecure_deserialization/README.md)

---

**Note on CVE facts:** "Notable CVEs" are illustrative and should be verified against NVD before
being cited — the dictionary's durable value is the *search methodology*, not a frozen CVE list.
All content is for **authorized testing only**; knowing a technique never bypasses the
`RunConfig.authorized_targets` safety gate.
