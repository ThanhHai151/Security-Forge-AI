# Red-Team OPSEC, Stealth & Evasion — a tradecraft reference

> **What:** a conceptual reference on how a real red team stays covert during an
> **authorized** engagement — concealing its source, blending into a target's network and
> hosts, managing the artifacts it leaves behind, and avoiding self-attribution — and, for
> every offensive concept, the **blue-team detection counterpart** that catches it.
>
> **Why here:** SecForge is both an offensive framework ([`ai_framework/`](../ai_framework/README.md))
> and a defensive one ([`defense/`](../defense/README.md)). Stealth tradecraft is the
> missing methodology layer between the two: the agent needs it to emulate a real adversary,
> and the defence pillar needs the *detection* half to harden a target against exactly these
> moves. This file is the shared source for both.
>
> **Scope & safety:** this is principles and *why* (tradecraft, MITRE ATT&CK IDs, real
> case studies, detection), **not** weaponization — no operator configs, malleable-C2
> profiles, bypass code, or step-by-step setup. It is written for authorized work only, and
> it deliberately pairs each evasion concept with how defenders see it. Several capabilities
> have **changed in viability over time** (and MITRE's own taxonomy changed in 2025); those
> are flagged inline. English-only (project rule).

This document is methodology, not code. It complements the vulnerability corpus
([`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md)) — that corpus answers *"how do I find and prove a
flaw?"*, this answers *"how does a real adversary operate without being seen, and how is that
seen anyway?"* The [agent system prompt](../ai_framework/agent/system.py) carries a compressed
version of §0–§1 as standing rules for every run.

---

## 0. Authorization is the whole game (read first)

Everything below is **only** lawful and ethical inside a signed engagement. The single line
that separates a red teamer from a criminal is not skill or tooling — it is **authorization
and intent**. Absent a signed Rules of Engagement (RoE) and written authorization, identical
activity is a felony under the U.S. **Computer Fraud and Abuse Act (18 U.S.C. § 1030)** and
equivalent statutes worldwide. SecForge's hard rule ("act only against authorized targets") is
not a formality; it is the precondition that makes this entire discipline legitimate.

Before any covert activity, a real engagement establishes:

- **Written authorization** — a signed scope/authorization letter (the "get-out-of-jail-free"
  letter) naming the assets, IP ranges, domains, and accounts in scope, the time windows, and
  the client signatory who can authorize it. **NIST SP 800-115** treats written authorization
  and RoE as foundational elements documented *before* any technical testing, and ships a
  dedicated RoE template in **Appendix B**. Authorization must be signed by an authorized
  representative of the target org — not merely an IT contact.
- **Rules of Engagement (RoE)** — PTES separates two concepts in pre-engagement: **scope** =
  *what* may be tested (with explicit exclusions/off-limits resources), and **RoE** = *how* the
  test is conducted, which techniques are permitted (e.g. is social engineering in scope? real
  phishing? denial-of-service — *never* by default?), data-handling rules, and escalation
  contacts. Scope creep is a genuine legal exposure, not a stylistic slip.
- **Deconfliction** — a pre-agreed channel and trusted line-of-contact so that when the blue
  team detects the red team, responders can confirm "that's the authorized test, stand down"
  instead of triggering a real incident, wasted IR, legal action, or law-enforcement referral.
- **A hard stop at the scope boundary.** A promising lead that is out of scope is **noted and
  left untouched** — never followed. This mirrors the agent's standing rule.

> **Ethical linchpin — document, don't destroy.** A criminal erases evidence to escape
> consequences. An authorized red team does the opposite: it keeps a **meticulous, timestamped
> log of every action** so the engagement is reproducible, the client can learn, and evidence
> chain-of-custody is preserved. "Erasing your footprint" in this document means understanding
> how attackers *reduce* their footprint (and how defenders detect that) — **not** performing
> destructive anti-forensics against a client's systems. Never delete a client's logs, corrupt
> their data, or degrade their ability to investigate. Anti-forensic or log-tampering behavior
> is performed **only** when explicitly pre-authorized in the RoE, against a controlled
> artifact, announced, and logged — the standard of care is reproducibility, not destruction.

The rest of this document assumes every technique is exercised inside these guardrails.

---

## 1. OPSEC fundamentals — indicators, footprint, and the Pyramid of Pain

**Operational Security (OPSEC)** is a five-step government/DoD discipline (NIST/CNSSI): *identify
critical information & indicators → analyze threats → analyze vulnerabilities → assess risk →
apply countermeasures.* It is **cyclical**, not strictly sequential. Applied to offensive
security the roles invert — the "adversary" who must be denied is the **blue team / SOC** — and
the "critical information" an operator must protect is anything that lets a defender **detect,
attribute, or evict** them (intentions, capabilities, activities, and engagement limitations).

Two concepts run through the whole topic:

- **Indicator (IoC).** Data derived from a detectable action that an adversary can piece
  together — "one piece of a larger puzzle." Operator examples: a source IP, a domain, a file
  hash, a TLS fingerprint, a distinctive user-agent, a consistent beacon interval, a timestamp,
  a keyboard locale. Each indicator is a thread a defender can pull.
- **Footprint.** The aggregate observable trace an operation leaves across network, host,
  identity, and OSINT surfaces. Good tradecraft *minimizes* and *normalizes* the footprint so it
  blends with legitimate activity rather than eliminating it (you cannot).

### The Pyramid of Pain (the mental model for all of §2–§6)

David Bianco's **Pyramid of Pain** (2013) ranks indicators by how much it costs the *adversary*
when a defender denies them:

| Tier | Indicator | Cost to the operator to change |
|------|-----------|-------------------------------|
| Bottom | Hash values | Trivial |
| ↓ | **IP addresses** | **Trivial** |
| ↓ | Domain names | Annoying (money, DNS propagation) |
| ↓ | Network/host artifacts | Annoying |
| ↓ | Tools | Challenging |
| Top | **TTPs** (tactics, techniques, procedures) | **Tough — can't easily abandon their methods** |

The core lesson, and the honest framing of this user's own examples: **swapping a source IP
("fake IP") is the cheapest possible move — cheap for the operator *and* cheap for the defender
to defeat.** The durable contest happens near the *top* of the pyramid, at tool/behavior
fingerprints (JA3/JARM, beaconing patterns) and TTPs. An operation that only rotates IPs and
spoofs a timezone has changed nothing that actually hurts a competent defender.

*Sources: attackiq.com/glossary/pyramid-of-pain-2, activecountermeasures.com "hunt what hurts",
Bianco (2013).*

### The evasion taxonomy — MITRE ATT&CK (the tactic split of 2025)

> **Framework change — CONFIRMED, not "drift" (verify current state on attack.mitre.org).**
> The historic **Defense Evasion (TA0005)** tactic has been **split into two tactics** in
> current ATT&CK (v19):
> - **TA0005 is renamed "Stealth"** — pure *concealment* behaviors: avoid, obfuscate, or mimic
>   normal operations to stay indistinguishable from benign activity, **without** modifying
>   security controls.
> - **TA0112 "Defense Impairment"** (new) — techniques that *weaken, disable, or tamper with*
>   security controls, pipelines, and tooling so defenders lose visibility.
>
> The reorganization is real: former **Impair Defenses (T1562)** and its sub-techniques
> (.001 Disable/Modify Tools, .006 Indicator Blocking) were merged into new **T1685 "Disable or
> Modify Tools"** under TA0112; **T1687 "Exploitation for Defense Impairment"** was added and the
> old "Exploitation for Defense Evasion" renamed **T1211 "Exploitation for Stealth."** Any
> detection/report still mapped to "TA0005 = evasion+impairment" or to T1562.001/.006 now has a
> tactic-level blind spot. **The stable anchors are the technique IDs** (T1070, T1036, T1027,
> T1218, T1055, T1497…), which persist across the rename; pre-2025 material calling TA0005
> "Defense Evasion" with ~40 techniques reflects ≤ v18. Cite versioned URLs for historical taxonomy.

Conceptually, the techniques an operator uses to stay hidden still fall into recognizable
families — Masquerading (T1036), Indicator Removal (T1070), Obfuscated/Encrypted content
(T1027), System Binary Proxy Execution (T1218), Process Injection (T1055),
Virtualization/Sandbox Evasion (T1497), and the now-separated control-tampering set under
TA0112. This document organizes them into **five operational layers (§2–§6)** and maps them
back in the table in §8, independent of MITRE's tactic labeling.

---

## 2. Network & infrastructure — source concealment ("fake IP")

### Tradecraft (the *why*)

- **It's a proxy problem (ATT&CK T1090).** Source concealment lives under Command-and-Control →
  **Proxy**: route through an intermediary "to avoid direct connections" and mask the true C2
  destination. Sub-techniques: Internal (.001), External (.002), Multi-hop (.003), Domain
  Fronting (.004). (attack.mitre.org/techniques/T1090)
- **Redirectors, not direct connections.** A **redirector** is a disposable, internet-facing
  host in front of the team server so the target never touches the backend. When defenders
  block the callback IP, they burn only the redirector, which is "easily swapped out without
  having to rebuild the team server." This is the whole reason a single static source IP is an
  OPSEC failure: it is a durable pivot that, once flagged, correlates *all* activity that ever
  touched it. (bluescreenofjeff Red-Team-Infrastructure-Wiki)
- **VPN vs Tor trade-off.** A VPN is one intermediary that *can see* your IP + destination and
  can log or be compelled — **inconspicuous but attributable**. Tor distributes trust across
  ~thousands of relays (guard knows your IP, exit knows your destination, structurally
  separated) — **non-attributable by design but conspicuous**: the exit-node list is public and
  trivially blocked, it's slow, and it's still vulnerable to end-to-end traffic correlation.
  (ivpn.net privacy-guides; arXiv 2004.09063)
- **Residential / rotating proxies & ORB networks.** Datacenter IPs are easy to flag by ASN;
  **residential** proxies borrow household IPs and blend with everyday user traffic. Nation-state
  "ORB" (operational relay box) networks egress from devices with **geographic proximity to the
  target** so traffic "blends in or is otherwise not anomalous" — a residential ISP in the
  target's own city. (Mandiant/Google "China-Nexus ORB Networks"; netacea.com; FBI residential-proxy alert)
- **Living off the cloud.** Sourcing traffic from hyperscaler ranges (AWS/GCP/Azure/Cloudflare)
  inherits the provider's reputation, so reputation-based blocking and takedowns become
  ineffective. (cybersecuritynews.com "attackers abuse cloud services")

### Detection counterpart (blue team / the [`defense/`](../defense/README.md) view)

- **Reputation & threat-intel feeds:** blocklists, passive DNS, BGP/WHOIS; **Tor** is caught by
  matching the Tor Project's published exit-node list; VPN/proxy/datacenter DBs refresh many
  times daily. Microsoft Entra ID Protection ships *Anonymous IP*, *Malicious IP*, and
  *nation-state IP* detections. (learn.microsoft.com/entra/id-protection)
- **Geo-anomaly / impossible-travel** flags distant logins in an impossible window — **but with
  a documented blind spot:** non-physical IPs (VPN/cloud) are *excluded* from impossible-travel
  scoring, which is exactly why a geographically-proximate residential proxy evades it.
  (learn.microsoft.com/defender-cloud-apps anomaly policy)
- **The IP indicator is decaying as a defense.** GreyNoise (2026): ~**78% of residential attacker
  IPs were seen at most twice** before rotating out — feed-based blocking is structurally late,
  so detection is moving to **behavior and device fingerprinting**. Mandiant tracks ORB networks
  "like evolving entities akin to APT groups," not static IoCs. This is the Pyramid of Pain in
  practice: chasing IPs is a losing game for both sides. (greynoise.io; Mandiant ORB)

---

## 3. Time, locale & timing OPSEC ("fake time zone")

This is where "erase your footprint" and "fake your timezone" meet reality: timestamps and
locale artifacts are among the strongest *attribution* leaks, and history is full of operators
caught by them.

### Tradecraft & documented attribution leaks

- **Build timestamps → operator timezone.** A PE file's `TimeDateStamp` is often left intact;
  across a large attributed sample set, compile times cluster into an 8–12h "9-to-5" band that
  reveals the operator's working timezone. The undocumented **Rich header** is "a very strong
  factor for attribution" — in **Olympic Destroyer**, a forgotten Rich header plus a compile
  timestamp tied a sample to a specific moment. (0xc0decafe.com PE-timestamps; Securelist
  "devil's in the Rich header")
- **Locale / keyboard / language artifacts.** PE resources embed a language ID; if unset, the
  build system's locale leaks in. The **Sony Pictures** malware carried Korean-language
  resources; ATT&CK **System Language Discovery (T1614.001)** documents malware checking keyboard
  layout / UI language to avoid running in certain countries (Ryuk/Cuba/DarkSide ship
  CIS-country "do-not-install" lists) "to reduce their risk of attracting the attention of
  specific law enforcement agencies." (blog.korelogic.com; attack.mitre.org/techniques/T1614/001)
- **Flagship case — APT1 (Mandiant, 2013):** ~97% of 1,905 operator logins used
  **Shanghai-registered IPs on Simplified-Chinese systems** with a "Chinese (Simplified) — US
  Keyboard" layout, and activity followed an **8 AM–5 PM Shanghai workday** — tying the group to
  PLA Unit 61398. Working hours are simultaneously *cover* and an *attribution lever*.
  (Mandiant APT1 report)
- **Beacon timing — sleep & jitter.** A perfectly regular callback is trivially detectable, so
  operators add **jitter** (randomized interval variance) and long **sleep** to go "low and
  slow," and tune callbacks into the target's **business hours** so they don't stand out as
  off-hours anomalies. (thedfirreport.com Cobalt Strike defender's guide pt.2)
- **What "erase footprint" means at this layer — Timestomp (T1070.006).** Modifying a file's
  MACE times to match its neighbours. On NTFS the user-visible `$STANDARD_INFORMATION` (`$SI`)
  times are editable while `$FILE_NAME` (`$FN`) requires kernel/deeper interaction, so advanced
  actors perform **"double timestomping"** to defeat `$SI`/`$FN` comparison — observed with
  **APT29** matching web-shell times to neighbouring files. (attack.mitre.org/techniques/T1070/006)

> **Honesty about "faking" — these signals are forgeable *and* have been used as false flags.**
> **Lazarus** planted clumsy transliterated-Russian strings and **Olympic Destroyer**
> manufactured signals pointing at four different nations to misdirect attribution. The lesson
> cuts both ways: an operator *can* spoof timezone/locale, and a defender must therefore treat
> any single timezone/locale signal as **circumstantial — corroborate with TTPs, infrastructure,
> and code overlap** before attributing. (BAE "Lazarus false-flag"; Securelist)

### Detection counterpart

- **Compile-timestamp & working-hours heatmaps** (day-of-week × hour) from attributed samples —
  demonstrated against APT1 (Shanghai 8–5). Tooling pitfall: some tools show `TimeDateStamp` in
  UTC, others silently localize — standardize to UTC.
- **Beaconing survives jitter statistically.** Shift from "find perfect periodicity" to "find a
  low-volume *persistent* connection to one destination." Tools like **RITA** score Zeek logs on
  periodicity/consistency; FFT/frequency-domain analysis catches any recurring frequency.
  **Caveat:** naive fixed-interval rules are fully defeated by high jitter (one test: *zero*
  detections against ±45% jitter). (hunt.io c2-beaconing; deeptempo.ai)
- **Timestomp forensics:** compare `$SI` vs `$FN`, watch **Sysmon Event ID 2 (FileCreateTime)**
  correlated with EID 11 (FileCreate), and `SetFileTime`/`touch -r` in odd contexts;
  double-timestomping is caught by falling back to the **USN Journal** (a `BasicInfoChange`
  records the *actual* modification time even when Explorer timestamps are forged) and
  `$MFT`/`$LogFile` correlation. (attack.mitre.org T1070.006; andreafortuna.org USN journal)

---

## 4. Traffic blending — looking like normal HTTPS/DNS

### Tradecraft (the *why*)

- **TLS fingerprinting (JA3 / JA3S) is the thing that actually hurts.** Because TLS Client/Server
  Hello are cleartext, **JA3** hashes the client's cipher/extension list and **JA3S** the
  server's — fingerprinting the *tool* "regardless of destination IPs, domains, or certs."
  Default tooling has a stable fingerprint, so an operator who rotates IPs/domains but never
  reshapes their TLS profile is still trivially clustered. This is why IP-only evasion (§2) is weak.
  (Salesforce Engineering "TLS fingerprinting with JA3 and JA3S")
- **Malleable C2 profiles** reshape an implant's HTTP(S)/DNS request/response — headers, URIs,
  body, even the handshake — to mimic benign services (e.g. look like Windows Update / Slack).
  *Default vs custom matters:* known/default profiles trip signatures; custom ones evade
  conventional detection. (Unit 42 "Cobalt Strike Malleable C2")
- **DNS-over-HTTPS / DNS tunneling** encodes data in subdomain labels to attacker name servers;
  **DoH** rides 443 and "blends into ordinary HTTPS," sidestepping DNS-layer logging — a common
  stealthy fallback when HTTP(S) is filtered. (nec.com ChamelDoH analysis)
- **Categorized / aged / look-alike domains + valid certs.** Domains cost more to change than IPs
  (registration + DNS propagation), which is why aged, pre-categorized domains and valid
  Let's-Encrypt certs are a tradecraft *investment* — one step up the Pyramid of Pain. (picussecurity.com)

> **Domain fronting — VIABILITY CHANGED (flagged, important).** The classic technique put a
> trusted **front domain in DNS/SNI** and the real C2 domain only in the **HTTP Host header**,
> so a shared CDN routed on the Host header after TLS termination. **Cloudflare disabled it
> ~2015; AWS CloudFront and Google both blocked it in April 2018** (CloudFront now returns HTTP
> **421** on SNI/Host mismatch); **Azure fully blocked by 2024.** *Classic domain fronting
> against the major CDNs is dead.* "Domainless" (blank-SNI) and domain-borrowing variants persist
> only on providers that don't validate SNI/Host equality, and emerging **ECH (Encrypted Client
> Hello)** could revive passive-detection resistance — **re-verify per provider before relying on
> anything here.** (Real precedent: Mandiant documented **APT29** fronting C2 through Google's CDN
> via Tor+`meek` for ~2 years.) (en.wikipedia.org/wiki/Domain_fronting; AWS Security Blog; Mandiant APT29)

### Detection counterpart

- **JA3/JA3S** detects malware by *how* it communicates, not *what*; combining client+server
  fingerprints disambiguates common sockets. Caveats: it's a *pivot not proof*, must handle
  Google **GREASE**, and produces false positives.
- **JARM** actively fingerprints a *server* (10 crafted Client Hellos → 62-char hash); C2
  frameworks deploy uniformly, so e.g. **80% of live Trickbot C2s shared one JARM** with zero
  overlap in the Alexa top 1M. Caveats: not proof of malice (Burp Collaborator / generic Java
  match), and it can be **spoofed/randomized**. (Salesforce Engineering JARM)
- **Domain-fronting detection:** inspect HTTPS for **SNI ≠ Host mismatch** (ATT&CK M1020).
- **DNS anomaly detection:** long high-entropy subdomains, NXDOMAIN bursts (DGA), query-timing
  beaconing, rare record-type spikes (TXT/NULL), clients using unauthorized external resolvers /
  DoH. DoH erodes content visibility → pivot to metadata + endpoint/process correlation.
  (nec.com; Cisco Talos "detecting DGA"; ATT&CK T1568.002)

---

## 5. Host & endpoint evasion — living off the land, and the defensive surfaces

### 5.1 Living off the Land (the *why*)

- **LOTL / LOLBins / GTFOBins.** Use legitimate, already-present, often-signed system binaries
  instead of dropping tools. Because they're trusted, malicious actions "blend in with normal
  system operations" — shifting activity from *malicious* to merely *suspicious* — and leave far
  fewer disk artifacts (often no file to quarantine or hash). The **LOLBAS** project (Windows)
  and **GTFOBins** (Unix) catalogue these, each entry mapped to ATT&CK. (lolbas-project.github.io;
  gtfobins.org; securityhq.com)
  - **This is now the norm, not the exception:** CrowdStrike's 2025 report found **79% of
    detections in 2024 were malware-free** (up from 40% in 2019). **Volt Typhoon** (2023)
    maintained access to US critical infrastructure for months using *exclusively* built-in
    Windows tools. (crowdstrike.com 2025 Global Threat Report; CISA AA23-144a)
- **Key ATT&CK techniques:** System Binary Proxy Execution **T1218** (rundll32/mshta/regsvr32/
  msiexec proxying execution to dodge signature defenses); Command & Scripting Interpreter
  **T1059** (PowerShell/cmd/bash — #2 and #3 in Red Canary's 2025 top techniques); Masquerading
  **T1036** ("renaming abusable system utilities to evade monitoring is a form of Masquerading");
  Ingress Tool Transfer **T1105** (using certutil/BITSAdmin/curl to pull payloads is itself LOTL).

### 5.2 The defensive-control surfaces (detection surfaces, not bypass recipes)

Operators are *aware* of these surfaces because they exist to catch attackers; understanding them
is what lets the [`defense/`](../defense/README.md) pillar reason about coverage gaps. Tampering
with any of them is now **Defense Impairment (TA0112)** — the set formerly called Impair Defenses
(T1562), reorganized into **T1685** and siblings (see §1).

- **AMSI (Antimalware Scan Interface)** submits script/macro content to the AV engine *after
  deobfuscation but before execution*, so on-disk vs. in-memory no longer matters for script
  visibility — it's exactly the surface that catches obfuscated/fileless PowerShell, WSH,
  Office VBA, and dynamic .NET loads. That's why it's a prime tampering target.
  ([learn.microsoft.com AMSI portal](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal); redcanary.com AMSI data source)
- **ETW (Event Tracing for Windows)** is the OS-wide telemetry backbone — **providers** emit
  events, **controllers/sessions** configure tracing, **consumers** read it — and it underpins
  much security telemetry (including AMSI and the PPL-protected Threat-Intelligence provider).
  Redirecting or disabling a session blinds sensors.
  ([learn.microsoft.com About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing))
- **Windows event logging** records post-exploitation activity — hence both disabling it
  (formerly T1562.002 Disable Windows Event Logging) and clearing it (Indicator Removal
  T1070.001, see §6).
- **EDR & BYOVD (category level).** EDR aggregates process/thread/image-load/registry/network and
  API telemetry, much of it sourced from ETW. **Bring-Your-Own-Vulnerable-Driver (BYOVD)** loads
  a legitimately-signed but vulnerable driver to run in kernel space and blind defenses — a
  documented Defense-Impairment approach (formerly under T1562.001).

### Detection counterpart

- **Process telemetry answers LOTL.** Windows command-line logging is off by default; **Sysmon**
  fills the gap — Event ID 1 (process creation with full command line + parent + hash), ID 7
  (image/DLL load → side-loading), ID 10 (ProcessAccess → LSASS credential theft), ID 11
  (FileCreate), ID 12/13/14 (registry). (learn.microsoft.com/sysinternals/sysmon; blackhillsinfosec.com)
- **Behavioral / parent-child anomalies:** an Office app or `explorer.exe` spawning
  `powershell.exe`/`cmd.exe`; PowerShell `EncodedCommand`/base64; download-and-exec cmdlets;
  execution from temp dirs. **Baseline** each high-risk binary's normal args/parent/user context
  before alerting. (elastic.co "detecting command scripting interpreter")
- **Watch the watchers (tamper detection).** ETW trace-session changes surface as
  `Microsoft-Windows-Kernel-EventTracing` **Event ID 12**; **Sysmon logs its own config change as
  Event ID 16** and its service-state as **Event ID 4** ("does not attempt to hide itself"); AMSI
  telemetry rides the `Microsoft-Antimalware-Scan-Interface` ETW provider (EID **1101**). The
  governing principle: **alert on the *absence* of expected telemetry** (a sensor going quiet) and
  on security-tool providers being disabled or downgraded. For BYOVD, match driver/image loads
  against known-vulnerable-driver blocklists (HVCI). (attack.mitre.org T1562.006; redcanary.com)
- **The hard part — chaining.** EDR catches a *single* LOLBin abuse well but struggles when each
  step looks normal in isolation; this needs **behavioral sequence/timeline correlation**, not
  single-event alerts. Preventive controls: AppLocker/WDAC, PowerShell Constrained Language Mode,
  ASR rules blocking Office child processes. (eventpeeker.com; securityhq.com)

---

## 6. Artifact & footprint management ("erase footprint") — and why local erasure is futile

This is the section the user's "erase footprint" most directly asks about — and the most
important honest finding is that **against modern telemetry, erasing your local footprint mostly
doesn't work, and *trying* often creates a louder signal than the footprint did.**

### The host-footprint inventory

An operation touches: files (payloads, tools), registry keys (Run keys, ETW autologger config),
**Prefetch** (`.pf` execution evidence), **Shellbags** (registry record of folder access),
Windows event logs, and NTFS metadata — the **`$MFT`** (per-file `$SI`/`$FN` timestamps),
**`$LogFile`**, and the **USN Journal** (`$Extend\$UsnJrnl:$J`, a change log), plus directory
index slack (`$I30`). Crucially, **the USN Journal logs *events, not just current state*** — every
create/delete/rename/data-change leaves a trace even if the file is later deleted or timestomped.
(unjaena.com Windows artifact guide; andreafortuna.org USN journal)

### Tradecraft (the *why*) — reduce, don't destroy

- **Indicator Removal (ATT&CK T1070)** covers clearing Windows event logs (.001), clearing
  command history, deleting files, and timestomping (.006, see §3). The *principle* an operator
  optimizes is **generating fewer artifacts in the first place** (in-memory/fileless execution,
  LOTL) rather than cleaning up after — because cleanup is itself an artifact.
- **In-memory / fileless (conceptual).** Memory-resident execution — staging via PowerShell,
  injecting into a host process, or storing obfuscated content in Registry/WMI/event logs
  (Obfuscated Files/Information **T1027**, incl. Fileless Storage T1027.011; Hide Artifacts
  **T1564**; Process Injection **T1055**) — minimizes *disk* artifacts. It does **not** leave *no*
  artifacts: it trades disk forensics for **memory forensics and EDR/behavioral telemetry.**

> **Professional norm restated (non-negotiable in authorized work):** a red team **documents** its
> footprint; it does **not** destroy the client's evidence. The correct workflow is
> *reproducibility and coordinated cleanup, not destruction*: keep operator activity logs and
> tooling logs so activity is auditable; remove implants/persistence in coordination with the
> client *after* the engagement, rather than erasing the client's ability to detect and learn.
> Unauthorized log manipulation and evidence tampering are crimes; any such testing happens only
> under an explicit RoE clause. See §0. (redteam.guide RoE template; lorikeetsecurity.com)

### Detection counterpart — the "local erasure is futile" thesis

- **Clearing a log ships its own alarm.** **Security Event ID 1102** ("audit log was cleared") and
  **System Event ID 104** ("log cleared") are written *before* the clear completes; combined with
  **Windows Event Forwarding (WEF)** shipping selected events to a hardened collector/SIEM, the
  act of clearing generates a preserved, high-fidelity alert. Service Control Manager EIDs
  7035/7036 can reveal the EventLog service being stopped.
  ([learn.microsoft.com WEF for intrusion detection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection);
  [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102); picussecurity.com T1562.002)
- **Telemetry has already left the building.** Forwarding + append-only/immutable SIEM storage
  (e.g. Azure Monitor / Microsoft Sentinel ingestion) puts events out of the operator's reach the
  instant they're written; **gaps in sequential Event Record IDs** betray clearing between
  forwarding intervals. (startupdefense.io T1070.001 — immutable-SIEM specifics secondary-sourced)
- **NTFS/journal forensics defeats disk-level anti-forensics.** `$SI`-vs-`$FN` comparison catches
  single timestomping; the **USN Journal** and `$MFT`+`$LogFile`+`$UsnJrnl` cross-correlation
  (Cowen's *TriForce*) catch double-timestomping and deleted-file traces; Prefetch parsing detects
  execution of known anti-forensic utilities. (attack.mitre.org T1070.006; unjaena.com)
- **Memory forensics catches fileless.** Volatility `windows.malfind` locates injected code via
  VAD tags and RWX/`PAGE_EXECUTE_READWRITE` regions and unbacked MZ headers — catching
  reflective/manually-mapped PE injection even after header stripping. (Blind spot: ordinary
  `LoadLibrary`/`CreateRemoteThread` DLL injection is visible via `dlllist`, not `malfind` —
  combine with `pslist`/`pstree`/`netscan`/`cmdline`.) AMSI still inspects deobfuscated script
  content regardless of encoding; ASR rules block obfuscated-script execution.
  (volatilityfoundation wiki; cyberengage.org; redcanary.com AMSI)

**The synthesis:** modern detection has moved *up* the Pyramid of Pain precisely because the
bottom (IPs, hashes, local logs) is cheap for attackers to change *and* increasingly ineffective
to change. Durable evasion — and therefore durable *detection* — lives in behavior, tool
fingerprints, and TTPs. An operator who understands this stops wasting effort on local cleanup;
a defender who understands this stops relying on host-local logs alone and forwards everything.

---

## 7. Threat-informed emulation & attribution

Red teaming is at its most valuable when it **emulates a specific, relevant adversary** rather
than showing off generic tricks — this tests whether the client can detect *the threats that
actually target them* (threat-informed defense).

- **Adversary emulation** reproduces a named actor's ATT&CK-mapped TTPs "in a safe, repeatable
  manner." MITRE's **Center for Threat-Informed Defense** publishes ready-to-run plans in the
  open **Adversary Emulation Library** — full-scope plans for named actors (e.g. **APT29**,
  **FIN6**) and micro/behavior-focused plans (e.g. web shells, AD enumeration), each with an
  `Infrastructure.md`. **MITRE ATT&CK Evaluations** benchmark EDR products against these.
  (ctid.mitre.org/resources/adversary-emulation-library; attack.mitre.org/resources/adversary-emulation-plans)
- **Attribution basics defenders use** (and therefore what emulation must be careful with):
  TTPs (top of the pyramid), infrastructure clustering (shared certs/JARM/registration/passive
  DNS), timing (working hours, compile times), and language/locale artifacts (§3).
- **How authorized emulation differs from real malicious activity — the four dividers:** it is
  **scoped, deconflicted, documented, and reversible**, executed against a consenting environment
  with a shared framework (ATT&CK) so results are measurable. A red team may *emulate* an
  adversary's false-flag behavior to test attribution processes — but it never actually frames a
  third party or destroys evidence, and always leaves a clean audit trail for the client.

---

## 8. Technique → ATT&CK → detection quick map

*(Technique IDs are the stable anchors; tactic labels reflect the 2025 Stealth / Defense-Impairment split — see §1.)*

| Operator goal | Layer | ATT&CK | Primary detection signal |
|---------------|-------|--------|--------------------------|
| Hide source IP | Network | T1090 (Proxy) | Reputation/Tor lists, impossible-travel, behavioral (IP feeds decaying) |
| Blend geographically | Network | T1090.003, T1584 | ORB/infra clustering, ASN + behavior anchors |
| Look like normal HTTPS | Traffic | T1071, T1573 | JA3/JA3S, JARM, malleable-profile signatures |
| Domain fronting | Traffic | T1090.004 | SNI ≠ Host mismatch (technique now largely dead on major CDNs) |
| DNS tunneling / DoH | Traffic | T1071.004, T1568.002 | Entropy/NXDOMAIN/timing anomalies; metadata correlation |
| Spoof timezone/locale | Attribution | T1614.001, T1070.006 | Compile-time heatmaps, $SI/$FN + USN journal, corroborate (forgeable) |
| Low-and-slow beacon | Timing | T1029, C2 | RITA/FFT persistence analysis (defeats jitter statistically) |
| Live off the land | Host | T1218, T1059, T1105 | Sysmon process telemetry, parent-child + baselining |
| Masquerade binaries | Host | T1036 | Renamed-LOLBin metadata/path analytics |
| Fileless / in-memory | Host | T1027, T1055, T1564 | AMSI, EDR injection telemetry, Volatility malfind |
| Impair defenses (AMSI/ETW/EDR) | Host | **T1685 / TA0112** (was T1562) | ETW EID 12, Sysmon EID 16/4, absence-of-telemetry, driver blocklist |
| Remove indicators | Footprint | T1070 (.001/.006) | Event ID 1102/104 forwarding, SIEM immutability, $MFT/USN journal |

---

## 9. How this maps into SecForge

- **For the offensive agent ([`ai_framework/`](../ai_framework/README.md)):** §0–§1 are compiled
  into standing rules in the [system prompt](../ai_framework/agent/system.py) — authorization-first,
  prefer the least-noisy action that still proves the point, document every action, stay in scope,
  and don't waste effort on local artifact-destruction. When an engagement needs a specific
  technique, the agent recalls the relevant §2–§6 principle and the [KB corpus](KNOWLEDGE_BASE.md).
- **For the defensive pillar ([`defense/`](../defense/README.md)):** the *detection counterpart*
  of each section is the checklist for "would this target see the attack?" — TLS/JA3 visibility,
  process telemetry (Sysmon), log forwarding/SIEM immutability, ETW/AMSI tamper monitoring, DNS
  anomaly monitoring, and impossible-travel blind spots.
- **For the knowledge base / labs:** the [`vuln_search/catalog/`](../vuln_search/catalog/INDEX.md)
  cards cover *what* to exploit; this file covers *how to operate covertly and how that's caught* —
  a natural companion for [`labs/`](../labs/README.md) exercises that pair an attack with its
  detection.

---

## 10. References

Grouped by section; all are public, authoritative sources. Items whose viability or taxonomy has
changed, or which are secondary/uncertain, are flagged in §0–§6 and in the verification note below.

**Standards, authorization & OPSEC doctrine**
- NIST SP 800-115 — https://csrc.nist.gov/pubs/sp/800/115/final ·
  PDF (incl. Appendix B RoE template) — https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf
- PTES Pre-engagement — http://www.pentest-standard.org/index.php/Pre-engagement ·
  https://pentest-standard.readthedocs.io/en/latest/preengagement_interactions.html
- RoE / CFAA 18 U.S.C. § 1030 framing — https://penetrationtestingauthority.com/rules-of-engagement-penetration-testing/ ·
  RoE template — https://redteam.guide/docs/Templates/roe_template/ · deconfliction — https://redteam.guide/docs/definitions/
- OPSEC 5-step process — https://csrc.nist.gov/glossary/term/operations_security ·
  DoD CDSE — https://www.cdse.edu/Portals/124/Documents/student-guides/GS130-guide.pdf ·
  DTIC OPSEC guide — https://apps.dtic.mil/sti/pdfs/AD1038572.pdf

**MITRE ATT&CK (note the 2025 Stealth / Defense-Impairment split)**
- Stealth (TA0005, current) — https://attack.mitre.org/tactics/TA0005/ ·
  Defense Impairment (TA0112, new) — https://attack.mitre.org/tactics/TA0112/ ·
  T1685 Disable or Modify Tools — https://attack.mitre.org/techniques/T1685/ ·
  legacy Defense Evasion (v15, pre-split) — https://attack.mitre.org/versions/v15/tactics/TA0005/ ·
  v19 split explainer — https://medium.com/mitre-attack/att-ck-v19-the-defense-evasion-split-ics-sub-techniques-new-ai-social-engineering-coverage-ff329cb65d66
- Techniques: T1090 (+.002/.003/.004), T1071(+.004), T1573, T1568(.002), T1583/T1584/T1608,
  T1614.001, T1070(+.001/.006), T1562(+.001/.002/.006), T1027(+.011), T1564, T1055, T1218, T1059,
  T1105, T1497(.003) — https://attack.mitre.org
- Adversary emulation — https://attack.mitre.org/resources/adversary-emulation-plans/ ·
  CTID Adversary Emulation Library — https://ctid.mitre.org/resources/adversary-emulation-library/ ·
  https://github.com/center-for-threat-informed-defense · ATT&CK Evaluations — https://www.attackiq.com/mitre-attack/

**Pyramid of Pain**
- https://www.attackiq.com/glossary/pyramid-of-pain-2/ ·
  https://www.activecountermeasures.com/hunt-what-hurts-the-pyramid-of-pain/ ·
  https://www.picussecurity.com/resource/glossary/what-is-pyramid-of-pain

**Network / infrastructure**
- Red Team Infrastructure Wiki — https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki ·
  SpecterOps "Designing Effective Covert Red Team Attack Infrastructure" —
  https://bluescreenofjeff.com/2017-12-05-designing-effective-covert-red-team-attack-infrastructure/
- Mandiant "China-Nexus / ORB Networks" — https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks ·
  GreyNoise "IP Reputation Fails against the Rotation Economy" — https://www.greynoise.io/blog/invisible-army-why-ip-reputation-fails-against-rotation-economy ·
  iVPN Tor-vs-VPN — https://www.ivpn.net/privacy-guides/adversaries-and-anonymity-systems-the-basics/ ·
  Microsoft Entra ID Protection — https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks ·
  Defender for Cloud Apps anomaly policy — https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

**Time / locale / timing**
- Mandiant APT1 report — https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf ·
  Securelist "The devil's in the Rich header" — https://securelist.com/the-devils-in-the-rich-header/84348/ ·
  BAE "Lazarus' False Flag Malware" — https://baesystemsai.blogspot.com/2017/02/lazarus-false-flag-malware.html ·
  KoreLogic PE resource languages — https://blog.korelogic.com/blog/2014/12/23/resource_language_codes ·
  DFIR Report Cobalt Strike pt.2 — https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/ ·
  RITA/beaconing — https://hunt.io/glossary/c2-beaconing · jitter-defeats-rules — https://www.deeptempo.ai/blogs/evading-rule-based-detection---part-1-c2-beaconing

**Traffic blending**
- JA3/JA3S — https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/ ·
  JARM — https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/ ·
  Unit 42 Malleable C2 — https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/ ·
  Domain fronting timeline — https://en.wikipedia.org/wiki/Domain_fronting ·
  AWS CloudFront protections — https://aws.amazon.com/blogs/security/enhanced-domain-protections-for-amazon-cloudfront-requests/ ·
  Mandiant APT29 domain fronting — https://cloud.google.com/blog/topics/threat-intelligence/apt29-domain-frontin/ ·
  ChamelDoH / DoH — https://www.nec.com/en/global/solutions/cybersecurity/blog/240920/index.html ·
  Cisco Talos "Detecting DGA" — https://blogs.cisco.com/security/talos/detecting-dga

**Host / LOTL / defensive surfaces / footprint**
- LOLBAS — https://lolbas-project.github.io/ · GTFOBins — https://gtfobins.org/ ·
  CrowdStrike 2025 Global Threat Report — https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/ ·
  CISA AA23-144a "Volt Typhoon" — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a ·
  Red Canary 2025 Threat Detection Report — https://redcanary.com/threat-detection-report/techniques/
- AMSI portal — https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal ·
  About Event Tracing (ETW) — https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing ·
  Windows Event Forwarding — https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection ·
  Event 1102 — https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 ·
  Sysmon — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Red Canary AMSI data source — https://redcanary.com/blog/threat-detection/better-know-a-data-source/amsi/ ·
  CrowdStrike patchless AMSI — https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/ ·
  Picus T1562.002 — https://www.picussecurity.com/resource/blog/t1562-002-disable-windows-event-logging ·
  Black Hills Sysmon EID breakdown — https://www.blackhillsinfosec.com/a-sysmon-event-id-breakdown/ ·
  Elastic "Detecting Command & Scripting Interpreter" — https://www.elastic.co/blog/detecting-command-scripting-interpreter
- Volatility malfind — https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal ·
  https://www.cyberengage.org/post/volatility-plugins-plugin-window-malfind-let-s-talk-about-it ·
  USN Journal / NTFS forensics — https://andreafortuna.org/2025/09/06/usn-journal/ · https://www.unjaena.com/en/blog/windows-artifact-guide

> **Verification note.** §2–§6 network/host claims are backed by direct multi-source fetches
> (MITRE, Microsoft Learn, vendor detection-engineering blogs); §0–§1 authorization/OPSEC and §7
> emulation are anchored to NIST SP 800-115, PTES, and the MITRE CTID library. Flagged
> uncertainties: (a) the **ATT&CK 2025 tactic split** is confirmed live, but treat exact
> release/edit dates as low-confidence — re-verify TA0005/TA0112/T1685 on attack.mitre.org;
> (b) domain-fronting viability and impossible-travel VPN/cloud exclusions change over time —
> re-verify per provider; (c) AMSI/ETW provider-internal event IDs (1101/1201), immutable-SIEM
> specifics, BYOVD's exact sub-technique mapping, and the "80% of samples use T1055" figure are
> secondary/single-sourced; (d) a few sources returned SSL/403 errors during research
> (0xc0decafe PE-timestamps, Cobalt Strike JARM, the T1562 parent page) and were corroborated via
> search-index excerpts against primary material.
