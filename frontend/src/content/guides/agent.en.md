# How to use the Agent page (Expert Supervisor)

The Agent page is an **advisory console**. SecForge itself never calls an AI model and never
touches your target — it *plans* the assessment and hands you a briefing that **you** run with an
external coding agent (e.g. Claude Code). Whatever the agent finds is recorded back here, so the
notebook tracks coverage for each target across sessions.

> **Authorized use only.** Test systems you own or are explicitly permitted to assess.

## The layout

- **Left — Hermes notebook:** your target domains (and any discovered subdomains).
- **Middle — Vulnerability catalog:** every technique for the selected domain, each with a status.
- **Right — Terminal + drawers:** where you paste agent output, plus the **Ask** and **Plan** drawers.

## Step 1 — Add a target

1. In **Target domain** (top-left), type a domain or URL such as `example.com`, then press Enter or the **+** button.
2. To attach a discovered subdomain under a target, click the **+** on that target's row.
3. **Click** a domain to select it (the catalog to its right updates). **Double-click** it — or use the row menu (**⋮ → View diagram**) — to open its **mind map**.

## Step 2 — Ask the Supervisor

1. Open the **Ask** drawer (the magnifier button on the far right).
2. In **"What are you testing for?"**, describe the goal — e.g. *"check authentication, authorization, and the /api/query endpoint"*.
3. Choose a **Scan mode**:
   - **Quick** — a handful of high-impact classes, time-boxed (good for a fast triage / CI).
   - **Standard** — balanced coverage of the whole attack surface (the default).
   - **Deep** — exhaustive, with active vulnerability chaining.
4. Complete **Rules of engagement**: select the agent harness and asset criticality; enter the
   signed authorization reference, testing window, exclusions, and subdomain policy; then confirm
   written authorization. Missing fields are allowed for planning but produce a blocked harness
   that prohibits target traffic.
5. Click **Ask the Supervisor**.

## Step 3 — Read the investigation plan

Open the **Plan** drawer to see harness readiness, any blocking RoE fields, the ranked
**investigation order**, the detected **app archetype**
(e.g. "social network" or "multi-user data management"), the **skills** picked for the job,
and **Questions to resolve**. Those questions form an evidence chain: map the surface, identify
the implementation, run a paired safe control, then prove minimum impact. Conditional questions
tell the agent when to continue or prune a branch. The top step is automatically marked *in
progress* (an amber ring on that technique in the catalog).

## Step 4 — Run it with your coding agent

Click **Copy harness** and hand the generated briefing (RoE, gates, phases, plan, questions, and
skills) to your selected external agent (Claude Code, OpenAI Codex, Cursor, or another host).
Ask it to answer every question from logs or source and to skip conditions that are false.
**SecForge advises; the agent
executes** — it does the real recon, exploitation, and proof-of-concept validation against the
target. SecForge deliberately never sends traffic to the target itself.

## Step 5 — Report the results back (Terminal → Ingest)

Paste your agent's raw output into the **Terminal** box and click **Ingest**. SecForge stores it
verbatim and mechanically extracts these marker lines (one per line, anywhere in the text):

```text
CONFIRMED: <technique name> [<severity>] — <evidence / how you confirmed it>
NEW_FINDING_TYPE: <short label> — JUSTIFICATION: <why it isn't an existing category>
```

- `[<severity>]` is optional but recommended: one of `critical | high | medium | low | info`. It sets the report/SARIF severity for that finding (e.g. a leaked live credential or unauthenticated full-DB write = `critical`).
- Ingest can only promote a finding to **unconfirmed**. Marking something **confirmed** is always a deliberate human action in the catalog (Step 6).

## Step 6 — Track coverage (Vulnerability catalog)

In the middle column, use each technique's dropdown to set its status — **untested**, **unconfirmed**,
or **confirmed** — and use the filter to show only one status. Click a technique to preview its
exploit chain inline; double-click to open the full mind map focused on it.

## Step 7 — Export a report

Click **Download SARIF** to export the domain's confirmed/unconfirmed findings as a **SARIF 2.1.0**
file — ready to upload to CI or GitHub code scanning. Severity comes from each finding's recorded
severity (falling back to a per-class default).

## Good to know

- **Continuous** mode is locked (a redesign is pending) — use **Single run**.
- The notebook is red-team only. Source-code review and dependency scanning live on the **Defense** page.
- Nothing here is destructive on its own: SecForge only advises and records — your external agent is what acts.
