# How to use the Defense page

The Defense page reviews a **local project directory** two ways at once: a **static code review**
that scans your source for catalogued vulnerability classes, and a **dependency (SCA) scan** that
flags known-vulnerable packages. Every finding is a *suggestion* — SecForge never modifies your code.

> **Authorized use only.** Review projects you own or are permitted to assess.

## Step 1 — Point it at a project

In the input box, enter the **absolute path** to the project directory you want to review, for example
`D:\projects\my-app` (Windows) or `/home/me/my-app` (Linux/macOS). Press Enter or click **Review**.

## Step 2 — (Optional) enable online advisories

Tick **Check advisories online (OSV)** to look up your dependencies against the public OSV
vulnerability database. Leave it **off** to run fully offline — the code review still works either way;
only the dependency CVE lookup needs the network.

## Step 3 — Run the review

Click **Review**. When it finishes, up to two sections appear:

### Code review

Each finding shows:

- a **severity** badge (critical / high / medium / low),
- the **file:line** where it was found,
- a short **message** describing the issue,
- the offending **code snippet**, and
- an expandable **remediation** with concrete, class-specific hardening guidance.

A severity tally and the number of files scanned head the section. "No findings" means nothing
matched the signature set — not a guarantee the code is safe.

### Dependencies

Vulnerable packages are listed with:

- the package **name@version**,
- its **ecosystem** and manifest **source**,
- linked **advisories** (click the advisory id to open it), and
- the version each issue is **fixed in**.

With online checks turned off, this section shows a hint instead of results.

## Good to know

- **Code review** is signature-based over your source files; **dependency scanning** parses your
  manifests (e.g. `package.json`, `requirements.txt`) and checks them against advisories.
- Findings are **advisory only** — apply the fixes yourself, then re-run the review to confirm the
  issue is gone.
- This page is standalone: it does not feed the Agent page's notebook.
