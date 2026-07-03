/**
 * Tiny hash router for the SPA (agent build). Sections: Docs (knowledge base), Pentest tool
 * catalog, and Agent (the Expert Supervisor console) — plus deep links into a single doc
 * (`#/docs/<slug>`). Docs is the home/default.
 *
 * Hash shapes:
 *   #/                 → docs (home)
 *   #/docs             → docs index (category browser)
 *   #/docs/<slug>      → a single vulnerability doc
 *   #/pentest          → pentest tool catalog
 *   #/vuln             → vuln search (catalog + CVE lookup)
 *   #/defense          → defense (codebase review)
 *   #/agent            → Agent console (Expert Supervisor; Continuous is locked)
 *   #/ai, #/auto       → back-compat: both fold into /agent
 *   #/router           → back-compat: the old Providers page was removed; falls through to docs
 *   #/<slug>           → back-compat: opens that doc under /docs
 */
import { bySlug } from "../content/catalog";

/** Parse a `window.location.hash` string into `{ section, slug }`. */
export function parseRoute(hash) {
  const raw = decodeURIComponent((hash || "").replace(/^#\/?/, "")).trim();
  const parts = raw.split("/").filter(Boolean);

  if (parts.length === 0) return { section: "docs", slug: "" };

  const [head, ...rest] = parts;
  if (head === "docs") {
    const slug = rest[0] && bySlug[rest[0]] ? rest[0] : "";
    return { section: "docs", slug };
  }
  if (head === "pentest") return { section: "pentest", slug: "" };
  if (head === "vuln") return { section: "vuln", slug: "" };
  if (head === "defense") return { section: "defense", slug: "" };
  if (head === "agent" || head === "ai" || head === "auto") return { section: "agent", slug: "" };

  // Back-compat: a bare known slug (`#/sql_injection`) opens that doc.
  if (bySlug[head]) return { section: "docs", slug: head };

  return { section: "docs", slug: "" };
}
