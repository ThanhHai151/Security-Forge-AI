/**
 * Loads the vulnerability dictionary from the sibling `vuln_search/catalog/` directory
 * at build time (Vite glob, raw markdown) and shapes it into a category tree the viewer
 * can render. The catalog is the canonical content source — this module only reads it.
 *
 * Structure produced:
 *   categories: [{ name, items: [Card] }]
 *   bySlug:     { [slug]: Card }
 *   Card:       { slug, title, category, status, locales: { en, vi? }, hasVi }
 *   locale doc: { title, summary, owasp, status, body }
 */

const CARD_FILES = import.meta.glob(
  "../../../vuln_search/catalog/**/README*.md",
  { query: "?raw", import: "default", eager: true }
);
const INDEX_FILE = import.meta.glob(
  "../../../vuln_search/catalog/INDEX.md",
  { query: "?raw", import: "default", eager: true }
);
// Content docs that live in `docs/` (not vuln classes) and are surfaced in the viewer —
// only files on the whitelist below are shown.
const DOC_FILES = import.meta.glob(
  "../../../docs/*.md",
  { query: "?raw", import: "default", eager: true }
);
const DOC_SOURCES = [
  {
    file: "RED_TEAM_OPSEC.md",
    slug: "red-team-opsec",
    category: "Red-team tradecraft",
  },
];

const slugFromPath = (path) => {
  const m = /catalog\/([^/]+)\/README/.exec(path);
  return m ? m[1] : null;
};
const localeFromPath = (path) => (/README\.([a-z]{2})\.md$/.exec(path)?.[1] ?? "en");

/** Parse one card: split the meta header (title + blockquote + bold fields) from the body. */
function parseCard(raw) {
  const lines = raw.split(/\r?\n/);
  let i = 0;
  while (i < lines.length && !/^#\s+/.test(lines[i])) i++;
  const title = i < lines.length ? lines[i].replace(/^#\s+/, "").trim() : "";
  if (i < lines.length) i++;

  const head = [];
  const body = [];
  let inBody = false;
  for (; i < lines.length; i++) {
    if (!inBody && /^##\s+/.test(lines[i])) inBody = true;
    (inBody ? body : head).push(lines[i]);
  }

  let summary = head
    .filter((l) => /^\s*>/.test(l))
    .map((l) => l.replace(/^\s*>\s?/, ""))
    .join(" ")
    .split(/\*\*(?:Deep dive|Tài liệu)/)[0]
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/\*\*/g, "")
    .replace(/`/g, "")
    .trim();

  const meta = (keys) => {
    for (const l of head) {
      const m = /^\*\*([^:*]+):\*\*\s*(.+)$/.exec(l.trim());
      if (m && keys.some((k) => m[1].toLowerCase().includes(k))) {
        return m[2].replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/`/g, "").trim();
      }
    }
    return "";
  };

  const owasp = meta(["owasp", "aliases", "tên gọi"]);
  const statusRaw = meta(["status", "trạng thái"]).toLowerCase();
  const status = /stub/.test(statusRaw) ? "stub" : statusRaw ? "complete" : "";

  return { title, summary, owasp, status, body: body.join("\n").trim() };
}

/** Parse INDEX.md into the canonical ordered category → item structure. */
function parseIndex(raw) {
  const cats = [];
  let cur = null;
  for (const line of raw.split(/\r?\n/)) {
    const h = /^##\s+(.+?)\s*$/.exec(line);
    if (h) { cur = { name: h[1].trim(), items: [] }; cats.push(cur); continue; }
    const it = /^-\s+(.*?)\[(.+?)\]\((\w[\w-]*)\/README\.md\)/.exec(line);
    if (it && cur) {
      const flags = it[1];
      cur.items.push({
        title: it[2].trim(),
        slug: it[3].trim(),
        indexStatus: flags.includes("✅") ? "complete" : "stub",
      });
    }
  }
  return cats.filter((c) => c.items.length);
}

// ── Build the per-slug locale map from the loaded files ──
const cards = {};
for (const [path, raw] of Object.entries(CARD_FILES)) {
  const slug = slugFromPath(path);
  if (!slug) continue;
  const locale = localeFromPath(path);
  (cards[slug] ??= { slug, locales: {} }).locales[locale] = parseCard(raw);
}

const indexRaw = Object.values(INDEX_FILE)[0] ?? "";
const indexCats = parseIndex(indexRaw);

const vulnCategories = indexCats.map((cat) => ({
  name: cat.name,
  items: cat.items
    .filter((it) => cards[it.slug])
    .map((it) => {
      const card = cards[it.slug];
      const en = card.locales.en ?? Object.values(card.locales)[0];
      return {
        slug: it.slug,
        title: en?.title || it.title,
        category: cat.name,
        status: en?.status || it.indexStatus,
        owasp: en?.owasp || "",
        summary: en?.summary || "",
        hasVi: Boolean(card.locales.vi),
        locales: card.locales,
      };
    }),
}));

// Build design-note categories from the whitelisted `docs/` files (keyed by basename).
const docByFile = Object.fromEntries(
  Object.entries(DOC_FILES).map(([path, raw]) => [path.split("/").pop(), raw])
);
const docCategoryMap = new Map();
for (const { file, slug, category } of DOC_SOURCES) {
  const raw = docByFile[file];
  if (!raw) continue;
  const parsed = parseCard(raw);
  const viFile = file.replace(/\.md$/, ".vi.md");
  const viRaw = docByFile[viFile];
  const viParsed = viRaw ? parseCard(viRaw) : null;
  const locales = { en: parsed };
  if (viParsed) locales.vi = viParsed;
  const item = {
    slug,
    title: parsed.title || file,
    category,
    status: parsed.status || "complete",
    owasp: parsed.owasp || "",
    summary: parsed.summary || "",
    hasVi: Boolean(viParsed),
    locales,
  };
  if (!docCategoryMap.has(category)) docCategoryMap.set(category, []);
  docCategoryMap.get(category).push(item);
}
const docCategories = [...docCategoryMap.entries()].map(([name, items]) => ({ name, items }));

export const categories = [...vulnCategories, ...docCategories];

export const allCards = categories.flatMap((c) => c.items);
export const bySlug = Object.fromEntries(allCards.map((c) => [c.slug, c]));

export const stats = {
  total: allCards.length,
  categories: categories.length,
  complete: allCards.filter((c) => c.status === "complete").length,
  bilingual: allCards.filter((c) => c.hasVi).length,
};

/** Resolve the doc for a card in the requested locale, English-fallback (i18n rule). */
export function docFor(card, locale) {
  return card.locales[locale] ?? card.locales.en ?? Object.values(card.locales)[0];
}
