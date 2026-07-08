/**
 * Loads the in-app "How to use" guides from `content/guides/<page>.<locale>.md` at build time
 * (Vite raw-markdown glob, same technique as `catalog.js`). Keeps the long-form instructions in
 * plain markdown files instead of escaped JS strings, and reuses the doc markdown renderer.
 */
const GUIDE_FILES = import.meta.glob(
  "./guides/*.md",
  { query: "?raw", import: "default", eager: true }
);

// Key by "<page>.<locale>" from the filename, e.g. "agent.en".
const byKey = Object.fromEntries(
  Object.entries(GUIDE_FILES).map(([path, raw]) => [path.split("/").pop().replace(/\.md$/, ""), raw])
);

/** Guide markdown for a page ("agent" | "defense") in a locale, English-fallback. */
export function getGuide(page, locale = "en") {
  return byKey[`${page}.${locale}`] ?? byKey[`${page}.en`] ?? "";
}
