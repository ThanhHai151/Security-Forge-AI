import { Marked } from "marked";
import { markedHighlight } from "marked-highlight";
import hljs from "highlight.js/lib/core";

import sql from "highlight.js/lib/languages/sql";
import bash from "highlight.js/lib/languages/bash";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import http from "highlight.js/lib/languages/http";
import python from "highlight.js/lib/languages/python";

const LANGS = { sql, bash, javascript, json, xml, http, python };
for (const [name, def] of Object.entries(LANGS)) hljs.registerLanguage(name, def);
const AUTO = Object.keys(LANGS);

const marked = new Marked(
  markedHighlight({
    emptyLangClass: "hljs",
    langPrefix: "hljs language-",
    highlight(code, lang) {
      try {
        if (lang && hljs.getLanguage(lang)) {
          return hljs.highlight(code, { language: lang }).value;
        }
        return hljs.highlightAuto(code, AUTO).value;
      } catch {
        return code;
      }
    },
  })
);
marked.setOptions({ gfm: true, breaks: false });

/** Stable, URL-safe id for a heading — shared by the TOC and the rendered anchors. */
export function slugify(text) {
  return text
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

/** Pull `##` / `###` headings from markdown source, in document order, de-duplicated. */
export function extractToc(md) {
  const items = [];
  const seen = Object.create(null);
  let inFence = false;
  for (const raw of md.split(/\r?\n/)) {
    if (/^\s*```/.test(raw)) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = /^(#{2,3})\s+(.+?)\s*#*\s*$/.exec(raw);
    if (!m) continue;
    const depth = m[1].length;
    const text = m[2].replace(/`/g, "").replace(/\*\*/g, "").trim();
    let slug = slugify(text);
    if (seen[slug] != null) { seen[slug] += 1; slug = `${slug}-${seen[slug]}`; }
    else { seen[slug] = 0; }
    items.push({ depth, text, slug });
  }
  return items;
}

const stripTags = (s) => s.replace(/<[^>]*>/g, "");

/**
 * Render a card body to HTML and its TOC. Heading ids are assigned in the same
 * document order as the TOC, so anchors and the contents list always agree.
 * External links open in a new tab; relative repo links become quiet, non-navigating
 * references (the markdown points at files that don't exist inside the SPA).
 */
export function renderDoc(md) {
  const toc = extractToc(md);
  let html = marked.parse(md ?? "");

  let i = 0;
  html = html.replace(
    /<(h[23])([^>]*)>([\s\S]*?)<\/\1>/g,
    (_m, tag, attrs, inner) => {
      const item = toc[i++];
      const id = item ? item.slug : slugify(stripTags(inner));
      return `<${tag} id="${id}"${attrs}>${inner}</${tag}>`;
    }
  );

  html = html.replace(
    /<a\s+href="([^"]*)"([^>]*)>([\s\S]*?)<\/a>/g,
    (_m, href, _attrs, text) => {
      if (/^https?:\/\//i.test(href)) {
        return `<a href="${href}" target="_blank" rel="noopener noreferrer" class="ext-link">${text}</a>`;
      }
      return `<span class="rel-ref" title="Reference inside the repository: ${href}">${text}</span>`;
    }
  );

  return { html, toc };
}
