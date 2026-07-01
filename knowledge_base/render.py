"""Safe markdown → HTML.

*Security-critical.* The notes contain live XSS/SQLi payloads, so **every** text node and
code span is HTML-escaped before it reaches the document — the viewer must render a payload,
never execute it. Link targets are scheme-checked (``javascript:`` and friends are dropped).
Supports headings (with TOC anchors), fenced code, tables, lists, blockquotes, rules, and
inline emphasis/code/links. Returns ``(html, toc)``.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

_SAFE_LINK_RE = re.compile(r"^(https?:|mailto:|#|/|\.{0,2}/)", re.IGNORECASE)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_FENCE_RE = re.compile(r"^(\s*)(```|~~~)\s*([\w+-]*)\s*$")
_HR_RE = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_OL_RE = re.compile(r"^(\s*)\d+[.)]\s+(.*)$")
_UL_RE = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_BQ_RE = re.compile(r"^\s*>\s?(.*)$")


@dataclass
class TocItem:
    level: int
    text: str
    id: str


def _slug(text: str, used: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    slug = base
    n = 2
    while slug in used:
        slug = f"{base}-{n}"
        n += 1
    used.add(slug)
    return slug


# ── inline ──────────────────────────────────────────────────────────────────
_CODE_SPAN_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*|__([^_]+)__")
_ITALIC_RE = re.compile(r"(?<!\*)\*(?!\s)([^*]+?)\*(?!\*)|(?<!_)_(?!\s)([^_]+?)_(?!_)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_PLACEHOLDER = "\x00CODE{}\x00"


def render_inline(text: str) -> str:
    """Escape, then apply inline formatting. Code spans keep their literal (escaped) text."""
    # 1. Pull out code spans so inline rules never touch their contents.
    spans: list[str] = []

    def _stash(m: re.Match[str]) -> str:
        spans.append(html.escape(m.group(1), quote=False))
        return _PLACEHOLDER.format(len(spans) - 1)

    text = _CODE_SPAN_RE.sub(_stash, text)
    # 2. Escape everything else (payloads become inert text here).
    text = html.escape(text, quote=False)
    # 3. Links: [text](url) with a scheme allow-list.
    def _link(m: re.Match[str]) -> str:
        label, url = m.group(1), m.group(2)
        url = html.unescape(url)
        if not _SAFE_LINK_RE.match(url):
            return label  # drop unsafe target, keep the visible text
        return f'<a href="{html.escape(url, quote=True)}">{label}</a>'

    text = _LINK_RE.sub(_link, text)
    # 4. Emphasis.
    text = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1) or m.group(2)}</strong>", text)
    text = _ITALIC_RE.sub(lambda m: f"<em>{m.group(1) or m.group(2)}</em>", text)
    # 5. Restore code spans.
    for i, span in enumerate(spans):
        text = text.replace(_PLACEHOLDER.format(i), f"<code>{span}</code>")
    return text


# ── block ───────────────────────────────────────────────────────────────────
def _render_table(rows: list[str]) -> str:
    def cells(line: str) -> list[str]:
        line = line.strip().strip("|")
        return [c.strip() for c in line.split("|")]

    header = cells(rows[0])
    body = [cells(r) for r in rows[2:]]
    out = ["<table>", "<thead><tr>"]
    out += [f"<th>{render_inline(c)}</th>" for c in header]
    out.append("</tr></thead>")
    if body:
        out.append("<tbody>")
        for r in body:
            out.append("<tr>" + "".join(f"<td>{render_inline(c)}</td>" for c in r) + "</tr>")
        out.append("</tbody>")
    out.append("</table>")
    return "".join(out)


def _is_table_sep(line: str) -> bool:
    return bool(re.match(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$", line))


def render_markdown(text: str) -> tuple[str, list[dict]]:
    """Render markdown to safe HTML; also return a flat table-of-contents list."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    html_parts: list[str] = []
    toc: list[TocItem] = []
    used_ids: set[str] = set()
    i = 0
    n = len(lines)

    para: list[str] = []

    def flush_para() -> None:
        if para:
            html_parts.append(f"<p>{render_inline(' '.join(para).strip())}</p>")
            para.clear()

    while i < n:
        line = lines[i]
        fence = _FENCE_RE.match(line)
        if fence:
            flush_para()
            lang = fence.group(3)
            i += 1
            buf: list[str] = []
            while i < n and not _FENCE_RE.match(lines[i]):
                buf.append(lines[i])
                i += 1
            i += 1  # consume closing fence
            cls = f' class="language-{html.escape(lang, quote=True)}"' if lang else ""
            code = html.escape("\n".join(buf), quote=False)
            html_parts.append(f"<pre><code{cls}>{code}</code></pre>")
            continue

        h = _HEADING_RE.match(line)
        if h:
            flush_para()
            level = len(h.group(1))
            content = h.group(2).strip()
            slug = _slug(content, used_ids)
            toc.append(TocItem(level=level, text=_clean(content), id=slug))
            html_parts.append(f'<h{level} id="{slug}">{render_inline(content)}</h{level}>')
            i += 1
            continue

        if _HR_RE.match(line):
            flush_para()
            html_parts.append("<hr />")
            i += 1
            continue

        # table: a header row followed by a separator row.
        if "|" in line and i + 1 < n and _is_table_sep(lines[i + 1]):
            flush_para()
            block = [line, lines[i + 1]]
            i += 2
            while i < n and "|" in lines[i] and lines[i].strip():
                block.append(lines[i])
                i += 1
            html_parts.append(_render_table(block))
            continue

        if _BQ_RE.match(line):
            flush_para()
            buf2: list[str] = []
            while i < n and _BQ_RE.match(lines[i]):
                buf2.append(_BQ_RE.match(lines[i]).group(1))  # type: ignore[union-attr]
                i += 1
            inner, _ = render_markdown("\n".join(buf2))
            html_parts.append(f"<blockquote>{inner}</blockquote>")
            continue

        if _UL_RE.match(line) or _OL_RE.match(line):
            block, i = _collect_list_block(lines, i, n)
            html_parts.append(_render_list(block))
            continue

        if not line.strip():
            flush_para()
            i += 1
            continue

        para.append(line.strip())
        i += 1

    flush_para()
    return "".join(html_parts), [t.__dict__ for t in toc]


def _collect_list_block(lines: list[str], i: int, n: int) -> tuple[list[str], int]:
    block: list[str] = []
    while i < n and (_UL_RE.match(lines[i]) or _OL_RE.match(lines[i]) or
                     (lines[i].startswith((" ", "\t")) and lines[i].strip())):
        block.append(lines[i])
        i += 1
    return block, i


def _render_list(block: list[str]) -> str:
    """Render a (possibly one-level-nested) list. Ordered if the first marker is numeric."""
    ordered = bool(_OL_RE.match(block[0]))
    tag = "ol" if ordered else "ul"
    items: list[str] = []
    cur: list[str] | None = None
    nested: list[str] = []
    for line in block:
        m = _UL_RE.match(line) or _OL_RE.match(line)
        if m and len(m.group(1)) == 0:
            if cur is not None:
                items.append(_finish_item(cur, nested))
                nested = []
            cur = [m.group(2)]
        elif m:  # indented marker → nested list line
            nested.append(line.lstrip())
        elif cur is not None:  # continuation text
            cur.append(line.strip())
    if cur is not None:
        items.append(_finish_item(cur, nested))
    return f"<{tag}>" + "".join(items) + f"</{tag}>"


def _finish_item(cur: list[str], nested: list[str]) -> str:
    inner = render_inline(" ".join(cur).strip())
    if nested:
        inner += _render_list(nested)
    return f"<li>{inner}</li>"


def _clean(text: str) -> str:
    """Plain-text form of inline markdown (for TOC labels)."""
    text = _LINK_RE.sub(r"\1", text)
    return re.sub(r"[*_`]+", "", text).strip()
