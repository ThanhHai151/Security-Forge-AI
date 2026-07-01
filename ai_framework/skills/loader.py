"""Skill loader — discover ``SKILL.md`` manifests and serve them on demand (progressive disclosure).

Each skill is one directory with a canonical ``SKILL.md`` (English) and optional ``SKILL.<locale>.md``
siblings (see ``docs/SKILLS_AND_I18N.md``). The agent never carries every skill's full text: the
system prompt lists only a compact **catalog** (name + when-to-use trigger), and the model pulls the
full procedure with the ``load_skill`` tool when a trigger actually matches. That keeps the context
window lean while making all catalogued tradecraft reachable.

Frontmatter is parsed with a tiny purpose-built reader (no YAML dependency — the manifests use a
fixed, simple shape): ``name``, ``description`` (may be a ``>-`` folded scalar), ``tags``,
``languages``. The "## When to Use" section body becomes the catalog trigger line.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

_LIST_RE = re.compile(r"\[(.*)\]")


def _parse_frontmatter(text: str) -> tuple[dict[str, str | list[str]], str]:
    """Split ``text`` into (frontmatter dict, body). No fence → ({}, text)."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    # Find the closing fence (first "---" after line 0).
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, text
    front: dict[str, str | list[str]] = {}
    i = 1
    while i < end:
        line = lines[i]
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if not m:
            i += 1
            continue
        key, raw = m.group(1), m.group(2).strip()
        if raw in (">-", ">", "|", "|-"):  # folded/literal scalar → gather indented continuation
            parts: list[str] = []
            i += 1
            while i < end and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                if lines[i].strip():
                    parts.append(lines[i].strip())
                i += 1
            front[key] = " ".join(parts)
            continue
        lm = _LIST_RE.search(raw)
        if lm is not None:  # inline list: [a, b, c]
            front[key] = [x.strip() for x in lm.group(1).split(",") if x.strip()]
        else:
            front[key] = raw.strip().strip('"').strip("'")
        i += 1
    return front, "\n".join(lines[end + 1 :])


def _section(body: str, heading: str) -> str:
    """Return the text under a ``## <heading>`` section (until the next ``## ``), trimmed."""
    pat = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    m = pat.search(body)
    if not m:
        return ""
    rest = body[m.end() :]
    nxt = re.search(r"^##\s+", rest, re.MULTILINE)
    return (rest[: nxt.start()] if nxt else rest).strip()


class Skill(BaseModel):
    """A discovered skill manifest — its catalog metadata plus where to load the full text."""

    name: str
    description: str = ""
    when_to_use: str = ""
    tags: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=lambda: ["en"])
    dir: str = ""  # directory name (== name by convention)

    def trigger(self) -> str:
        """One-line 'when to use' for the catalog (first sentence/line of the section)."""
        src = self.when_to_use or self.description
        first = src.strip().split("\n", 1)[0].strip()
        return (first[:200] + "…") if len(first) > 200 else first


def _localized(canonical: Path, locale: str) -> Path:
    """``SKILL.md`` → ``SKILL.<locale>.md`` (locale != en); English is the bare name."""
    if locale == "en":
        return canonical
    return canonical.with_name(canonical.name.replace(".md", f".{locale}.md"))


class SkillRegistry:
    """Discovers ``*/SKILL.md`` under a root and serves catalog + full manifests on demand."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else Path(__file__).resolve().parent

    def _manifests(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        return sorted(self.root.glob("*/SKILL.md"))

    def skills(self) -> list[Skill]:
        out: list[Skill] = []
        for path in self._manifests():
            try:
                front, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
            except OSError:
                continue
            name = str(front.get("name") or path.parent.name)
            tags = front.get("tags") or []
            langs = front.get("languages") or ["en"]
            out.append(
                Skill(
                    name=name,
                    description=str(front.get("description") or ""),
                    when_to_use=_section(body, "When to Use"),
                    tags=[str(t) for t in tags] if isinstance(tags, list) else [],
                    languages=[str(x) for x in langs] if isinstance(langs, list) else ["en"],
                    dir=path.parent.name,
                )
            )
        return out

    def catalog(self) -> list[dict[str, str]]:
        """Compact list for the system prompt: name + one-line trigger."""
        return [{"name": s.name, "trigger": s.trigger()} for s in self.skills()]

    def get(self, name: str) -> Skill | None:
        return next((s for s in self.skills() if s.name == name or s.dir == name), None)

    def load(self, name: str, locale: str = "en") -> str | None:
        """Full manifest text for ``name`` in ``locale`` (falls back to English; None if unknown)."""
        skill = self.get(name)
        if skill is None:
            return None
        canonical = self.root / skill.dir / "SKILL.md"
        localized = _localized(canonical, locale)
        target = localized if localized.is_file() else canonical
        try:
            return target.read_text(encoding="utf-8")
        except OSError:
            return None
