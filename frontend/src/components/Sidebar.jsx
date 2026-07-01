import { useState } from "react";
import { CaretRight } from "@phosphor-icons/react";
import SearchInput from "./SearchInput";
import { localizeCategory } from "../i18n/strings";

function ItemRow({ item, active, onSelect }) {
  return (
    <button
      onClick={() => onSelect(item.slug)}
      className={`nav-row w-full flex items-center gap-2.5 pl-5 pr-3 py-[7px] text-left text-[13px] ${
        active
          ? "bg-zinc-800 text-zinc-100"
          : "text-zinc-400 hover:text-zinc-100"
      }`}
      style={active ? { boxShadow: "inset 2px 0 0 #22B890" } : undefined}
    >
      <span
        className="w-1.5 h-1.5 shrink-0"
        title={item.status === "complete" ? "Complete" : "Draft"}
        style={{
          background: item.status === "complete" ? "#22B890" : "#F5B547",
          boxShadow:
            item.status === "complete"
              ? "0 0 6px rgba(34,184,144,0.7)"
              : "none",
        }}
      />
      <span className="truncate flex-1">{item.title}</span>
    </button>
  );
}

function Category({ cat, activeSlug, onSelect, forceOpen, locale }) {
  const [open, setOpen] = useState(true);
  const expanded = forceOpen || open;
  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-left group"
      >
        <CaretRight
          size={12}
          weight="bold"
          className={`text-zinc-600 transition-transform duration-150 ${
            expanded ? "rotate-90" : ""
          }`}
        />
        <span className="flex-1 text-[11px] font-bold uppercase tracking-wider text-zinc-300 group-hover:text-zinc-100 transition-colors">
          {localizeCategory(cat.name, locale)}
        </span>
        <span className="text-[11px] font-mono tabular-nums text-zinc-600">
          {cat.items.length}
        </span>
      </button>
      {expanded && (
        <div className="pb-1.5">
          {cat.items.map((item) => (
            <ItemRow
              key={item.slug}
              item={item}
              active={item.slug === activeSlug}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function Sidebar({
  categories,
  matchCount,
  activeSlug,
  onSelect,
  query,
  onQuery,
  searchRef,
  t,
  locale,
}) {
  const searching = query.trim().length > 0;
  return (
    <div className="flex flex-col h-full bg-zinc-950/40">
      <div className="px-4 py-3 border-b border-white/[0.06] space-y-2">
        <SearchInput
          value={query}
          onChange={onQuery}
          placeholder={t.searchPlaceholder}
          inputRef={searchRef}
        />
        {searching && (
          <p className="text-[11px] font-mono text-zinc-500 px-0.5">
            {matchCount > 0 ? t.resultsCount(matchCount) : t.noResults}
          </p>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-1">
        {categories.length === 0 && (
          <p className="px-5 py-8 text-[13px] text-zinc-500">{t.noResults}.</p>
        )}
        {categories.map((cat) => (
          <Category
            key={cat.name}
            cat={cat}
            activeSlug={activeSlug}
            onSelect={onSelect}
            forceOpen={searching}
            locale={locale}
          />
        ))}
      </nav>
    </div>
  );
}
