import { CaretRight } from "@phosphor-icons/react";
import { localizeCategory } from "../i18n/strings";

function Stat({ value, label }) {
  return (
    <div className="flex flex-col">
      <span className="text-[2rem] font-bold text-emerald-400 tabular-nums leading-none">
        {value}
      </span>
      <span className="mt-1.5 text-[11px] font-mono uppercase tracking-wider text-zinc-500">
        {label}
      </span>
    </div>
  );
}

function CategoryCard({ cat, onSelect, t, locale }) {
  return (
    <section className="border border-white/[0.07] bg-zinc-900/30">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
        <h3 className="text-[12px] font-semibold uppercase tracking-wider text-zinc-300">
          {localizeCategory(cat.name, locale)}
        </h3>
        <span className="text-[11px] font-mono tabular-nums text-zinc-600">
          {cat.items.length}
        </span>
      </div>
      <ul>
        {cat.items.map((item) => (
          <li key={item.slug}>
            <button
              onClick={() => onSelect(item.slug)}
              className="nav-row group w-full flex items-center gap-2.5 px-4 py-2 text-left"
            >
              <span
                className="w-1.5 h-1.5 shrink-0"
                style={{
                  background: item.status === "complete" ? "#22B890" : "#F5B547",
                  boxShadow:
                    item.status === "complete"
                      ? "0 0 6px rgba(34,184,144,0.7)"
                      : "none",
                }}
              />
              <span className="flex-1 text-[13px] text-zinc-300 group-hover:text-zinc-100 truncate">
                {item.title}
              </span>
              <CaretRight
                size={12}
                className="text-zinc-700 group-hover:text-emerald-400 transition-colors shrink-0"
              />
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function Landing({ categories, stats, onSelect, t, locale }) {
  return (
    <div className="page-enter max-w-[1100px]">
      <header className="pt-2 pb-8">
        <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          {t.heroKicker}
        </p>
        <h1 className="mt-3 text-[2.3rem] sm:text-[3rem] font-bold text-zinc-50 tracking-tight leading-[1.08] text-balance max-w-[20ch]">
          {t.heroTitle}
        </h1>
        <p className="mt-5 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[66ch]">
          {t.heroLead}
        </p>

        <div className="mt-9 flex flex-wrap gap-x-12 gap-y-6">
          <Stat value={stats.total} label={t.statClasses} />
          <Stat value={stats.categories} label={t.statCategories} />
          <Stat value={stats.complete} label={t.statComplete} />
          <Stat value={stats.bilingual} label={t.statBilingual} />
        </div>
      </header>

      <h2 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 mb-4 flex items-center gap-2.5">
        <span className="w-4 h-px bg-emerald-500/60" />
        {t.browseBy}
      </h2>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {categories.map((cat) => (
          <CategoryCard key={cat.name} cat={cat} onSelect={onSelect} t={t} locale={locale} />
        ))}
      </div>

      <footer className="mt-10 pt-5 border-t border-white/[0.06] text-[12px] text-zinc-500">
        {t.authNote}
      </footer>
    </div>
  );
}
