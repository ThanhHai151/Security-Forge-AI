import { ShieldChevron, List, Translate, Sun, Moon } from "@phosphor-icons/react";
import { LOCALES } from "../i18n/strings";

function NavLink({ href, active, children }) {
  return (
    <a
      href={href}
      className={`px-2 sm:px-3 py-1.5 text-[13px] font-medium transition-colors whitespace-nowrap ${
        active ? "text-emerald-400" : "text-zinc-400 hover:text-zinc-100"
      }`}
      style={active ? { boxShadow: "inset 0 -2px 0 #22B890" } : undefined}
      aria-current={active ? "page" : undefined}
    >
      {children}
    </a>
  );
}

export default function TopNav({ section, locale, onLocale, theme, onTheme, t, onMenu, onBrand }) {
  const isLight = theme === "light";
  return (
    <header className="fixed top-0 inset-x-0 z-40 h-[64px]">
      <div className="absolute inset-0 bg-zinc-950/90 backdrop-blur-md" />
      {/* Glowing teal hairline under the bar — the SGU signature accent line */}
      <div
        className="absolute bottom-0 inset-x-0 h-px"
        style={{
          background:
            "linear-gradient(90deg, transparent 0%, rgba(34,184,144,0.5) 20%, rgba(34,184,144,0.8) 50%, rgba(34,184,144,0.5) 80%, transparent 100%)",
          boxShadow: "0 0 8px rgba(34,184,144,0.4)",
        }}
      />

      <div className="relative h-full px-4 sm:px-6 flex items-center justify-between gap-3">
        <div className="flex items-center gap-1 sm:gap-3 min-w-0">
          {section === "docs" && (
            <button
              onClick={onMenu}
              aria-label="Toggle navigation"
              className="lg:hidden text-zinc-400 hover:text-zinc-100 transition-colors"
            >
              <List size={22} />
            </button>
          )}

          <button
            onClick={onBrand}
            className="flex items-center gap-2.5 shrink-0 group"
            aria-label={`${t.brand} home`}
          >
            <span className="w-8 h-8 bg-emerald-500/15 border border-emerald-500/25 flex items-center justify-center transition-colors group-hover:border-emerald-400/50">
              <ShieldChevron size={16} weight="fill" className="text-emerald-400" />
            </span>
            <span className="hidden sm:flex flex-col leading-none text-left">
              <span className="text-[15px] font-bold text-zinc-100 tracking-tight">
                {t.brand}
              </span>
              <span className="text-[10.5px] font-mono text-zinc-500 mt-0.5 tracking-wide">
                {t.subtitle}
              </span>
            </span>
          </button>

          {/* Primary navigation */}
          <nav className="flex items-center ml-1 sm:ml-4" aria-label="Primary">
            <NavLink href="#/docs" active={section === "docs"}>
              {t.navDocs}
            </NavLink>
            <NavLink href="#/pentest" active={section === "pentest"}>
              {t.navPentest}
            </NavLink>
            <NavLink href="#/vuln" active={section === "vuln"}>
              {t.navVuln}
            </NavLink>
            <NavLink href="#/defense" active={section === "defense"}>
              {t.navDefense}
            </NavLink>
            <NavLink href="#/ai" active={section === "ai"}>
              {t.navAi}
            </NavLink>
            <NavLink href="#/router" active={section === "router"}>
              {t.navRouter}
            </NavLink>
          </nav>
        </div>

        <div className="flex items-center gap-2 sm:gap-4 shrink-0">
          {/* Locale toggle — UI strings + content both switch */}
          <div className="flex items-center bg-zinc-900/70 border border-white/[0.06] p-0.5">
            <Translate size={14} className="text-zinc-500 mx-1.5 hidden sm:block" />
            {LOCALES.map((lc) => (
              <button
                key={lc}
                onClick={() => onLocale(lc)}
                className={`px-2 sm:px-2.5 py-1 text-[12px] font-semibold uppercase tracking-wider transition-colors ${
                  locale === lc
                    ? "bg-zinc-800 text-emerald-400"
                    : "text-zinc-500 hover:text-zinc-200"
                }`}
              >
                {lc}
              </button>
            ))}
          </div>

          {/* Light/dark theme toggle — flips the navy-ink palette, keeps the teal accent */}
          <button
            onClick={onTheme}
            aria-label={isLight ? "Switch to dark theme" : "Switch to light theme"}
            title={isLight ? "Dark mode" : "Light mode"}
            className="flex items-center justify-center w-8 h-8 bg-zinc-900/70 border border-white/[0.06] text-zinc-400 hover:text-emerald-400 hover:border-emerald-400/40 transition-colors shrink-0"
          >
            {isLight ? <Moon size={15} weight="fill" /> : <Sun size={15} weight="fill" />}
          </button>
        </div>
      </div>
    </header>
  );
}
