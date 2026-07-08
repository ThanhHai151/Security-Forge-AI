import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { X } from "@phosphor-icons/react";

import TopNav from "./components/TopNav";
import Sidebar from "./components/Sidebar";
import Toc from "./components/Toc";
import DocView from "./components/DocView";
import Landing from "./components/Landing";
import Pentest from "./components/Pentest";
import Agent from "./components/Agent";
import VulnSearch from "./components/VulnSearch";
import Defense from "./components/Defense";

import { categories, bySlug, stats, docFor } from "./content/catalog";
import { renderDoc } from "./lib/markdown";
import { parseRoute } from "./lib/route";
import { STRINGS } from "./i18n/strings";

const LOCALE_KEY = "secforge_locale";
const THEME_KEY = "secforge_theme";

function filterCategories(query, locale) {
  const q = query.trim().toLowerCase();
  if (!q) return { list: categories, count: stats.total };
  let count = 0;
  const list = categories
    .map((cat) => {
      const items = cat.items.filter((item) => {
        const doc = docFor(item, locale);
        const hay = `${item.title} ${item.owasp} ${item.summary} ${item.slug} ${doc?.title ?? ""} ${doc?.summary ?? ""}`.toLowerCase();
        return hay.includes(q);
      });
      count += items.length;
      return { ...cat, items };
    })
    .filter((cat) => cat.items.length > 0);
  return { list, count };
}

export default function App() {
  const [locale, setLocale] = useState(
    () => localStorage.getItem(LOCALE_KEY) || "en"
  );
  const [theme, setTheme] = useState(() =>
    document.documentElement.classList.contains("light") ? "light" : "dark"
  );
  const [route, setRoute] = useState(() => parseRoute(window.location.hash));
  const [query, setQuery] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const searchRef = useRef(null);

  const t = STRINGS[locale] ?? STRINGS.en;
  const { section, slug } = route;

  useEffect(() => {
    localStorage.setItem(LOCALE_KEY, locale);
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    localStorage.setItem(THEME_KEY, theme);
    document.documentElement.classList.toggle("light", theme === "light");
  }, [theme]);

  useEffect(() => {
    const onHash = () => {
      setRoute(parseRoute(window.location.hash));
      setDrawerOpen(false);
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // In the Docs section, global "/" focuses the dictionary search; Escape closes the drawer.
  useEffect(() => {
    const onKey = (e) => {
      if (
        e.key === "/" &&
        section === "docs" &&
        document.activeElement?.tagName !== "INPUT"
      ) {
        e.preventDefault();
        setDrawerOpen(true);
        requestAnimationFrame(() => searchRef.current?.focus());
      } else if (e.key === "Escape") {
        setDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [section]);

  const navigate = useCallback((path) => {
    window.location.hash = path;
    setDrawerOpen(false);
  }, []);

  const goDocs = useCallback(() => navigate("/docs"), [navigate]);
  const openDoc = useCallback((s) => navigate(`/docs/${s}`), [navigate]);

  const toggleTheme = useCallback(
    () => setTheme((prev) => (prev === "light" ? "dark" : "light")),
    []
  );

  const { list: filtered, count: matchCount } = useMemo(
    () => filterCategories(query, locale),
    [query, locale]
  );

  const activeCard = section === "docs" && slug ? bySlug[slug] : null;
  const doc = useMemo(() => {
    if (!activeCard) return null;
    const resolved = docFor(activeCard, locale);
    const { html, toc } = renderDoc(resolved?.body ?? "");
    return { resolved, html, toc };
  }, [activeCard, locale]); // eslint-disable-line react-hooks/exhaustive-deps

  const usingFallback =
    activeCard && locale !== "en" && !activeCard.locales[locale];

  const sidebar = (
    <Sidebar
      categories={filtered}
      matchCount={matchCount}
      activeSlug={slug}
      onSelect={openDoc}
      query={query}
      onQuery={setQuery}
      searchRef={searchRef}
      t={t}
      locale={locale}
    />
  );

  return (
    <div className="min-h-[100dvh]">
      <TopNav
        section={section}
        locale={locale}
        onLocale={setLocale}
        theme={theme}
        onTheme={toggleTheme}
        t={t}
        onMenu={() => setDrawerOpen(true)}
        onBrand={goDocs}
      />

      {section === "pentest" && (
        <main className="pt-[64px]">
          <Pentest t={t} locale={locale} />
        </main>
      )}

      {section === "vuln" && (
        <main className="pt-[64px]">
          <VulnSearch t={t} locale={locale} onOpenDoc={openDoc} />
        </main>
      )}

      {section === "defense" && (
        <main className="pt-[64px]">
          <Defense t={t} locale={locale} />
        </main>
      )}

      {section === "agent" && (
        <main className="pt-[64px]">
          <Agent t={t} locale={locale} />
        </main>
      )}

      {section === "docs" && (
        <>
          {/* Fixed sidebar (lg+) */}
          <aside className="hidden lg:block fixed top-[64px] bottom-0 left-0 w-[300px] border-r border-white/[0.06] z-30">
            {sidebar}
          </aside>

          {/* Mobile drawer */}
          {drawerOpen && (
            <div className="lg:hidden fixed inset-0 z-50">
              <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={() => setDrawerOpen(false)}
              />
              <div className="drawer-enter absolute top-0 left-0 bottom-0 w-[300px] bg-zinc-950 border-r border-white/[0.08] flex flex-col">
                <div className="h-[64px] flex items-center justify-between px-4 border-b border-white/[0.06] shrink-0">
                  <span className="text-[15px] font-bold text-zinc-100">{t.brand}</span>
                  <button
                    onClick={() => setDrawerOpen(false)}
                    aria-label="Close navigation"
                    className="text-zinc-400 hover:text-zinc-100"
                  >
                    <X size={20} />
                  </button>
                </div>
                <div className="flex-1 min-h-0">{sidebar}</div>
              </div>
            </div>
          )}

          <main className="lg:pl-[300px] pt-[64px]">
            <div className="mx-auto max-w-[1240px] px-5 sm:px-8 lg:px-12 py-9 flex gap-10">
              <div className="flex-1 min-w-0">
                {activeCard && doc ? (
                  <DocView
                    key={slug + locale}
                    card={activeCard}
                    doc={doc.resolved}
                    html={doc.html}
                    usingFallback={usingFallback}
                    onHome={goDocs}
                    onDocs={goDocs}
                    t={t}
                    locale={locale}
                  />
                ) : (
                  <Landing
                    categories={categories}
                    stats={stats}
                    onSelect={openDoc}
                    t={t}
                    locale={locale}
                  />
                )}
              </div>

              {activeCard && doc?.toc.length > 0 && (
                <aside className="hidden xl:block w-[220px] shrink-0">
                  <div className="sticky top-[88px] max-h-[calc(100vh-110px)] overflow-y-auto">
                    <Toc key={slug} toc={doc.toc} t={t} />
                  </div>
                </aside>
              )}
            </div>
          </main>
        </>
      )}
    </div>
  );
}
