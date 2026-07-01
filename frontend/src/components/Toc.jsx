import { useEffect, useState } from "react";

/** Right-rail contents with IntersectionObserver scroll-spy. Keyed by slug in the
 *  parent so it remounts (and re-observes) when the document changes. */
export default function Toc({ toc, t }) {
  const [active, setActive] = useState(toc[0]?.slug ?? "");

  useEffect(() => {
    const els = toc
      .map((item) => document.getElementById(item.slug))
      .filter(Boolean);
    if (!els.length) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -68% 0px", threshold: 0 }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, [toc]);

  const go = (slug) => {
    const el = document.getElementById(slug);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      setActive(slug);
    }
  };

  if (!toc.length) return null;

  return (
    <nav aria-label={t.onThisPage} className="text-[12.5px]">
      <p className="text-[10.5px] font-semibold uppercase tracking-wider text-zinc-500 mb-3 flex items-center gap-2">
        <span className="w-3 h-px bg-emerald-500/60" />
        {t.onThisPage}
      </p>
      <ul className="space-y-0.5 border-l border-white/[0.07]">
        {toc.map((item) => {
          const isActive = item.slug === active;
          return (
            <li key={item.slug}>
              <button
                onClick={() => go(item.slug)}
                className={`block w-full text-left py-1 transition-colors -ml-px border-l-2 ${
                  item.depth === 3 ? "pl-6" : "pl-3"
                } ${
                  isActive
                    ? "border-emerald-500 text-emerald-400"
                    : "border-transparent text-zinc-500 hover:text-zinc-200"
                }`}
              >
                {item.text}
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
