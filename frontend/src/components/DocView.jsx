import { Warning, Tag } from "@phosphor-icons/react";
import Breadcrumb from "./Breadcrumb";
import StatusBadge from "./StatusBadge";
import { localizeCategory } from "../i18n/strings";

export default function DocView({ card, doc, html, usingFallback, onHome, onDocs, t, locale }) {
  return (
    <article className="page-enter">
      <Breadcrumb
        category={localizeCategory(card.category, locale)}
        title={doc.title}
        onHome={onHome}
        onDocs={onDocs}
        t={t}
      />

      <header className="mt-5 pb-6 mb-2 border-b border-white/[0.07]">
        <h1 className="text-[1.9rem] sm:text-[2.2rem] font-bold text-zinc-50 tracking-tight leading-[1.12] text-balance">
          {doc.title}
        </h1>

        <div className="mt-4 flex flex-wrap items-center gap-2.5">
          <StatusBadge status={doc.status || card.status} labels={t} />
          {doc.owasp && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 border border-white/[0.08] bg-zinc-900/60 text-[11px] font-mono text-zinc-400">
              <Tag size={12} className="text-emerald-400/70" />
              {doc.owasp}
            </span>
          )}
        </div>

        {doc.summary && (
          <p className="mt-5 text-[1.02rem] leading-relaxed text-zinc-300 max-w-[68ch]">
            {doc.summary}
          </p>
        )}

        {usingFallback && (
          <p className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 border border-amber-400/20 bg-amber-400/[0.06] text-[12px] text-amber-300/90">
            <Warning size={13} weight="fill" />
            Tiếng Việt chưa có cho mục này — đang hiển thị bản tiếng Anh.
          </p>
        )}
      </header>

      <div className="prose" dangerouslySetInnerHTML={{ __html: html }} />

      <footer className="mt-12 pt-5 border-t border-white/[0.06] flex items-start gap-2.5 text-[12px] text-zinc-500">
        <Warning size={14} className="text-zinc-600 mt-0.5 shrink-0" />
        <p className="max-w-[60ch]">{t.authNote}</p>
      </footer>
    </article>
  );
}
