import { CaretRight, House } from "@phosphor-icons/react";

export default function Breadcrumb({ category, title, onHome, onDocs, t }) {
  return (
    <nav className="flex items-center gap-1.5 text-[12px] text-zinc-500 font-mono">
      <button
        onClick={onHome}
        className="flex items-center gap-1.5 hover:text-emerald-400 transition-colors"
      >
        <House size={13} weight="fill" />
        {t.brand}
      </button>
      <CaretRight size={11} className="text-zinc-700" />
      <button onClick={onDocs} className="hover:text-emerald-400 transition-colors">
        {t.navDocs}
      </button>
      <CaretRight size={11} className="text-zinc-700" />
      <span className="text-zinc-500">{category}</span>
      <CaretRight size={11} className="text-zinc-700" />
      <span className="text-zinc-300 truncate">{title}</span>
    </nav>
  );
}
