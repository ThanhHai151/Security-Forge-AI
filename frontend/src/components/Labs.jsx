import { useCallback, useEffect, useState } from "react";
import { Flask, CircleNotch, CheckCircle, Circle, BookOpen, Warning } from "@phosphor-icons/react";

import { getLabs } from "../lib/api";

function LabCard({ lab, t, onOpenDoc }) {
  const solved = lab.solved;
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-semibold text-zinc-100">{lab.title}</span>
            <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border border-white/[0.08] text-zinc-400">
              {lab.category}
            </span>
          </div>
          <p className="mt-1.5 text-[12.5px] leading-relaxed text-zinc-400">{lab.description}</p>
          <div className="mt-2 flex items-center gap-3 text-[11.5px] font-mono text-zinc-500">
            <span>
              {t.labsDifficulty}: {lab.difficulty}
            </span>
            {lab.kb_id && (
              <button
                onClick={() => onOpenDoc?.(lab.kb_id)}
                className="inline-flex items-center gap-1 hover:text-emerald-400 transition-colors"
              >
                <BookOpen size={12} /> {t.labsKb}
              </button>
            )}
          </div>
        </div>
        <span
          className={`shrink-0 inline-flex items-center gap-1 text-[11px] font-mono ${
            solved ? "text-emerald-400" : "text-zinc-600"
          }`}
        >
          {solved ? <CheckCircle size={14} weight="fill" /> : <Circle size={14} />}
          {solved ? t.labsSolved : t.labsUnsolved}
        </span>
      </div>
    </div>
  );
}

export default function Labs({ t, onOpenDoc }) {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const refresh = useCallback(async () => {
    try {
      const data = await getLabs();
      setLabs(data.labs || []);
      setErr("");
    } catch (e) {
      setErr(e.message === "Failed to fetch" ? t.backendDown : String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className="page-enter mx-auto max-w-[980px] px-5 sm:px-8 lg:px-12 py-10">
      <header className="pb-7">
        <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          <Flask size={15} weight="fill" /> {t.labsKicker}
        </p>
        <h1 className="mt-3 text-[2.1rem] sm:text-[2.6rem] font-bold text-zinc-50 tracking-tight leading-[1.08]">
          {t.labsTitle}
        </h1>
        <p className="mt-4 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[70ch]">{t.labsLead}</p>
      </header>

      <p className="mb-6 flex items-start gap-2 text-[12px] leading-relaxed text-zinc-500 border border-white/[0.06] bg-zinc-900/20 px-3 py-2.5">
        <Warning size={15} className="text-emerald-400/80 mt-0.5 shrink-0" />
        {t.labsDisabledNote}
      </p>

      {err && (
        <p className="mb-5 text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
          {err}
        </p>
      )}

      {loading ? (
        <p className="flex items-center gap-2 text-[13px] text-zinc-500">
          <CircleNotch size={15} className="animate-spin" /> …
        </p>
      ) : labs.length === 0 ? (
        <p className="text-[13px] text-zinc-500">{t.labsEmpty}</p>
      ) : (
        <div className="space-y-2.5">
          {labs.map((lab) => (
            <LabCard key={lab.slug} lab={lab} t={t} onOpenDoc={onOpenDoc} />
          ))}
        </div>
      )}
    </div>
  );
}
