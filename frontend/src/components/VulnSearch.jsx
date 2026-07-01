import { useCallback, useState } from "react";
import { MagnifyingGlass, CircleNotch, Bug, ArrowSquareOut } from "@phosphor-icons/react";

import { vulnSearch } from "../lib/api";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2.5 text-[14px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";

function ScoreBar({ score, max }) {
  const pct = max > 0 ? Math.max(8, Math.round((score / max) * 100)) : 0;
  return (
    <span className="inline-block w-16 h-1 bg-zinc-800 align-middle">
      <span className="block h-full bg-emerald-500/70" style={{ width: `${pct}%` }} />
    </span>
  );
}

export default function VulnSearch({ t, locale, onOpenDoc }) {
  const [q, setQ] = useState("");
  const [online, setOnline] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const run = useCallback(async () => {
    if (!q.trim()) return;
    setLoading(true);
    setErr("");
    try {
      setResult(await vulnSearch(q.trim(), { online, locale }));
    } catch (e) {
      setErr(e.message === "Failed to fetch" ? t.backendDown : String(e.message || e));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [q, online, locale, t]);

  const maxScore = result?.techniques?.[0]?.score || 1;

  return (
    <div className="page-enter mx-auto max-w-[980px] px-5 sm:px-8 lg:px-12 py-10">
      <header className="pb-7">
        <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          <Bug size={15} weight="fill" /> {t.vulnKicker}
        </p>
        <h1 className="mt-3 text-[2.1rem] sm:text-[2.6rem] font-bold text-zinc-50 tracking-tight leading-[1.08]">
          {t.vulnTitle}
        </h1>
        <p className="mt-4 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[70ch]">{t.vulnLead}</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          className={inputCls}
          placeholder={t.vulnPlaceholder}
        />
        <button
          onClick={run}
          disabled={!q.trim() || loading}
          className={`shrink-0 flex items-center justify-center gap-2 px-5 py-2.5 text-[13px] font-semibold transition-colors ${
            q.trim() && !loading
              ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
          }`}
        >
          {loading ? <CircleNotch size={15} className="animate-spin" /> : <MagnifyingGlass size={15} />}
          {loading ? t.vulnSearching : t.vulnSearch}
        </button>
      </div>
      <label className="mt-3 flex items-center gap-2 text-[12.5px] text-zinc-400 select-none cursor-pointer">
        <input type="checkbox" checked={online} onChange={(e) => setOnline(e.target.checked)} />
        {t.vulnOnline}
      </label>

      {err && (
        <p className="mt-5 text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
          {err}
        </p>
      )}

      {!result && !err && (
        <p className="mt-10 text-[13px] text-zinc-500">{t.vulnEmpty}</p>
      )}

      {result && (
        <div className="mt-8 grid lg:grid-cols-2 gap-6 items-start">
          {/* techniques */}
          <section>
            <h2 className="text-[12px] font-semibold uppercase tracking-wider text-zinc-300 mb-3">
              {t.vulnTechniques} · {result.techniques.length}
            </h2>
            {result.techniques.length === 0 ? (
              <p className="text-[13px] text-zinc-500">{t.vulnNoResults}</p>
            ) : (
              <div className="space-y-2">
                {result.techniques.map((c) => (
                  <button
                    key={c.slug}
                    onClick={() => onOpenDoc?.(c.slug)}
                    className="w-full text-left border border-white/[0.07] bg-zinc-900/30 p-3 hover:border-emerald-500/30 transition-colors group"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[13.5px] font-semibold text-zinc-100 group-hover:text-emerald-400">
                        {c.title}
                      </span>
                      <ScoreBar score={c.score} max={maxScore} />
                    </div>
                    <p className="mt-1 text-[11.5px] font-mono text-zinc-500">
                      {c.category}
                      {c.owasp ? `  ·  ${c.owasp}` : ""}
                    </p>
                    {c.why && <p className="mt-1 text-[11.5px] text-zinc-500">{t.vulnWhy}: {c.why}</p>}
                  </button>
                ))}
              </div>
            )}
          </section>

          {/* cves */}
          <section>
            <h2 className="text-[12px] font-semibold uppercase tracking-wider text-zinc-300 mb-3">
              {t.vulnCves} · {result.cves.length}
              {result.online ? "" : " (seed)"}
            </h2>
            {result.cves.length === 0 ? (
              <p className="text-[13px] text-zinc-500">—</p>
            ) : (
              <div className="space-y-2">
                {result.cves.map((c) => (
                  <div key={c.id} className="border border-white/[0.07] bg-zinc-900/30 p-3">
                    <div className="flex items-center gap-2">
                      <span className="text-[12.5px] font-mono font-semibold text-emerald-400/90">
                        {c.id}
                      </span>
                      {c.severity && (
                        <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border border-white/[0.08] text-zinc-400">
                          {c.severity}
                        </span>
                      )}
                      <span className="text-[10px] font-mono text-zinc-600 ml-auto">{c.source}</span>
                    </div>
                    {c.summary && <p className="mt-1 text-[12.5px] text-zinc-400">{c.summary}</p>}
                    {c.references?.[0] && (
                      <a
                        href={c.references[0]}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1.5 inline-flex items-center gap-1 text-[11.5px] text-zinc-500 hover:text-emerald-400"
                      >
                        <ArrowSquareOut size={12} /> reference
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
