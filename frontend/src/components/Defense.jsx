import { useCallback, useState } from "react";
import { ShieldCheck, CircleNotch, Warning, FileCode, Package, BookOpen } from "@phosphor-icons/react";

import { scanDefense } from "../lib/api";
import HelpModal from "./HelpModal";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2.5 text-[14px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors font-mono";

const SEV = {
  critical: "text-red-400 border-red-500/40",
  high: "text-orange-400 border-orange-500/40",
  medium: "text-amber-400 border-amber-500/40",
  low: "text-zinc-400 border-white/[0.12]",
  unknown: "text-zinc-400 border-white/[0.12]",
};

function sevLabel(t, sev) {
  return { critical: t.sevCritical, high: t.sevHigh, medium: t.sevMedium, low: t.sevLow }[sev] || sev;
}

function SevBadge({ sev, t }) {
  return (
    <span
      className={`text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${SEV[sev] || SEV.low}`}
    >
      {sevLabel(t, sev)}
    </span>
  );
}

function FindingCard({ f, t }) {
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30 p-3">
      <div className="flex items-center gap-2 flex-wrap">
        <SevBadge sev={f.severity} t={t} />
        <span className="text-[13px] font-semibold text-zinc-100">{f.title}</span>
        <span className="text-[11px] font-mono text-zinc-500 ml-auto">
          {f.file}:{f.line}
        </span>
      </div>
      <p className="mt-1.5 text-[12.5px] text-zinc-400">{f.message}</p>
      <pre className="mt-2 overflow-x-auto bg-zinc-950/70 border border-white/[0.05] p-2 text-[11.5px] font-mono text-zinc-300">
        <code>{f.snippet}</code>
      </pre>
      {f.guidance && (
        <details className="mt-2">
          <summary className="text-[11.5px] font-mono uppercase tracking-wider text-emerald-400/80 cursor-pointer">
            {t.defGuidance}
          </summary>
          <p className="mt-1.5 whitespace-pre-wrap text-[12.5px] leading-relaxed text-zinc-400">
            {f.guidance}
          </p>
        </details>
      )}
    </div>
  );
}

function DepCard({ d, t }) {
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30 p-3">
      <div className="flex items-center gap-2 flex-wrap">
        <SevBadge sev={d.severity} t={t} />
        <span className="text-[13px] font-semibold text-zinc-100 font-mono">
          {d.name}@{d.version}
        </span>
        <span className="text-[11px] font-mono text-zinc-500 ml-auto">
          {d.ecosystem} · {d.source}
        </span>
      </div>
      <ul className="mt-2 space-y-1.5">
        {d.advisories.map((a) => (
          <li key={a.id} className="text-[12px] text-zinc-400">
            <a
              href={a.reference}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-emerald-400/80 hover:text-emerald-300"
            >
              {a.id}
            </a>
            {a.summary ? ` — ${a.summary}` : ""}
            {a.fixed && (
              <span className="text-zinc-500">
                {" "}
                ({t.defFixedIn} {a.fixed})
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

const order = ["critical", "high", "medium", "low", "unknown"];

export default function Defense({ t, locale = "en" }) {
  const [path, setPath] = useState("");
  const [depsOnline, setDepsOnline] = useState(false);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [helpOpen, setHelpOpen] = useState(false);

  const run = useCallback(async () => {
    if (!path.trim()) return;
    setLoading(true);
    setErr("");
    try {
      setReport(await scanDefense({ path: path.trim(), deps_online: depsOnline }));
    } catch (e) {
      setErr(e.message === "Failed to fetch" ? t.backendDown : String(e.message || e));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [path, depsOnline, t]);

  const code = report?.code_review;
  const deps = report?.dependencies;

  return (
    <div className="page-enter mx-auto max-w-[980px] px-5 sm:px-8 lg:px-12 py-10">
      <header className="pb-7">
        <div className="flex items-start justify-between gap-3">
          <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
            <ShieldCheck size={15} weight="fill" /> {t.defKicker}
          </p>
          <button
            onClick={() => setHelpOpen(true)}
            className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 text-[12.5px] font-medium border border-white/[0.08] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/25 transition-colors"
          >
            <BookOpen size={14} weight="bold" /> {t.helpButton}
          </button>
        </div>
        <h1 className="mt-3 text-[2.1rem] sm:text-[2.6rem] font-bold text-zinc-50 tracking-tight leading-[1.08]">
          {t.defTitle}
        </h1>
        <p className="mt-4 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[70ch]">{t.defLead}</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-2">
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          className={inputCls}
          placeholder={t.defPlaceholder}
        />
        <button
          onClick={run}
          disabled={!path.trim() || loading}
          className={`shrink-0 flex items-center justify-center gap-2 px-5 py-2.5 text-[13px] font-semibold transition-colors ${
            path.trim() && !loading
              ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
          }`}
        >
          {loading ? <CircleNotch size={15} className="animate-spin" /> : <ShieldCheck size={15} />}
          {loading ? t.defReviewing : t.defReview}
        </button>
      </div>

      <label className="mt-3 flex items-center gap-2 text-[12px] text-zinc-400 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={depsOnline}
          onChange={(e) => setDepsOnline(e.target.checked)}
          className="accent-emerald-500"
        />
        {t.defCheckAdvisories}
      </label>

      <p className="mt-3 flex items-start gap-2 text-[11.5px] leading-relaxed text-zinc-500">
        <Warning size={14} className="text-emerald-400/70 mt-0.5 shrink-0" />
        {t.defAuthNote}
      </p>

      {err && (
        <p className="mt-5 text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
          {err}
        </p>
      )}

      {code && !err && (
        <div className="mt-8">
          <div className="flex items-center gap-2 flex-wrap mb-4">
            <FileCode size={15} className="text-zinc-500" />
            <span className="text-[12px] font-semibold uppercase tracking-wider text-zinc-300">
              {t.defCodeReview}
            </span>
            <span className="text-[12.5px] text-zinc-400">
              · {code.files_scanned} {t.defFilesScanned}
            </span>
            {order
              .filter((s) => code.by_severity?.[s])
              .map((s) => (
                <span
                  key={s}
                  className={`text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${SEV[s]}`}
                >
                  {code.by_severity[s]} {sevLabel(t, s)}
                </span>
              ))}
          </div>

          {code.findings.length === 0 ? (
            <p className="text-[13px] text-emerald-400/90 border border-emerald-500/20 bg-emerald-500/[0.05] px-3 py-2.5">
              {t.defNoFindings}
            </p>
          ) : (
            <div className="space-y-2.5">
              {code.findings.map((f, i) => (
                <FindingCard key={`${f.file}:${f.line}:${i}`} f={f} t={t} />
              ))}
            </div>
          )}
        </div>
      )}

      {deps && !err && (
        <div className="mt-8">
          <div className="flex items-center gap-2 flex-wrap mb-4">
            <Package size={15} className="text-zinc-500" />
            <span className="text-[12px] font-semibold uppercase tracking-wider text-zinc-300">
              {t.defDeps}
            </span>
            <span className="text-[12.5px] text-zinc-400">
              · {deps.dependencies_scanned} {t.defDepsScanned} · {deps.manifests_scanned}{" "}
              {t.defManifests}
            </span>
          </div>

          {deps.findings.length > 0 ? (
            <div className="space-y-2.5">
              {deps.findings.map((d) => (
                <DepCard key={`${d.name}@${d.version}`} d={d} t={t} />
              ))}
            </div>
          ) : (
            <p className="text-[13px] text-zinc-400 border border-white/[0.08] bg-zinc-900/30 px-3 py-2.5">
              {deps.advisory_source === "osv" ? t.defNoVulnDeps : t.defDepsOffline}
            </p>
          )}
        </div>
      )}

      {helpOpen && (
        <HelpModal page="defense" locale={locale} title={t.helpButton} onClose={() => setHelpOpen(false)} />
      )}
    </div>
  );
}
