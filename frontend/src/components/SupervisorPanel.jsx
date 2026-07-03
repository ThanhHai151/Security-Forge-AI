import { useState } from "react";
import {
  CaretLeft,
  CircleNotch,
  ListChecks,
  MagnifyingGlass,
  PaperPlaneRight,
  TerminalWindow,
} from "@phosphor-icons/react";

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-500 mb-1">
        {label}
      </span>
      {children}
    </label>
  );
}

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2 text-[13px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";

function DrawerTab({ label, icon, active, onClick }) {
  return (
    <button
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`w-9 h-9 flex items-center justify-center border transition-colors ${
        active
          ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"
          : "border-white/[0.08] text-zinc-500 hover:text-zinc-200"
      }`}
    >
      {icon}
    </button>
  );
}

// The Expert Supervisor never executes anything itself (see ai_framework/supervisor) — it
// only ranks an investigation strategy and hands off the right skill(s) for an external
// coding agent (e.g. Claude Code) to actually carry out. Blackbox only: there's no source
// path to point it at. The Terminal is the dominant, central element of this column — today
// it's a manual mirror (paste the agent's raw output and it's stored verbatim, then
// mechanically parsed for CONFIRMED/NEW_FINDING_TYPE markers, see
// ai_framework/supervisor/ingest.py); "Expert Supervisor" (ask a question) and
// "Investigation strategy" (its answer) live in two collapsible drawers off the right edge
// so they don't compete with the Terminal for space when not in use.
export default function SupervisorPanel({
  activeDomain,
  question,
  setQuestion,
  onAsk,
  asking,
  advice,
  adviceErr,
  ingestText,
  setIngestText,
  onIngest,
  ingesting,
  ingestResult,
  ingestErr,
  t,
}) {
  const [openDrawer, setOpenDrawer] = useState(null); // null | "supervisor" | "strategy"
  const canAsk = Boolean(activeDomain) && question.trim() && !asking;
  const toggleDrawer = (name) => setOpenDrawer((cur) => (cur === name ? null : name));

  return (
    <div className="flex-1 min-w-0 flex lg:min-h-0 relative">
      <div className="flex-1 min-w-0 flex flex-col border border-white/[0.07] bg-zinc-900/30 lg:min-h-0">
        <div className="px-3 py-2 border-b border-white/[0.06] flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200 shrink-0">
          <TerminalWindow size={13} className="text-emerald-400" weight="bold" /> {t.supTerminalHeading}
        </div>
        <div className="flex-1 min-h-0 flex flex-col p-3 gap-2">
          <p className="text-[11.5px] text-zinc-500 shrink-0">{t.supCliEmpty}</p>
          <textarea
            value={ingestText}
            onChange={(e) => setIngestText(e.target.value)}
            placeholder={t.supIngestPlaceholder}
            className={`${inputCls} flex-1 min-h-0 resize-none font-mono text-[12px]`}
          />
          <div className="shrink-0 flex items-center gap-2">
            <button
              onClick={onIngest}
              disabled={!activeDomain || !ingestText.trim() || ingesting}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium transition-colors ${
                activeDomain && ingestText.trim() && !ingesting
                  ? "bg-emerald-500/15 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/25"
                  : "border border-white/[0.07] text-zinc-600 cursor-not-allowed"
              }`}
            >
              {ingesting ? (
                <CircleNotch size={13} className="animate-spin" />
              ) : (
                <PaperPlaneRight size={13} weight="bold" />
              )}
              {t.supIngest}
            </button>
            {ingestResult && (
              <p className="text-[11.5px] text-emerald-400/90">
                {t.supIngestResult(ingestResult.promoted.length, ingestResult.custom_added.length)}
              </p>
            )}
            {ingestErr && <p className="text-[12px] text-red-400/90">{ingestErr}</p>}
          </div>
        </div>
      </div>

      {/* Collapsible drawers, anchored to the right edge of this column */}
      <div className="shrink-0 flex flex-col gap-1.5 ml-1.5">
        <DrawerTab
          label={t.supHeading}
          icon={<MagnifyingGlass size={14} weight="bold" />}
          active={openDrawer === "supervisor"}
          onClick={() => toggleDrawer("supervisor")}
        />
        <DrawerTab
          label={t.supAdviceHeading}
          icon={<ListChecks size={14} weight="bold" />}
          active={openDrawer === "strategy"}
          onClick={() => toggleDrawer("strategy")}
        />
      </div>

      {openDrawer === "supervisor" && (
        <div className="absolute top-0 right-[42px] w-[320px] h-full border border-white/[0.1] bg-zinc-950 z-10 flex flex-col shadow-2xl">
          <div className="px-3 py-2 border-b border-white/[0.06] flex items-center justify-between shrink-0">
            <span className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
              <MagnifyingGlass size={13} className="text-emerald-400" weight="bold" /> {t.supHeading}
            </span>
            <button onClick={() => setOpenDrawer(null)} className="text-zinc-500 hover:text-zinc-200">
              <CaretLeft size={13} />
            </button>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-3">
            <Field label={t.supQuestion}>
              <textarea
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder={t.supQuestionPlaceholder}
                rows={3}
                className={`${inputCls} resize-none`}
              />
            </Field>
            <button
              onClick={onAsk}
              disabled={!canAsk}
              className={`w-full flex items-center justify-center gap-2 px-3 py-2 text-[12.5px] font-semibold transition-colors ${
                canAsk
                  ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                  : "bg-zinc-800 text-zinc-600 cursor-not-allowed"
              }`}
            >
              {asking && <CircleNotch size={14} className="animate-spin" />}
              {asking ? t.supAsking : t.supAsk}
            </button>
            {!activeDomain && <p className="text-[11.5px] text-zinc-600">{t.notebookEmpty}</p>}
            {adviceErr && <p className="text-[12px] text-red-400/90">{adviceErr}</p>}
          </div>
        </div>
      )}

      {openDrawer === "strategy" && (
        <div className="absolute top-0 right-[42px] w-[320px] h-full border border-white/[0.1] bg-zinc-950 z-10 flex flex-col shadow-2xl">
          <div className="px-3 py-2 border-b border-white/[0.06] flex items-center justify-between shrink-0">
            <span className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
              <ListChecks size={13} className="text-emerald-400" weight="bold" /> {t.supAdviceHeading}
            </span>
            <button onClick={() => setOpenDrawer(null)} className="text-zinc-500 hover:text-zinc-200">
              <CaretLeft size={13} />
            </button>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-3">
            {!advice ? (
              <p className="text-[12px] text-zinc-500">{t.supAdviceEmpty}</p>
            ) : (
              <>
                {advice.archetype && (
                  <p className="text-[11.5px] font-mono text-zinc-500">
                    {t.supArchetype}: <span className="text-emerald-400/90">{advice.archetype}</span>
                  </p>
                )}
                <ol className="space-y-2 list-decimal list-inside">
                  {advice.plan.map((step) => (
                    <li key={step.order} className="text-[12.5px] text-zinc-200">
                      <span className="font-medium">{step.action}</span>
                      <p className="ml-4 text-[11.5px] text-zinc-500 leading-snug">{step.reasoning}</p>
                    </li>
                  ))}
                </ol>
                {advice.skills?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {advice.skills.map((s) => (
                      <span
                        key={s.name}
                        title={s.trigger}
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono border border-emerald-600/30 text-emerald-400/90 bg-emerald-500/[0.05]"
                      >
                        {t.supSkillLabel}: {s.name}
                      </span>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
