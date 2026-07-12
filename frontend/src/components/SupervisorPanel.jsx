import { useState } from "react";
import {
  CaretLeft,
  Check,
  CircleNotch,
  Copy,
  DownloadSimple,
  ListChecks,
  MagnifyingGlass,
  PaperPlaneRight,
  TerminalWindow,
} from "@phosphor-icons/react";

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-300 mb-1">
        {label}
      </span>
      {children}
    </label>
  );
}

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2 text-[13px] text-zinc-100 " +
  "placeholder:text-zinc-400 focus:border-emerald-500/50 outline-none transition-colors";

// Icon + short text label, not an icon alone — the two things this button set gates (asking
// the Supervisor a question, and reading its plan) are the whole point of this page, so they
// need to be self-explanatory at a glance, not just discoverable via a tooltip. `aria-expanded`
// + `aria-controls` describe the disclosure relationship to the drawer it opens.
function DrawerTab({ label, shortLabel, icon, active, controls, onClick }) {
  return (
    <button
      onClick={onClick}
      aria-label={label}
      title={label}
      aria-expanded={active}
      aria-controls={controls}
      className={`flex flex-col items-center justify-center gap-1 min-w-[52px] px-1.5 py-2 border transition-colors ${
        active
          ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"
          : "border-white/[0.08] text-zinc-300 hover:text-zinc-100 hover:border-white/[0.18]"
      }`}
    >
      {icon}
      <span className="text-[9.5px] font-semibold uppercase tracking-wide leading-none">
        {shortLabel}
      </span>
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
// so they don't compete with the Terminal for space when not in use. A labeled onboarding
// block above the paste area (instead of a bare placeholder in an otherwise-empty box) and a
// direct "Ask" shortcut from it are what make the primary action discoverable without opening
// a drawer first.
export default function SupervisorPanel({
  activeDomain,
  question,
  setQuestion,
  scanMode,
  setScanMode,
  harnessConfig,
  setHarnessConfig,
  onExportSarif,
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
  const [copied, setCopied] = useState(false);
  const canAsk = Boolean(activeDomain) && question.trim() && !asking;
  const toggleDrawer = (name) => setOpenDrawer((cur) => (cur === name ? null : name));
  const showOnboarding = !ingestText.trim() && !ingestResult;
  const scanModes = [
    { id: "quick", label: t.supScanQuick },
    { id: "standard", label: t.supScanStandard },
    { id: "deep", label: t.supScanDeep },
  ];
  const updateHarness = (field, value) =>
    setHarnessConfig((current) => ({ ...current, [field]: value }));
  const copyHarness = async () => {
    if (!advice?.context_block) return;
    try {
      await navigator.clipboard.writeText(advice.context_block);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="flex-1 min-w-0 flex lg:min-h-0 relative">
      <div className="flex-1 min-w-0 flex flex-col border border-white/[0.07] bg-zinc-900/30 lg:min-h-0">
        <div className="px-3 py-2 border-b border-white/[0.06] flex items-center gap-1.5 shrink-0">
          <TerminalWindow size={13} className="text-emerald-400" weight="bold" />
          <h2 className="text-[12px] font-semibold text-zinc-100">{t.supTerminalHeading}</h2>
        </div>
        <div className="flex-1 min-h-0 flex flex-col p-3 gap-2">
          {showOnboarding && (
            <div className="shrink-0 border border-dashed border-white/[0.12] bg-white/[0.02] px-3 py-2.5 flex items-start gap-2.5">
              <TerminalWindow size={16} className="text-emerald-400 mt-0.5 shrink-0" weight="bold" />
              <div className="min-w-0">
                <p className="text-[12.5px] font-medium text-zinc-100">{t.supTerminalEmptyTitle}</p>
                <p className="text-[11.5px] text-zinc-300 mt-0.5 leading-snug">{t.supCliEmpty}</p>
                {activeDomain && !advice && (
                  <button
                    onClick={() => toggleDrawer("supervisor")}
                    className="mt-2 inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[11.5px] font-medium bg-emerald-500/15 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/25 transition-colors"
                  >
                    <MagnifyingGlass size={12} weight="bold" /> {t.supAsk}
                  </button>
                )}
                {!activeDomain && (
                  <p className="text-[11.5px] text-zinc-300 mt-1.5">{t.notebookEmpty}</p>
                )}
              </div>
            </div>
          )}
          <label className="flex-1 min-h-0 flex flex-col">
            <span className="sr-only">{t.supIngestPlaceholder}</span>
            <textarea
              value={ingestText}
              onChange={(e) => setIngestText(e.target.value)}
              placeholder={t.supIngestPlaceholder}
              className={`${inputCls} flex-1 min-h-0 resize-none font-mono text-[12px]`}
            />
          </label>
          <div className="shrink-0 flex items-center gap-2 flex-wrap">
            <button
              onClick={onIngest}
              disabled={!activeDomain || !ingestText.trim() || ingesting}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium transition-colors ${
                activeDomain && ingestText.trim() && !ingesting
                  ? "bg-emerald-500/15 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/25"
                  : "border border-white/[0.07] text-zinc-500 cursor-not-allowed"
              }`}
            >
              {ingesting ? (
                <CircleNotch size={13} className="animate-spin" />
              ) : (
                <PaperPlaneRight size={13} weight="bold" />
              )}
              {t.supIngest}
            </button>
            <button
              onClick={onExportSarif}
              disabled={!activeDomain}
              title={t.supExportSarif}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium border transition-colors ${
                activeDomain
                  ? "border-white/[0.12] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/25"
                  : "border-white/[0.07] text-zinc-500 cursor-not-allowed"
              }`}
            >
              <DownloadSimple size={13} weight="bold" />
              {t.supExportSarif}
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
          shortLabel={t.supAskShort}
          icon={<MagnifyingGlass size={15} weight="bold" />}
          active={openDrawer === "supervisor"}
          controls="sup-ask-drawer"
          onClick={() => toggleDrawer("supervisor")}
        />
        <DrawerTab
          label={t.supAdviceHeading}
          shortLabel={t.supPlanShort}
          icon={<ListChecks size={15} weight="bold" />}
          active={openDrawer === "strategy"}
          controls="sup-plan-drawer"
          onClick={() => toggleDrawer("strategy")}
        />
      </div>

      {openDrawer === "supervisor" && (
        <div
          id="sup-ask-drawer"
          className="absolute top-0 right-[58px] w-[320px] h-full border border-white/[0.1] bg-zinc-950 z-10 flex flex-col shadow-2xl"
        >
          <div className="px-3 py-2 border-b border-white/[0.06] flex items-center justify-between shrink-0">
            <h2 className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-100">
              <MagnifyingGlass size={13} className="text-emerald-400" weight="bold" /> {t.supHeading}
            </h2>
            <button
              onClick={() => setOpenDrawer(null)}
              aria-label={t.chainClose}
              className="text-zinc-300 hover:text-zinc-100"
            >
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
            <div>
              <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-300 mb-1">
                {t.supScanMode}
              </span>
              <div role="radiogroup" aria-label={t.supScanMode} className="flex gap-1">
                {scanModes.map((m) => (
                  <button
                    key={m.id}
                    role="radio"
                    aria-checked={scanMode === m.id}
                    onClick={() => setScanMode(m.id)}
                    className={`flex-1 px-2 py-1.5 text-[11.5px] font-medium border transition-colors ${
                      scanMode === m.id
                        ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"
                        : "border-white/[0.08] text-zinc-300 hover:text-zinc-100"
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>
            <section className="border-t border-white/[0.07] pt-3 space-y-3">
              <h3 className="text-[11px] font-mono uppercase tracking-wider text-zinc-300">
                {t.supRoeHeading}
              </h3>
              <Field label={t.supVendor}>
                <select
                  value={harnessConfig.vendor}
                  onChange={(e) => updateHarness("vendor", e.target.value)}
                  className={inputCls}
                >
                  <option value="generic">{t.supVendorGeneric}</option>
                  <option value="claude-code">Claude Code</option>
                  <option value="codex">OpenAI Codex</option>
                  <option value="cursor">Cursor</option>
                </select>
              </Field>
              <Field label={t.supCriticality}>
                <select
                  value={harnessConfig.assetCriticality}
                  onChange={(e) => updateHarness("assetCriticality", e.target.value)}
                  className={inputCls}
                >
                  <option value="unknown">{t.supCriticalityUnknown}</option>
                  <option value="critical">{t.supCriticalityCritical}</option>
                  <option value="production">{t.supCriticalityProduction}</option>
                  <option value="non-production">{t.supCriticalityNonProduction}</option>
                </select>
              </Field>
              <Field label={t.supAuthorizationRef}>
                <input
                  value={harnessConfig.authorizationReference}
                  onChange={(e) => updateHarness("authorizationReference", e.target.value)}
                  placeholder={t.supAuthorizationRefPlaceholder}
                  className={inputCls}
                />
              </Field>
              <Field label={t.supWindowStart}>
                <input
                  type="datetime-local"
                  value={harnessConfig.windowStart}
                  onChange={(e) => updateHarness("windowStart", e.target.value)}
                  className={inputCls}
                />
              </Field>
              <Field label={t.supWindowEnd}>
                <input
                  type="datetime-local"
                  value={harnessConfig.windowEnd}
                  onChange={(e) => updateHarness("windowEnd", e.target.value)}
                  className={inputCls}
                />
              </Field>
              <Field label={t.supExcludedTargets}>
                <input
                  value={harnessConfig.excludedTargets}
                  onChange={(e) => updateHarness("excludedTargets", e.target.value)}
                  placeholder={t.supExcludedTargetsPlaceholder}
                  className={inputCls}
                />
              </Field>
              <label className="flex items-start gap-2 text-[11.5px] text-zinc-300">
                <input
                  type="checkbox"
                  checked={harnessConfig.allowSubdomains}
                  onChange={(e) => updateHarness("allowSubdomains", e.target.checked)}
                  className="mt-0.5 accent-emerald-500"
                />
                <span>{t.supAllowSubdomains}</span>
              </label>
              <label className="flex items-start gap-2 text-[11.5px] text-zinc-100">
                <input
                  type="checkbox"
                  checked={harnessConfig.authorizationConfirmed}
                  onChange={(e) => updateHarness("authorizationConfirmed", e.target.checked)}
                  className="mt-0.5 accent-emerald-500"
                />
                <span>{t.supAuthorizationConfirm}</span>
              </label>
            </section>
            <button
              onClick={onAsk}
              disabled={!canAsk}
              className={`w-full flex items-center justify-center gap-2 px-3 py-2 text-[12.5px] font-semibold transition-colors ${
                canAsk
                  ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                  : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
              }`}
            >
              {asking && <CircleNotch size={14} className="animate-spin" />}
              {asking ? t.supAsking : t.supAsk}
            </button>
            {!activeDomain && <p className="text-[11.5px] text-zinc-300">{t.notebookEmpty}</p>}
            {adviceErr && <p className="text-[12px] text-red-400/90">{adviceErr}</p>}
          </div>
        </div>
      )}

      {openDrawer === "strategy" && (
        <div
          id="sup-plan-drawer"
          className="absolute top-0 right-[58px] w-[320px] h-full border border-white/[0.1] bg-zinc-950 z-10 flex flex-col shadow-2xl"
        >
          <div className="px-3 py-2 border-b border-white/[0.06] flex items-center justify-between shrink-0">
            <h2 className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-100">
              <ListChecks size={13} className="text-emerald-400" weight="bold" /> {t.supAdviceHeading}
            </h2>
            <button
              onClick={() => setOpenDrawer(null)}
              aria-label={t.chainClose}
              className="text-zinc-300 hover:text-zinc-100"
            >
              <CaretLeft size={13} />
            </button>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-3">
            {!advice ? (
              <p className="text-[12px] text-zinc-300">{t.supAdviceEmpty}</p>
            ) : (
              <>
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={`text-[10.5px] font-mono uppercase ${
                      advice.harness?.ready ? "text-emerald-400" : "text-amber-400"
                    }`}
                  >
                    {advice.harness?.ready ? t.supHarnessReady : t.supHarnessDraft}
                  </span>
                  <button
                    onClick={copyHarness}
                    disabled={!advice.context_block}
                    title={t.supCopyHarness}
                    className="inline-flex items-center gap-1.5 px-2 py-1 border border-white/[0.12] text-[11px] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/25 disabled:text-zinc-600"
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? t.supHarnessCopied : t.supCopyHarness}
                  </button>
                </div>
                {advice.harness?.blockers?.length > 0 && (
                  <ul className="space-y-1 border-l border-amber-500/30 pl-2">
                    {advice.harness.blockers.map((blocker) => (
                      <li key={blocker} className="text-[11px] leading-snug text-amber-300/90">
                        {blocker}
                      </li>
                    ))}
                  </ul>
                )}
                {advice.archetype && (
                  <p className="text-[11.5px] font-mono text-zinc-300">
                    {t.supArchetype}: <span className="text-emerald-400/90">{advice.archetype}</span>
                  </p>
                )}
                <ol className="space-y-2 list-decimal list-inside">
                  {advice.plan.map((step) => (
                    <li key={step.order} className="text-[12.5px] text-zinc-100">
                      <span className="font-medium">{step.action}</span>
                      <p className="ml-4 text-[12px] text-zinc-300 leading-snug">{step.reasoning}</p>
                    </li>
                  ))}
                </ol>
                {advice.questions?.length > 0 && (
                  <section className="border-t border-white/[0.07] pt-2.5">
                    <h3 className="text-[11px] font-mono uppercase tracking-wider text-zinc-300 mb-2">
                      {t.supReasoningHeading}
                    </h3>
                    <ol className="space-y-2">
                      {advice.questions.map((item) => (
                        <li
                          key={item.id}
                          title={item.rationale}
                          className="border-l border-emerald-500/25 pl-2"
                        >
                          <p className="text-[10px] font-mono uppercase tracking-wide text-emerald-400/80">
                            {item.order}. {item.technique} · {item.stage}
                          </p>
                          <p className="text-[12px] text-zinc-100 leading-snug mt-0.5">
                            {item.question}
                          </p>
                          {item.condition !== "always" && (
                            <p className="text-[10.5px] text-zinc-400 mt-0.5">
                              {t.supReasoningCondition}: {item.condition}
                            </p>
                          )}
                        </li>
                      ))}
                    </ol>
                  </section>
                )}
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
