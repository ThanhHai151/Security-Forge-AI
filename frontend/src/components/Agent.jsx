import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Robot,
  Play,
  Stop,
  CircleNotch,
  Brain,
  Warning,
  ShieldWarning,
  Plugs,
  ArrowRight,
  Terminal as TerminalIcon,
  CaretLeft,
  CaretRight,
  Plus,
  Check,
  X,
  ChatCircleDots,
} from "@phosphor-icons/react";

import {
  getAccounts,
  startRun,
  getRun,
  listRuns,
  stopRun,
  getMemory,
  startCampaign,
  startPentest,
  getCampaign,
  listCampaigns,
  continueCampaign,
  stopCampaign,
  approveAction,
  rejectAction,
} from "../lib/api";

const POLL_MS = 1200;
const HISTORY_PREVIEW_LEN = 64;

function truncate(s, n) {
  const str = (s || "").trim();
  return str.length > n ? `${str.slice(0, n - 1)}…` : str;
}

function Dot({ ok }) {
  return (
    <span
      className={`inline-block w-1.5 h-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-zinc-600"}`}
      style={ok ? { boxShadow: "0 0 6px rgba(64,212,168,0.9)" } : undefined}
    />
  );
}

function OutcomeDot({ outcome }) {
  if (outcome === "incomplete" || outcome === "running") {
    return <CircleNotch size={11} className="animate-spin text-emerald-400 shrink-0" />;
  }
  return <Dot ok={outcome !== "error" && outcome !== "stopped"} />;
}

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

function ToolCallLine({ call }) {
  return (
    <div className="mt-1.5 text-[12px] font-mono">
      <span className="text-emerald-400">{call.name}</span>
      <span className="text-zinc-500">(</span>
      <span className="text-zinc-400 break-all">{JSON.stringify(call.arguments)}</span>
      <span className="text-zinc-500">)</span>
    </div>
  );
}

function TurnCard({ turn, label }) {
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-1.5 border-b border-white/[0.06]">
        <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
          {label}
        </span>
      </div>
      <div className="px-3 py-2.5 space-y-2">
        {turn.tool_calls?.map((c) => (
          <ToolCallLine key={c.id} call={c} />
        ))}
        {turn.tool_results?.map((r) => (
          <pre
            key={r.call_id}
            className={`mt-1 text-[11.5px] font-mono whitespace-pre-wrap overflow-x-auto px-2.5 py-1.5 border-l-2 ${
              r.ok
                ? "border-l-emerald-600 bg-[#0A1020] text-[#D8E4F8]"
                : "border-l-red-500 bg-red-500/[0.05] text-red-300/90"
            }`}
          >
            {r.log}
          </pre>
        ))}
        {!turn.tool_calls?.length && !turn.tool_results?.length && (
          <p className="text-[11.5px] text-zinc-600 italic">no tool activity this turn</p>
        )}
      </div>
    </div>
  );
}

const KIND_LABEL = { target_fact: "fact", attempt: "attempt", lesson: "lesson" };

function MemoryView({ summary, t }) {
  if (!summary) return null;
  const byKind = summary.by_kind || {};
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-2 border-b border-white/[0.06] flex items-center justify-between">
        <span className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
          <Brain size={13} className="text-emerald-400" weight="fill" /> {t.aiMemHeading}
        </span>
        <span className="flex items-center gap-2.5 text-[10.5px] font-mono text-zinc-500">
          {Object.entries(byKind).map(([k, n]) => (
            <span key={k}>
              {n} {KIND_LABEL[k] || k}
            </span>
          ))}
        </span>
      </div>
      <div className="px-3 py-2 max-h-[220px] overflow-y-auto">
        {(summary.recent || []).length === 0 ? (
          <p className="text-[12px] text-zinc-500 py-2">{t.aiMemEmpty}</p>
        ) : (
          <ul className="space-y-1.5">
            {summary.recent.map((r, i) => (
              <li key={i} className="text-[12px] leading-snug">
                <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-600 mr-1.5">
                  {KIND_LABEL[r.kind] || r.kind}
                </span>
                {r.technique && <span className="text-emerald-400/80 mr-1.5">{r.technique}</span>}
                <span className="text-zinc-400">{r.body}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Coverage map (continuous mode) ─────────────────────────────────────────
const COV = {
  confirmed: { cls: "text-red-300 border-red-500/30 bg-red-500/[0.07]", glyph: "!" },
  blocked: { cls: "text-amber-300 border-amber-500/30 bg-amber-500/[0.07]", glyph: "⏸" },
  tried: { cls: "text-emerald-300 border-emerald-500/25 bg-emerald-500/[0.06]", glyph: "✓" },
  untried: { cls: "text-zinc-500 border-white/[0.08] bg-transparent", glyph: "·" },
};

function CoverageMap({ coverage, t }) {
  if (!coverage?.length) return <p className="text-[12px] text-zinc-500">{t.termEmptyCoverage}</p>;
  const label = {
    confirmed: t.termConfirmed,
    blocked: t.termBlocked,
    tried: t.termTried,
    untried: t.termUntried,
  };
  return (
    <div className="flex flex-wrap gap-1.5">
      {coverage.map((c) => {
        const s = COV[c.status] || COV.untried;
        return (
          <span
            key={c.id || c.technique}
            title={`${c.technique} — ${label[c.status] || c.status}${c.description ? `: ${c.description}` : ""}`}
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 border text-[11px] font-mono ${s.cls}`}
          >
            <span>{s.glyph}</span>
            {c.technique}
          </span>
        );
      })}
    </div>
  );
}

// ── Left column: run/campaign history (scrolls internally only) ───────────
function HistorySidebar({ kind, history, activeId, onSelect, onNew, t }) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <button
        onClick={onNew}
        className="flex items-center justify-center gap-1.5 px-3 py-2 mb-3 text-[12.5px] font-medium
                   text-emerald-400 border border-emerald-500/25 bg-emerald-500/[0.06]
                   hover:bg-emerald-500/[0.1] transition-colors shrink-0"
      >
        <Plus size={14} weight="bold" /> {kind === "single" ? t.aiNewRun : t.termNewTarget}
      </button>

      <p className="px-0.5 pb-2 text-[11px] font-mono uppercase tracking-wider text-zinc-500 shrink-0">
        {t.aiHistory}
      </p>

      <div className="flex-1 min-h-0 overflow-y-auto space-y-1 pr-0.5">
        {history.length === 0 ? (
          <p className="text-[12px] text-zinc-600 px-0.5">{t.aiNoHistory}</p>
        ) : (
          history.map((h) => (
            <button
              key={h.id}
              onClick={() => onSelect(h.id)}
              className={`w-full text-left px-2.5 py-2 border transition-colors ${
                h.id === activeId
                  ? "border-emerald-500/30 bg-emerald-500/[0.07]"
                  : "border-transparent hover:border-white/[0.07] hover:bg-white/[0.02]"
              }`}
            >
              {kind === "single" ? (
                <>
                  <span className="flex items-center gap-1.5 text-[12.5px] text-zinc-200 leading-snug">
                    <OutcomeDot outcome={h.outcome} />
                    <span className="truncate">{truncate(h.goal, HISTORY_PREVIEW_LEN) || "—"}</span>
                  </span>
                  <span className="mt-0.5 block text-[10.5px] font-mono text-zinc-600 truncate">
                    {h.target} · {h.turns} {t.aiTurns}
                  </span>
                </>
              ) : (
                <>
                  <span className="flex items-center gap-1.5 text-[12.5px] text-zinc-200 leading-snug">
                    <OutcomeDot outcome={h.status} />
                    <span className="truncate">{truncate(h.domain, HISTORY_PREVIEW_LEN) || "—"}</span>
                  </span>
                  <span className="mt-0.5 block text-[10.5px] font-mono text-zinc-600 truncate">
                    {h.status} · {h.phases} {t.termPhase.toLowerCase()}
                  </span>
                </>
              )}
            </button>
          ))
        )}
      </div>
    </div>
  );
}

// ── Right column, bottom half: single-run config ───────────────────────────
function SingleConfigPanel({
  mode, setMode, target, setTarget, authTargets, setAuthTargets, stepBudget, setStepBudget,
  noAccounts, enabledAccounts, pool, t,
}) {
  return (
    <div className="shrink-0 flex flex-col border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-2 border-b border-white/[0.06]">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">{t.aiMode}</span>
      </div>
      <div className="p-3 space-y-3">
        <div className="flex gap-1.5">
          {[
            { id: "router", label: t.aiModeRouter },
            { id: "offline", label: t.aiModeOffline },
          ].map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`flex-1 px-2.5 py-1.5 text-[12px] font-medium border transition-colors ${
                mode === m.id
                  ? "bg-zinc-800 text-emerald-400 border-emerald-500/30"
                  : "text-zinc-500 border-white/[0.07] hover:text-zinc-200"
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {mode === "router" &&
          (noAccounts ? (
            <a
              href="#/router"
              className="flex items-center justify-between gap-2 border border-amber-500/25 bg-amber-500/[0.05] px-3 py-2.5 text-[12px] text-amber-200/90 hover:bg-amber-500/[0.09] transition-colors"
            >
              <span className="flex items-center gap-2">
                <Plugs size={14} /> {t.aiNoAccounts}
              </span>
              <span className="flex items-center gap-1 text-emerald-400">
                {t.aiGoToRouter} <ArrowRight size={13} />
              </span>
            </a>
          ) : (
            <p className="flex items-center gap-2 text-[11.5px] font-mono text-zinc-500">
              <Dot ok /> {enabledAccounts.length} {t.aiAccountsReady} · {pool.policy}
            </p>
          ))}

        <Field label={t.aiTarget}>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="127.0.0.1" className={inputCls} />
        </Field>
        <Field label={t.aiAuthorized}>
          <input
            value={authTargets}
            onChange={(e) => setAuthTargets(e.target.value)}
            placeholder={t.aiAuthPlaceholder}
            className={inputCls}
          />
        </Field>
        <Field label={t.aiBudget}>
          <input
            type="number" min={1} max={50} value={stepBudget}
            onChange={(e) => setStepBudget(e.target.value)}
            className={inputCls + " w-24"}
          />
        </Field>

        <p className="flex items-start gap-1.5 text-[11px] text-zinc-500">
          <Warning size={13} className="text-amber-400/80 mt-0.5 shrink-0" />
          {t.aiAuthNote}
        </p>
      </div>
    </div>
  );
}

// ── Right column, bottom half: continuous-campaign config ──────────────────
function CampaignConfigPanel({
  mode, setMode, authTargets, setAuthTargets, phaseStepBudget, setPhaseStepBudget,
  maxPhases, setMaxPhases, autopilot, setAutopilot, autoApprove, setAutoApprove,
  noAccounts, enabledAccounts, pool, t,
}) {
  return (
    <div className="shrink-0 flex flex-col border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-2 border-b border-white/[0.06]">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">{t.aiMode}</span>
      </div>
      <div className="p-3 space-y-3">
        <div className="flex gap-1.5">
          {[
            { id: "router", label: t.aiModeRouter },
            { id: "offline", label: t.aiModeOffline },
          ].map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`flex-1 px-2.5 py-1.5 text-[12px] font-medium border transition-colors ${
                mode === m.id
                  ? "bg-zinc-800 text-emerald-400 border-emerald-500/30"
                  : "text-zinc-500 border-white/[0.07] hover:text-zinc-200"
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {mode === "router" &&
          (noAccounts ? (
            <a
              href="#/router"
              className="flex items-center justify-between gap-2 border border-amber-500/25 bg-amber-500/[0.05] px-3 py-2.5 text-[12px] text-amber-200/90 hover:bg-amber-500/[0.09] transition-colors"
            >
              <span className="flex items-center gap-2">
                <Plugs size={14} /> {t.aiNoAccounts}
              </span>
              <span className="flex items-center gap-1 text-emerald-400">
                {t.aiGoToRouter} <ArrowRight size={13} />
              </span>
            </a>
          ) : (
            <p className="flex items-center gap-2 text-[11.5px] font-mono text-zinc-500">
              <Dot ok /> {enabledAccounts.length} {t.aiAccountsReady} · {pool.policy}
            </p>
          ))}

        <label className="flex items-center gap-2 text-[12px] text-zinc-300 cursor-pointer select-none">
          <input type="checkbox" checked={autopilot} onChange={(e) => setAutopilot(e.target.checked)} className="accent-emerald-500" />
          <span className="font-medium">{t.termAutopilot}</span>
        </label>
        <p className="text-[11px] text-zinc-500 -mt-2">{t.termAutopilotHint}</p>

        <Field label={t.aiAuthorized}>
          <input
            value={authTargets}
            onChange={(e) => setAuthTargets(e.target.value)}
            placeholder={t.aiAuthPlaceholder}
            className={inputCls}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label={t.aiBudget}>
            <input
              type="number" min={1} max={50} value={phaseStepBudget}
              onChange={(e) => setPhaseStepBudget(e.target.value)}
              className={inputCls}
            />
          </Field>
          <Field label={t.termPhase}>
            <input
              type="number" min={1} max={50} value={maxPhases}
              onChange={(e) => setMaxPhases(e.target.value)}
              className={inputCls}
            />
          </Field>
        </div>

        <label className="flex items-center gap-2 text-[11.5px] text-zinc-400 cursor-pointer select-none">
          <input
            type="checkbox" checked={autoApprove}
            onChange={(e) => setAutoApprove(e.target.checked)}
            className="accent-emerald-500"
          />
          {t.termAutoApprove}
        </label>

        <p className="flex items-start gap-1.5 text-[11px] text-zinc-500">
          <ShieldWarning size={13} className="text-amber-400/80 mt-0.5 shrink-0" />
          {t.termAuthOnly}
        </p>
      </div>
    </div>
  );
}

// ── Single-run composer (goal input, doubles as the Stop control while running) ──
function Composer({ size, goal, setGoal, onRun, onStop, canRun, running, t }) {
  const big = size === "lg";
  const submit = () => {
    if (canRun) onRun();
  };
  return (
    <div className={big ? "w-full max-w-[720px] mx-auto" : "w-full"}>
      <div
        className={`flex items-end gap-2 border bg-zinc-900/60 transition-colors focus-within:border-emerald-500/50 ${
          big ? "border-white/[0.10] px-4 py-3 rounded-2xl" : "border-white/[0.08] px-3 py-2 rounded-xl"
        }`}
      >
        <textarea
          value={goal}
          onChange={(e) => setGoal(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
          disabled={running}
          rows={big ? 2 : 1}
          placeholder={t.aiGoalPlaceholder}
          className={`flex-1 min-w-0 resize-none bg-transparent text-zinc-100 placeholder:text-zinc-600
                      outline-none disabled:opacity-50 ${big ? "text-[15px]" : "text-[13.5px]"}`}
        />
        {running ? (
          <button
            onClick={onStop}
            aria-label={t.aiStop}
            title={t.aiStop}
            className={`shrink-0 flex items-center justify-center rounded-lg transition-colors bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 ${
              big ? "w-10 h-10" : "w-9 h-9"
            }`}
          >
            <Stop size={big ? 16 : 14} weight="fill" />
          </button>
        ) : (
          <button
            onClick={submit}
            disabled={!canRun}
            aria-label={t.aiRun}
            title={t.aiRun}
            className={`shrink-0 flex items-center justify-center rounded-lg transition-colors ${
              big ? "w-10 h-10" : "w-9 h-9"
            } ${
              canRun ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400" : "bg-zinc-800 text-zinc-600 cursor-not-allowed"
            }`}
          >
            <Play size={big ? 17 : 15} weight="fill" />
          </button>
        )}
      </div>
    </div>
  );
}

// ── Campaign composer (domain input, shown before a campaign is started) ──
function CampaignComposer({ domain, setDomain, onStart, canStart, starting, t }) {
  const submit = () => {
    if (canStart) onStart();
  };
  return (
    <div className="w-full max-w-[720px] mx-auto">
      <div className="flex items-end gap-2 border border-white/[0.10] bg-zinc-900/60 px-4 py-3 rounded-2xl transition-colors focus-within:border-emerald-500/50">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder={t.termDomainPlaceholder}
          className="flex-1 min-w-0 bg-transparent text-[15px] text-zinc-100 placeholder:text-zinc-600 outline-none"
        />
        <button
          onClick={submit}
          disabled={!canStart}
          aria-label={t.termStart}
          title={t.termStart}
          className={`shrink-0 w-10 h-10 flex items-center justify-center rounded-lg transition-colors ${
            canStart ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400" : "bg-zinc-800 text-zinc-600 cursor-not-allowed"
          }`}
        >
          {starting ? <CircleNotch size={17} className="animate-spin" /> : <Play size={17} weight="fill" />}
        </button>
      </div>
    </div>
  );
}

// ── Chat bubbles (shared shape: one turn, single-run or one phase's turn) ──
function AgentTurnBubble({ turn, label }) {
  const resultByCallId = Object.fromEntries((turn.tool_results || []).map((r) => [r.call_id, r]));
  return (
    <div className="flex gap-2.5 max-w-[720px]">
      <div className="w-6 h-6 rounded-full bg-emerald-500/15 border border-emerald-500/25 flex items-center justify-center shrink-0 mt-0.5">
        <Robot size={13} className="text-emerald-400" weight="fill" />
      </div>
      <div className="min-w-0 flex-1 space-y-1.5">
        <span className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-600">{label}</span>
        {turn.reasoning && (
          <p className="text-[13.5px] leading-relaxed text-zinc-200 whitespace-pre-wrap">{turn.reasoning}</p>
        )}
        {turn.tool_calls?.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {turn.tool_calls.map((c) => {
              const r = resultByCallId[c.id];
              const cls = !r
                ? "border-white/[0.08] text-zinc-400 bg-zinc-900/40"
                : r.ok
                  ? "border-emerald-600/30 text-emerald-400/90 bg-emerald-500/[0.05]"
                  : "border-red-500/30 text-red-300/90 bg-red-500/[0.05]";
              return (
                <span key={c.id} className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono border ${cls}`}>
                  {c.name}
                </span>
              );
            })}
          </div>
        )}
        {turn.next_plan && (
          <p className="text-[11.5px] text-zinc-500 italic">{turn.next_plan}</p>
        )}
      </div>
    </div>
  );
}

function UserBubble({ text, sub, t }) {
  return (
    <div className="flex flex-row-reverse gap-2.5 max-w-[720px] ml-auto">
      <div className="w-6 h-6 rounded-full bg-zinc-800 border border-white/[0.08] flex items-center justify-center shrink-0 mt-0.5">
        <span className="text-[10px] font-semibold text-zinc-400">{(t.aiYou || "Y")[0]}</span>
      </div>
      <div className="min-w-0 space-y-1">
        <span className="block text-right text-[10.5px] font-mono uppercase tracking-wider text-zinc-600">{t.aiYou}</span>
        <p className="text-[13.5px] leading-relaxed text-zinc-100 bg-zinc-900/50 border border-white/[0.07] px-3 py-2 whitespace-pre-wrap">
          {text}
        </p>
        {sub && <p className="text-right text-[11px] font-mono text-zinc-600">{sub}</p>}
      </div>
    </div>
  );
}

// ── Approvals card (continuous mode — held state-changing actions) ─────────
function Approvals({ campaign, t, onApprove, onReject, busy }) {
  const pending = (campaign.pending_approvals || []).filter((p) => p.status === "pending");
  const resolved = (campaign.pending_approvals || []).filter((p) => p.status !== "pending");
  if (!pending.length && !resolved.length) return null;
  return (
    <div className="border border-amber-500/25 bg-amber-500/[0.04] max-w-[720px]">
      <div className="px-3 py-2 border-b border-amber-500/15 flex items-center gap-1.5 text-[12px] font-semibold text-amber-200/90">
        <ShieldWarning size={14} weight="fill" /> {t.termApprovals}
      </div>
      <div className="px-3 py-2 space-y-2">
        {pending.map((p) => (
          <div key={p.id} className="text-[12px]">
            <ToolCallLine call={p.tool_call} />
            {p.rationale && <p className="text-[11.5px] text-zinc-400 mt-0.5">{p.rationale}</p>}
            <div className="flex gap-1.5 mt-1.5">
              <button
                disabled={busy}
                onClick={() => onApprove(p.id)}
                className="inline-flex items-center gap-1 px-2 py-1 text-[11.5px] font-medium bg-emerald-500 text-zinc-950 hover:bg-emerald-400 disabled:opacity-50"
              >
                <Check size={12} weight="bold" /> {t.termApprove}
              </button>
              <button
                disabled={busy}
                onClick={() => onReject(p.id)}
                className="inline-flex items-center gap-1 px-2 py-1 text-[11.5px] font-medium border border-white/[0.1] text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
              >
                <X size={12} weight="bold" /> {t.termReject}
              </button>
            </div>
          </div>
        ))}
        {resolved.map((p) => (
          <div key={p.id} className="text-[11.5px] font-mono text-zinc-500">
            <span className={p.status === "approved" ? "text-emerald-400/80" : "text-zinc-600"}>
              [{p.status === "approved" ? t.termApproved : t.termRejected}]
            </span>{" "}
            {p.tool_call?.name}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Center column: single-run chat thread ──────────────────────────────────
function SingleThread({ run, runErr, t, bottomRef }) {
  return (
    <div className="lg:flex-1 lg:min-h-0 lg:overflow-y-auto space-y-4 py-4">
      {runErr && (
        <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">{runErr}</p>
      )}
      {run && (
        <>
          <UserBubble text={run.config?.goal} sub={`${t.aiTarget}: ${run.config?.target}`} t={t} />
          {run.error && (
            <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2 ml-8">
              {run.error}
            </p>
          )}
          {(run.transcript || []).map((turn) => (
            <AgentTurnBubble key={turn.index} turn={turn} label={`${t.aiAgentLabel} · ${t.aiTurn} ${turn.index + 1}`} />
          ))}
          {run.outcome === "incomplete" && (
            <div className="flex items-center gap-2 text-[12px] font-mono text-zinc-500 ml-8">
              <CircleNotch size={13} className="animate-spin text-emerald-400" /> {t.aiRunning}
            </div>
          )}
          {run.outcome === "stopped" && (
            <p className="text-[12px] font-mono text-zinc-500 ml-8">{t.termStopped}</p>
          )}
        </>
      )}
      <div ref={bottomRef} />
    </div>
  );
}

// ── Center column: continuous-campaign thread ──────────────────────────────
function CampaignThread({ campaign, campaignErr, busy, onApprove, onReject, onContinue, onStop, t, bottomRef }) {
  const status = campaign?.status;
  const running = status === "running";
  const phaseRuns = campaign?.phase_runs || [];
  const openApprovals = useMemo(
    () => (campaign?.pending_approvals || []).some((p) => p.status === "pending"),
    [campaign]
  );

  return (
    <div className="lg:flex-1 lg:min-h-0 lg:overflow-y-auto space-y-4 py-4">
      {campaignErr && (
        <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">{campaignErr}</p>
      )}
      {campaign && (
        <>
          <UserBubble text={campaign.config?.domain} sub={campaign.config?.autopilot ? t.termAutopilot : undefined} t={t} />

          {phaseRuns.map((run, pi) =>
            (run.transcript || []).map((turn) => (
              <AgentTurnBubble
                key={`${run.id || pi}-${turn.index}`}
                turn={turn}
                label={`${t.termPhase} ${pi + 1} · ${t.aiTurn} ${turn.index + 1}`}
              />
            ))
          )}

          <Approvals campaign={campaign} t={t} busy={busy} onApprove={onApprove} onReject={onReject} />

          {running && (
            <p className="flex items-center gap-2 text-[12px] font-mono text-emerald-400 ml-8">
              <CircleNotch size={13} className="animate-spin" /> {t.termRunning}
            </p>
          )}

          {/* Stop is available any time the campaign is live — including mid-phase. */}
          {["running", "awaiting_user", "hardened"].includes(status) && (
            <div
              className={`max-w-[720px] border px-3 py-2.5 ${
                status === "hardened" ? "border-sky-500/25 bg-sky-500/[0.05]" : "border-white/[0.07] bg-zinc-900/30"
              }`}
            >
              {status !== "running" && (
                <p className="text-[12.5px] text-zinc-200 mb-2">
                  {status === "hardened" ? t.termHardened : t.termAwaiting}
                </p>
              )}
              <div className="flex gap-1.5">
                {status !== "running" && (
                  <button
                    disabled={busy || openApprovals}
                    title={openApprovals ? t.termApprovals : undefined}
                    onClick={onContinue}
                    className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-semibold bg-emerald-500 text-zinc-950 hover:bg-emerald-400 disabled:opacity-50"
                  >
                    <ArrowRight size={13} weight="bold" />
                    {status === "hardened" ? t.termContinueAnyway : t.termContinue}
                  </button>
                )}
                <button
                  disabled={busy}
                  onClick={onStop}
                  className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-medium border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20 disabled:opacity-50"
                >
                  <Stop size={13} weight="fill" /> {t.termStop}
                </button>
              </div>
            </div>
          )}

          {status === "completed" && (
            <p className="flex items-center gap-2 text-[12px] font-mono text-emerald-400/90 border border-emerald-500/20 bg-emerald-500/[0.05] px-3 py-2 max-w-[720px]">
              <Check size={13} weight="bold" /> {t.termCompleted}
            </p>
          )}
          {status === "stopped" && <p className="text-[12px] font-mono text-zinc-500 ml-8">{t.termStopped}</p>}
          {status === "error" && campaign.error && (
            <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2 max-w-[720px]">
              {campaign.error}
            </p>
          )}
        </>
      )}
      <div ref={bottomRef} />
    </div>
  );
}

// ── Right column, top half: retractable raw tool output ───────────────────
function TerminalPanel({ agentMode, run, campaign, memory, open, onToggle, t }) {
  if (!open) {
    return (
      <button
        onClick={onToggle}
        aria-label={t.aiTerminal}
        title={t.aiTerminal}
        className="flex flex-col items-center gap-2 flex-1 min-h-0 w-10 shrink-0 pt-3 text-zinc-500 hover:text-emerald-400
                   border border-white/[0.07] bg-zinc-900/30 transition-colors"
      >
        <CaretLeft size={14} />
        <TerminalIcon size={16} />
      </button>
    );
  }

  const singleTurns = run?.transcript || [];
  const phaseRuns = campaign?.phase_runs || [];

  return (
    <div className="flex-1 min-h-0 flex flex-col border border-white/[0.07] bg-zinc-900/30">
      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06] shrink-0">
        <span className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-zinc-400">
          <TerminalIcon size={13} /> {t.aiTerminal}
        </span>
        <button onClick={onToggle} aria-label="Collapse" className="text-zinc-500 hover:text-zinc-200 transition-colors">
          <CaretRight size={14} />
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto p-2.5 space-y-2.5">
        {agentMode === "single" ? (
          singleTurns.length === 0 ? (
            <p className="text-[12px] text-zinc-600 italic p-1.5">{t.aiTerminalEmpty}</p>
          ) : (
            singleTurns.map((turn) => <TurnCard key={turn.index} turn={turn} label={`${t.aiTurn} ${turn.index + 1}`} />)
          )
        ) : campaign ? (
          <>
            <div className="border border-white/[0.06] bg-zinc-900/20 p-2.5">
              <p className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-500 mb-1.5">{t.termCoverage}</p>
              <CoverageMap coverage={campaign.coverage} t={t} />
            </div>
            {phaseRuns.flatMap((run, pi) =>
              (run.transcript || []).map((turn) => (
                <TurnCard
                  key={`${run.id || pi}-${turn.index}`}
                  turn={turn}
                  label={`${t.termPhase} ${pi + 1} · ${t.aiTurn} ${turn.index + 1}`}
                />
              ))
            )}
          </>
        ) : (
          <p className="text-[12px] text-zinc-600 italic p-1.5">{t.aiTerminalEmpty}</p>
        )}
        <MemoryView summary={memory} t={t} />
      </div>
    </div>
  );
}

export default function Agent({ t }) {
  const [agentMode, setAgentMode] = useState("single"); // "single" | "continuous"
  const [pool, setPool] = useState({ policy: "tiered", accounts: [] });
  const [mode, setMode] = useState("router"); // "router" | "offline" — shared by both modes

  // ── single-run state ──
  const [goal, setGoal] = useState("");
  const [target, setTarget] = useState("127.0.0.1");
  const [authTargets, setAuthTargets] = useState("");
  const [stepBudget, setStepBudget] = useState(6);
  const [runId, setRunId] = useState("");
  const [run, setRun] = useState(null);
  const [running, setRunning] = useState(false);
  const [runErr, setRunErr] = useState("");
  const [history, setHistory] = useState([]);

  // ── continuous-campaign state ──
  const [domain, setDomain] = useState("");
  const [autopilot, setAutopilot] = useState(true);
  const [phaseStepBudget, setPhaseStepBudget] = useState(8);
  const [maxPhases, setMaxPhases] = useState(6);
  const [autoApprove, setAutoApprove] = useState(false);
  const [campaignId, setCampaignId] = useState("");
  const [campaign, setCampaign] = useState(null);
  const [campaignErr, setCampaignErr] = useState("");
  const [campaignBusy, setCampaignBusy] = useState(false);
  const [starting, setStarting] = useState(false);
  const [campaignHistory, setCampaignHistory] = useState([]);

  const [memory, setMemory] = useState(null);
  const [termOpen, setTermOpen] = useState(true);
  const bottomRef = useRef(null);

  const enabledAccounts = useMemo(() => (pool.accounts || []).filter((a) => a.enabled), [pool]);

  useEffect(() => {
    getAccounts()
      .then((data) => {
        setPool(data);
        if (!(data.accounts || []).some((a) => a.enabled)) setMode("offline");
      })
      .catch(() => {});
  }, []);

  const loadHistory = useCallback(() => {
    listRuns().then((data) => setHistory(data.runs || [])).catch(() => {});
  }, []);
  const loadCampaignHistory = useCallback(() => {
    listCampaigns().then((data) => setCampaignHistory(data.campaigns || [])).catch(() => {});
  }, []);

  useEffect(() => loadHistory(), [loadHistory]);
  useEffect(() => loadCampaignHistory(), [loadCampaignHistory]);

  const activeTarget = agentMode === "single" ? target : domain;
  const loadMemory = useCallback(() => {
    if (!activeTarget.trim()) return setMemory(null);
    getMemory(activeTarget.trim()).then(setMemory).catch(() => {});
  }, [activeTarget]);
  useEffect(() => loadMemory(), [loadMemory]);

  // Poll the single run until it leaves "incomplete".
  useEffect(() => {
    if (!runId) return;
    let active = true;
    const tick = async () => {
      try {
        const r = await getRun(runId);
        if (!active) return;
        setRun(r);
        if (r.outcome !== "incomplete") {
          setRunning(false);
          clearInterval(h);
          loadMemory();
          loadHistory();
        }
      } catch (e) {
        if (active) {
          setRunErr(String(e.message || e));
          setRunning(false);
          clearInterval(h);
        }
      }
    };
    const h = setInterval(tick, POLL_MS);
    tick();
    return () => {
      active = false;
      clearInterval(h);
    };
  }, [runId, loadMemory, loadHistory]);

  // Poll the campaign while it's live.
  useEffect(() => {
    if (!campaignId) return;
    let active = true;
    const tick = async () => {
      try {
        const c = await getCampaign(campaignId);
        if (!active) return;
        setCampaign(c);
        if (["stopped", "error", "completed"].includes(c.status)) {
          clearInterval(h);
          loadMemory();
          loadCampaignHistory();
        }
      } catch (e) {
        if (active) setCampaignErr(String(e.message || e));
      }
    };
    const h = setInterval(tick, POLL_MS);
    tick();
    return () => {
      active = false;
      clearInterval(h);
    };
  }, [campaignId, loadMemory, loadCampaignHistory]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [run?.transcript?.length, campaign?.phase_runs?.length]);

  const noAccounts = mode === "router" && enabledAccounts.length === 0;
  const canRun = goal.trim() && target.trim() && !running && !noAccounts;
  const canStart = domain.trim() && !starting && !(mode === "router" && noAccounts);

  const onRun = useCallback(async () => {
    setRunErr("");
    setRun(null);
    setRunId("");
    const body = {
      goal: goal.trim(),
      target: target.trim(),
      backend: mode,
      step_budget: Number(stepBudget) || 6,
      authorized_targets: authTargets.split(",").map((s) => s.trim()).filter(Boolean),
    };
    try {
      setRunning(true);
      const { id } = await startRun(body);
      setRunId(id);
      setHistory((prev) => [
        { id, goal: body.goal, target: body.target, backend: body.backend, outcome: "incomplete", turns: 0 },
        ...prev.filter((h) => h.id !== id),
      ]);
      setGoal("");
    } catch (e) {
      setRunning(false);
      setRunErr(String(e.message || e));
    }
  }, [goal, target, mode, stepBudget, authTargets]);

  const onStopRun = useCallback(async () => {
    if (!runId) return;
    // A 409 just means the run finished on its own a moment before Stop landed — a benign
    // race, not a real error. Either way the poll loop already reflects the true outcome.
    try {
      await stopRun(runId);
    } catch {
      /* ignore */
    }
  }, [runId]);

  const onSelectHistory = useCallback((id) => {
    setRunErr("");
    setRun(null);
    setRunId(id);
  }, []);
  const onNewRun = useCallback(() => {
    setRunId("");
    setRun(null);
    setRunErr("");
    setGoal("");
  }, []);

  const onStartCampaign = useCallback(async () => {
    setCampaignErr("");
    setCampaign(null);
    setCampaignId("");
    const body = {
      domain: domain.trim(),
      backend: mode,
      phase_step_budget: Number(phaseStepBudget) || 8,
      max_phases: Number(maxPhases) || 6,
      auto_approve_mutating: autoApprove,
      authorized_targets: authTargets.split(",").map((s) => s.trim()).filter(Boolean),
    };
    try {
      setStarting(true);
      const startFn = autopilot ? startPentest : startCampaign;
      const { id } = await startFn(body);
      setCampaignId(id);
      setCampaignHistory((prev) => [
        { id, domain: body.domain, status: "running", phases: 0 },
        ...prev.filter((h) => h.id !== id),
      ]);
    } catch (e) {
      setCampaignErr(String(e.message || e));
    } finally {
      setStarting(false);
    }
  }, [domain, mode, phaseStepBudget, maxPhases, autoApprove, authTargets, autopilot]);

  const campaignAct = useCallback(
    async (fn, ...args) => {
      setCampaignBusy(true);
      setCampaignErr("");
      try {
        await fn(campaignId, ...args);
        setCampaign(await getCampaign(campaignId));
      } catch (e) {
        setCampaignErr(String(e.message || e));
      } finally {
        setCampaignBusy(false);
      }
    },
    [campaignId]
  );

  const onSelectCampaign = useCallback((id) => {
    setCampaignErr("");
    setCampaign(null);
    setCampaignId(id);
  }, []);
  const onNewCampaign = useCallback(() => {
    setCampaignId("");
    setCampaign(null);
    setCampaignErr("");
    setDomain("");
  }, []);

  const configProps = {
    mode, setMode, authTargets, setAuthTargets, noAccounts, enabledAccounts, pool,
  };

  const showSingleChat = Boolean(runId);
  const showCampaignThread = Boolean(campaignId);

  return (
    <div className="page-enter agent-page-shell mx-auto max-w-[1480px] px-4 sm:px-6 lg:px-8 py-6 flex flex-col">
      {/* Single run / Continuous toggle — the merged "Agent" surface's top-level switch. */}
      <div className="shrink-0 mb-4 flex gap-1.5">
        {[
          { id: "single", label: t.agentModeSingle },
          { id: "continuous", label: t.agentModeContinuous },
        ].map((m) => (
          <button
            key={m.id}
            onClick={() => setAgentMode(m.id)}
            className={`px-3 py-1.5 text-[12.5px] font-medium border transition-colors ${
              agentMode === m.id
                ? "bg-zinc-800 text-emerald-400 border-emerald-500/30"
                : "text-zinc-500 border-white/[0.07] hover:text-zinc-200"
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="flex flex-col lg:flex-row gap-4 lg:flex-1 lg:min-h-0">
        <aside className="hidden lg:flex w-[220px] shrink-0 flex-col min-h-0">
          {agentMode === "single" ? (
            <HistorySidebar kind="single" history={history} activeId={runId} onSelect={onSelectHistory} onNew={onNewRun} t={t} />
          ) : (
            <HistorySidebar
              kind="continuous" history={campaignHistory} activeId={campaignId}
              onSelect={onSelectCampaign} onNew={onNewCampaign} t={t}
            />
          )}
        </aside>

        <div className="flex-1 min-w-0 flex flex-col lg:min-h-0">
          {agentMode === "single" ? (
            !showSingleChat ? (
              <div className="py-10 lg:py-0 lg:flex-1 lg:min-h-0 flex flex-col justify-center">
                <Composer size="lg" t={t} goal={goal} setGoal={setGoal} onRun={onRun} onStop={onStopRun} canRun={canRun} running={running} />
              </div>
            ) : (
              <>
                <SingleThread run={run} runErr={runErr} t={t} bottomRef={bottomRef} />
                <div className="shrink-0 pt-3">
                  <Composer size="sm" t={t} goal={goal} setGoal={setGoal} onRun={onRun} onStop={onStopRun} canRun={canRun} running={running} />
                </div>
              </>
            )
          ) : !showCampaignThread ? (
            <div className="py-10 lg:py-0 lg:flex-1 lg:min-h-0 flex flex-col justify-center">
              <CampaignComposer domain={domain} setDomain={setDomain} onStart={onStartCampaign} canStart={canStart} starting={starting} t={t} />
            </div>
          ) : (
            <CampaignThread
              campaign={campaign}
              campaignErr={campaignErr}
              busy={campaignBusy}
              onApprove={(id) => campaignAct(approveAction, id)}
              onReject={(id) => campaignAct(rejectAction, id)}
              onContinue={() => campaignAct(continueCampaign)}
              onStop={() => campaignAct(stopCampaign)}
              t={t}
              bottomRef={bottomRef}
            />
          )}
        </div>

        <aside className="flex flex-col lg:w-[340px] shrink-0 min-h-0 gap-4">
          <div className="hidden lg:flex lg:flex-1 lg:min-h-0">
            <TerminalPanel
              agentMode={agentMode} run={run} campaign={campaign} memory={memory}
              open={termOpen} onToggle={() => setTermOpen((v) => !v)} t={t}
            />
          </div>
          {agentMode === "single" && showSingleChat && (
            <p className="lg:hidden flex items-center gap-1.5 text-[11px] text-zinc-600">
              <ChatCircleDots size={13} /> {t.aiTerminal}: {t.aiTurns} {run?.transcript?.length || 0}
            </p>
          )}
          {agentMode === "single" ? (
            <SingleConfigPanel {...configProps} target={target} setTarget={setTarget} stepBudget={stepBudget} setStepBudget={setStepBudget} t={t} />
          ) : (
            <CampaignConfigPanel
              {...configProps}
              phaseStepBudget={phaseStepBudget} setPhaseStepBudget={setPhaseStepBudget}
              maxPhases={maxPhases} setMaxPhases={setMaxPhases}
              autopilot={autopilot} setAutopilot={setAutopilot}
              autoApprove={autoApprove} setAutoApprove={setAutoApprove}
              t={t}
            />
          )}
        </aside>
      </div>
    </div>
  );
}
