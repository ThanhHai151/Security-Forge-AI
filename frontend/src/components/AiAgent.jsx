import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Robot,
  Play,
  CircleNotch,
  Brain,
  Stack,
  ShieldCheck,
  Warning,
  Plugs,
  ArrowRight,
} from "@phosphor-icons/react";

import { getAccounts, startRun, getRun, getMemory } from "../lib/api";

const POLL_MS = 1200;

function Dot({ ok }) {
  return (
    <span
      className={`inline-block w-1.5 h-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-zinc-600"}`}
      style={ok ? { boxShadow: "0 0 6px rgba(64,212,168,0.9)" } : undefined}
    />
  );
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

function TurnCard({ turn, t }) {
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-1.5 border-b border-white/[0.06]">
        <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
          {t.aiTurn} {turn.index + 1}
        </span>
      </div>
      <div className="px-3 py-2.5 space-y-2">
        {turn.reasoning && (
          <p className="text-[12.5px] leading-relaxed text-zinc-300 whitespace-pre-wrap">
            {turn.reasoning}
          </p>
        )}
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
        {turn.next_plan && (
          <p className="text-[12px] text-zinc-400">
            <span className="text-zinc-600 font-mono">{t.aiPlan}: </span>
            {turn.next_plan}
          </p>
        )}
      </div>
    </div>
  );
}

const KIND_LABEL = {
  target_fact: "fact",
  attempt: "attempt",
  lesson: "lesson",
};

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
      <div className="px-3 py-2 max-h-[260px] overflow-y-auto">
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

export default function AiAgent({ t }) {
  const [pool, setPool] = useState({ policy: "tiered", accounts: [] });
  const [mode, setMode] = useState("router"); // "router" | "offline"

  const [goal, setGoal] = useState("");
  const [target, setTarget] = useState("127.0.0.1");
  const [authTargets, setAuthTargets] = useState("");
  const [stepBudget, setStepBudget] = useState(6);

  const [runId, setRunId] = useState("");
  const [run, setRun] = useState(null);
  const [running, setRunning] = useState(false);
  const [runErr, setRunErr] = useState("");
  const [memory, setMemory] = useState(null);

  const enabledAccounts = useMemo(
    () => (pool.accounts || []).filter((a) => a.enabled),
    [pool]
  );

  // Load the account pool; default to offline if nothing is configured yet.
  useEffect(() => {
    getAccounts()
      .then((data) => {
        setPool(data);
        if (!(data.accounts || []).some((a) => a.enabled)) setMode("offline");
      })
      .catch(() => {});
  }, []);

  const loadMemory = useCallback(() => {
    if (!target.trim()) return setMemory(null);
    getMemory(target.trim()).then(setMemory).catch(() => {});
  }, [target]);

  useEffect(() => {
    loadMemory();
  }, [loadMemory]);

  // Poll the run until it leaves "incomplete"; refresh memory when it finishes.
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
  }, [runId, loadMemory]);

  const noAccounts = mode === "router" && enabledAccounts.length === 0;
  const canRun = goal.trim() && target.trim() && !running && !noAccounts;

  const onRun = useCallback(async () => {
    setRunErr("");
    setRun(null);
    setRunId("");
    const body = {
      goal: goal.trim(),
      target: target.trim(),
      backend: mode,
      step_budget: Number(stepBudget) || 6,
      authorized_targets: authTargets
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };
    try {
      setRunning(true);
      const { id } = await startRun(body);
      setRunId(id);
    } catch (e) {
      setRunning(false);
      setRunErr(String(e.message || e));
    }
  }, [goal, target, mode, stepBudget, authTargets]);

  const reports = run?.compaction_reports || [];
  const lastReport = reports[reports.length - 1];

  return (
    <div className="page-enter mx-auto max-w-[1240px] px-5 sm:px-8 lg:px-12 py-10">
      {/* ── Hero ── */}
      <header className="pb-7">
        <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          <Robot size={15} weight="fill" /> {t.aiKicker}
        </p>
        <h1 className="mt-3 text-[2.1rem] sm:text-[2.8rem] font-bold text-zinc-50 tracking-tight leading-[1.08] max-w-[22ch]">
          {t.aiTitle}
        </h1>
        <p className="mt-5 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[70ch]">{t.aiLead}</p>
      </header>

      {/* ── Capability strip ── */}
      <div className="grid sm:grid-cols-3 gap-3 mb-8">
        {[
          { icon: Brain, title: t.aiMemoryTitle, body: t.aiMemoryNote },
          { icon: Stack, title: t.aiBudgetTitle, body: t.aiBudgetNote },
          { icon: ShieldCheck, title: t.aiPersonaTitle, body: t.aiPersonaNote },
        ].map((x) => (
          <div key={x.title} className="border border-white/[0.07] bg-zinc-900/30 p-3">
            <p className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
              <x.icon size={14} className="text-emerald-400" weight="fill" /> {x.title}
            </p>
            <p className="mt-1 text-[11.5px] leading-snug text-zinc-500">{x.body}</p>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-[380px_1fr] gap-6 items-start">
        {/* ── Config column ── */}
        <div className="space-y-4">
          <Field label={t.aiMode}>
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
          </Field>

          {mode === "router" &&
            (noAccounts ? (
              <a
                href="#/router"
                className="flex items-center justify-between gap-2 border border-amber-500/25 bg-amber-500/[0.05] px-3 py-2.5 text-[12.5px] text-amber-200/90 hover:bg-amber-500/[0.09] transition-colors"
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

          <Field label={t.aiGoal}>
            <textarea
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              rows={2}
              placeholder={t.aiGoalPlaceholder}
              className={inputCls + " resize-y"}
            />
          </Field>

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
              type="number"
              min={1}
              max={50}
              value={stepBudget}
              onChange={(e) => setStepBudget(e.target.value)}
              className={inputCls + " w-28"}
            />
          </Field>

          <button
            onClick={onRun}
            disabled={!canRun}
            className={`w-full flex items-center justify-center gap-2 px-4 py-2.5 text-[13px] font-semibold transition-colors ${
              canRun
                ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
            }`}
          >
            {running ? (
              <>
                <CircleNotch size={15} className="animate-spin" /> {t.aiRunning}
              </>
            ) : (
              <>
                <Play size={15} weight="fill" /> {t.aiRun}
              </>
            )}
          </button>

          <p className="flex items-start gap-1.5 text-[11px] text-zinc-500">
            <Warning size={13} className="text-amber-400/80 mt-0.5 shrink-0" />
            {t.aiAuthNote}
          </p>
        </div>

        {/* ── Output column ── */}
        <div className="min-w-0 space-y-4">
          {runErr && (
            <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
              {runErr}
            </p>
          )}

          {run && (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3 border border-white/[0.07] bg-zinc-900/30 px-3 py-2">
                <span className="flex items-center gap-2 text-[12px]">
                  {run.outcome === "incomplete" ? (
                    <CircleNotch size={14} className="animate-spin text-emerald-400" />
                  ) : (
                    <Dot ok={run.outcome === "done"} />
                  )}
                  <span className="font-mono text-zinc-300">
                    {run.outcome === "incomplete" ? t.aiRunning : run.outcome}
                  </span>
                </span>
                <span className="text-[11px] font-mono text-zinc-500">
                  {t.aiTurns}: {run.transcript?.length || 0}
                  {lastReport && ` · ${t.aiBudget}: ${lastReport.tokens_after}/${lastReport.input_budget}`}
                </span>
              </div>

              {run.error && (
                <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
                  {run.error}
                </p>
              )}

              {(run.transcript || []).map((turn) => (
                <TurnCard key={turn.index} turn={turn} t={t} />
              ))}
            </div>
          )}

          {!run && !runErr && (
            <div className="border border-dashed border-white/[0.10] py-12 text-center">
              <Robot size={28} className="text-zinc-700 mx-auto" />
              <p className="mt-3 text-[13px] text-zinc-500">{t.aiNoRun}</p>
            </div>
          )}

          {/* Hermes memory for this target — grows as the agent learns */}
          <MemoryView summary={memory} t={t} />
        </div>
      </div>
    </div>
  );
}
