import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Plus,
  Terminal as TerminalIcon,
  CircleNotch,
  ArrowRight,
  Stop,
  ShieldWarning,
  Check,
  X,
  Lightning,
} from "@phosphor-icons/react";

import {
  getAccounts,
  startCampaign,
  getCampaign,
  continueCampaign,
  stopCampaign,
  approveAction,
  rejectAction,
} from "../lib/api";

const POLL_MS = 1200;

// Coverage-status → colour + glyph (the "đã thử / chưa thử" map).
const COV = {
  confirmed: { cls: "text-red-300 border-red-500/30 bg-red-500/[0.07]", glyph: "!" },
  blocked: { cls: "text-amber-300 border-amber-500/30 bg-amber-500/[0.07]", glyph: "⏸" },
  tried: { cls: "text-emerald-300 border-emerald-500/25 bg-emerald-500/[0.06]", glyph: "✓" },
  untried: { cls: "text-zinc-500 border-white/[0.08] bg-transparent", glyph: "·" },
};

function CoverageMap({ coverage, t }) {
  if (!coverage?.length)
    return <p className="text-[12px] text-zinc-500">{t.termEmptyCoverage}</p>;
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

function ToolLine({ call }) {
  return (
    <div className="text-[12px] font-mono">
      <span className="text-emerald-400">{call.name}</span>
      <span className="text-zinc-600">(</span>
      <span className="text-zinc-400 break-all">{JSON.stringify(call.arguments)}</span>
      <span className="text-zinc-600">)</span>
    </div>
  );
}

function PhaseBlock({ run, index, t }) {
  const turns = run?.transcript || [];
  return (
    <div className="border border-white/[0.07] bg-zinc-900/30">
      <div className="px-3 py-1.5 border-b border-white/[0.06] flex items-center justify-between">
        <span className="text-[10.5px] font-mono uppercase tracking-wider text-emerald-400/80">
          {t.termPhase} {index + 1}
        </span>
        <span className="text-[10.5px] font-mono text-zinc-500">
          {run?.outcome === "incomplete" ? t.termRunning : run?.outcome}
        </span>
      </div>
      <div className="px-3 py-2 space-y-2.5">
        {turns.map((turn) => (
          <div key={turn.index} className="space-y-1">
            {turn.reasoning && (
              <p className="text-[12px] leading-relaxed text-zinc-300 whitespace-pre-wrap">
                <span className="text-zinc-600 font-mono select-none">$ </span>
                {turn.reasoning}
              </p>
            )}
            {turn.tool_calls?.map((c) => (
              <ToolLine key={c.id} call={c} />
            ))}
            {turn.tool_results?.map((r) => (
              <pre
                key={r.call_id}
                className={`text-[11.5px] font-mono whitespace-pre-wrap overflow-x-auto px-2.5 py-1.5 border-l-2 ${
                  r.ok
                    ? "border-l-emerald-600 bg-[#0A1020] text-[#D8E4F8]"
                    : "border-l-amber-500 bg-amber-500/[0.05] text-amber-200/90"
                }`}
              >
                {r.log}
              </pre>
            ))}
            {turn.next_plan && (
              <p className="text-[12px] text-zinc-400">
                <ArrowRight size={11} className="inline text-zinc-600 mr-1" />
                {turn.next_plan}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function Approvals({ campaign, t, onApprove, onReject, busy }) {
  const pending = (campaign.pending_approvals || []).filter((p) => p.status === "pending");
  const resolved = (campaign.pending_approvals || []).filter((p) => p.status !== "pending");
  if (!pending.length && !resolved.length) return null;
  return (
    <div className="border border-amber-500/25 bg-amber-500/[0.04]">
      <div className="px-3 py-2 border-b border-amber-500/15 flex items-center gap-1.5 text-[12px] font-semibold text-amber-200/90">
        <ShieldWarning size={14} weight="fill" /> {t.termApprovals}
      </div>
      <div className="px-3 py-2 space-y-2">
        {pending.map((p) => (
          <div key={p.id} className="text-[12px]">
            <ToolLine call={p.tool_call} />
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
            {p.result_log && (
              <pre className="mt-1 whitespace-pre-wrap text-[11px] text-zinc-400 bg-[#0A1020] px-2 py-1 border-l-2 border-l-zinc-700">
                {p.result_log}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Terminal({ t }) {
  const [mode, setMode] = useState("offline"); // resolved from the account pool below
  const [campaignId, setCampaignId] = useState("");
  const [campaign, setCampaign] = useState(null);
  const [domain, setDomain] = useState("");
  const [showInput, setShowInput] = useState(true);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);

  // Pick the router backend when the operator has connected accounts, else offline.
  useEffect(() => {
    getAccounts()
      .then((data) => {
        if ((data.accounts || []).some((a) => a.enabled)) setMode("router");
      })
      .catch(() => {});
  }, []);

  // Poll the campaign while it exists and hasn't been stopped (keeps coverage/approvals fresh).
  useEffect(() => {
    if (!campaignId) return;
    let active = true;
    const tick = async () => {
      try {
        const c = await getCampaign(campaignId);
        if (!active) return;
        setCampaign(c);
        if (c.status === "stopped" || c.status === "error") clearInterval(h);
      } catch (e) {
        if (active) setErr(String(e.message || e));
      }
    };
    const h = setInterval(tick, POLL_MS);
    tick();
    return () => {
      active = false;
      clearInterval(h);
    };
  }, [campaignId]);

  const start = useCallback(async () => {
    const d = domain.trim();
    if (!d || busy) return;
    setErr("");
    setCampaign(null);
    setBusy(true);
    try {
      const { id } = await startCampaign({ domain: d, backend: mode });
      setCampaignId(id);
      setShowInput(false);
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }, [domain, mode, busy]);

  const act = useCallback(
    async (fn, ...args) => {
      setBusy(true);
      setErr("");
      try {
        await fn(campaignId, ...args);
        const c = await getCampaign(campaignId);
        setCampaign(c);
      } catch (e) {
        setErr(String(e.message || e));
      } finally {
        setBusy(false);
      }
    },
    [campaignId]
  );

  const status = campaign?.status;
  const running = status === "running";
  const phaseRuns = campaign?.phase_runs || [];
  const openApprovals = useMemo(
    () => (campaign?.pending_approvals || []).some((p) => p.status === "pending"),
    [campaign]
  );

  return (
    <div className="page-enter mx-auto max-w-[1100px] px-5 sm:px-8 lg:px-12 py-10">
      <header className="pb-6">
        <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          <TerminalIcon size={15} weight="fill" /> {t.termKicker}
        </p>
        <h1 className="mt-3 text-[2rem] sm:text-[2.5rem] font-bold text-zinc-50 tracking-tight leading-[1.1] max-w-[22ch]">
          {t.termTitle}
        </h1>
        <p className="mt-4 text-[1.02rem] leading-relaxed text-zinc-400 max-w-[72ch]">{t.termLead}</p>
      </header>

      {/* ── Terminal shell ── */}
      <div className="border border-white/[0.09] bg-[#080B12]">
        {/* Title bar with the (+) button */}
        <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.07] bg-zinc-900/40">
          <button
            onClick={() => {
              setShowInput((v) => !v);
              setTimeout(() => inputRef.current?.focus(), 0);
            }}
            aria-label={t.termNewTarget}
            title={t.termNewTarget}
            className="flex items-center justify-center w-6 h-6 border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors"
          >
            <Plus size={14} weight="bold" />
          </button>
          <span className="text-[11px] font-mono text-zinc-500">
            secforge://auto-pentest{campaign?.config?.domain ? ` — ${campaign.config.domain}` : ""}
          </span>
          <span className="ml-auto text-[10.5px] font-mono text-zinc-600">{mode}</span>
        </div>

        {/* Domain input (revealed by +) */}
        {showInput && (
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-white/[0.06]">
            <span className="text-emerald-500 font-mono text-[13px] select-none">$</span>
            <input
              ref={inputRef}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && start()}
              placeholder={t.termDomainPlaceholder}
              className="flex-1 bg-transparent border-none outline-none text-[13px] font-mono text-zinc-100 placeholder:text-zinc-600"
            />
            <button
              onClick={start}
              disabled={!domain.trim() || busy}
              className={`inline-flex items-center gap-1 px-3 py-1 text-[12px] font-semibold transition-colors ${
                domain.trim() && !busy
                  ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                  : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
              }`}
            >
              {busy ? <CircleNotch size={13} className="animate-spin" /> : <Lightning size={13} weight="fill" />}
              {t.termStart}
            </button>
          </div>
        )}

        {/* Body */}
        <div className="px-3 py-3 space-y-3 min-h-[220px]">
          {err && (
            <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
              {err}
            </p>
          )}

          {!campaign && !err && (
            <div className="py-14 text-center">
              <TerminalIcon size={26} className="text-zinc-700 mx-auto" />
              <p className="mt-3 text-[12.5px] text-zinc-500">{t.termNoRun}</p>
            </div>
          )}

          {campaign && (
            <>
              {/* Coverage map */}
              <div className="border border-white/[0.06] bg-zinc-900/20 p-2.5">
                <p className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-500 mb-1.5">
                  {t.termCoverage}
                </p>
                <CoverageMap coverage={campaign.coverage} t={t} />
              </div>

              {/* Pending approvals (state-changing actions held for you) */}
              <Approvals
                campaign={campaign}
                t={t}
                busy={busy}
                onApprove={(id) => act(approveAction, id)}
                onReject={(id) => act(rejectAction, id)}
              />

              {/* Phase transcripts */}
              {phaseRuns.map((run, i) => (
                <PhaseBlock key={run.id || i} run={run} index={i} t={t} />
              ))}

              {/* Live cursor while a phase runs */}
              {running && (
                <p className="flex items-center gap-2 text-[12px] font-mono text-emerald-400">
                  <CircleNotch size={13} className="animate-spin" /> {t.termRunning}
                  <span className="inline-block w-2 h-4 bg-emerald-400/80 animate-pulse" />
                </p>
              )}

              {/* Between-phase prompt: continue or stop (asked every phase) */}
              {(status === "awaiting_user" || status === "hardened") && (
                <div
                  className={`border px-3 py-2.5 ${
                    status === "hardened"
                      ? "border-sky-500/25 bg-sky-500/[0.05]"
                      : "border-emerald-500/20 bg-emerald-500/[0.04]"
                  }`}
                >
                  <p className="text-[12.5px] text-zinc-200">
                    {status === "hardened" ? t.termHardened : t.termAwaiting}
                  </p>
                  <div className="flex gap-1.5 mt-2">
                    <button
                      disabled={busy || openApprovals}
                      title={openApprovals ? t.termApprovals : undefined}
                      onClick={() => act(continueCampaign)}
                      className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-semibold bg-emerald-500 text-zinc-950 hover:bg-emerald-400 disabled:opacity-50"
                    >
                      <ArrowRight size={13} weight="bold" />
                      {status === "hardened" ? t.termContinueAnyway : t.termContinue}
                    </button>
                    <button
                      disabled={busy}
                      onClick={() => act(stopCampaign)}
                      className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-medium border border-white/[0.1] text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
                    >
                      <Stop size={13} weight="fill" /> {t.termStop}
                    </button>
                  </div>
                </div>
              )}

              {status === "stopped" && (
                <p className="text-[12px] font-mono text-zinc-500">{t.termStopped}</p>
              )}
              {status === "error" && campaign.error && (
                <p className="text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
                  {campaign.error}
                </p>
              )}
            </>
          )}
        </div>
      </div>

      <p className="mt-4 flex items-start gap-1.5 text-[11px] text-zinc-500">
        <ShieldWarning size={13} className="text-amber-400/80 mt-0.5 shrink-0" />
        {t.termAuthOnly}
      </p>
    </div>
  );
}
