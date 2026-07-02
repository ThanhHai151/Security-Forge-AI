import { useCallback, useEffect, useState } from "react";
import { Gauge, ArrowClockwise, Trash, CircleNotch, FloppyDisk } from "@phosphor-icons/react";

import { getUsage, resetUsage, updateAccount } from "../lib/api";
import SettingsModal from "./SettingsModal";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-2 py-1 text-[12px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";

// Compact number formatting: 1234 → "1.2k", 1250000 → "1.2M".
function fmt(n) {
  const v = Number(n) || 0;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(v >= 10_000 ? 0 : 1)}k`;
  return String(v);
}

// Usage bar vs an optional daily limit. Green < 80%, amber < 100%, red at/over the ceiling.
function LimitBar({ used, limit }) {
  if (!limit) return null;
  const pct = Math.min(100, Math.round((used / limit) * 100));
  const color = used >= limit ? "bg-red-500" : pct > 80 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="mt-1 h-1.5 bg-zinc-800 overflow-hidden" title={`${used} / ${limit}`}>
      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function Metric({ label, value, sub }) {
  return (
    <div>
      <p className="text-[10px] font-mono uppercase tracking-wider text-zinc-600">{label}</p>
      <p className="text-[15px] font-semibold text-zinc-100 tabular-nums">{value}</p>
      {sub && <p className="text-[10.5px] text-zinc-500">{sub}</p>}
    </div>
  );
}

function QuotaRow({ a, t, onChanged }) {
  const [req, setReq] = useState(a.limits?.daily_requests || 0);
  const [tok, setTok] = useState(a.limits?.daily_tokens || 0);
  const [saving, setSaving] = useState(false);

  const today = a.today || {};
  const total = a.total || {};
  const calls = total.calls || 0;
  const okRate = calls ? Math.round(((total.ok || 0) / calls) * 100) : null;
  const dirty =
    Number(req) !== (a.limits?.daily_requests || 0) || Number(tok) !== (a.limits?.daily_tokens || 0);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      await updateAccount(a.id, {
        quota_daily_requests: Number(req) || 0,
        quota_daily_tokens: Number(tok) || 0,
      });
      onChanged();
    } finally {
      setSaving(false);
    }
  }, [a.id, req, tok, onChanged]);

  return (
    <div className="border border-white/[0.07] bg-zinc-900/40 p-3 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[12.5px] font-semibold text-zinc-100 truncate">{a.label}</span>
          <span className="text-[10px] font-mono uppercase tracking-wider px-1 py-0.5 border border-white/[0.08] text-zinc-400">
            {a.tier}
          </span>
          {a.health?.cooling && (
            <span className="text-[10px] font-mono text-amber-400/90">{t.qtCooling}</span>
          )}
          {!a.enabled && <span className="text-[10px] font-mono text-zinc-600">off</span>}
        </div>
        <button
          onClick={async () => {
            await resetUsage(a.id);
            onChanged();
          }}
          title={t.qtReset}
          className="shrink-0 flex items-center justify-center w-7 h-7 border border-white/[0.08] text-zinc-500 hover:text-red-400 hover:border-red-500/40 transition-colors"
        >
          <Trash size={12} />
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div>
          <Metric label={`${t.qtRequests} · ${t.qtToday}`} value={fmt(today.calls || 0)} />
          <LimitBar used={today.calls || 0} limit={a.limits?.daily_requests || 0} />
        </div>
        <div>
          <Metric label={`${t.qtTokens} · ${t.qtToday}`} value={fmt(today.total_tokens || 0)} />
          <LimitBar used={today.total_tokens || 0} limit={a.limits?.daily_tokens || 0} />
        </div>
        <Metric
          label={t.qtTotal}
          value={fmt(calls)}
          sub={`${fmt(total.total_tokens || 0)} ${t.qtTokens.toLowerCase()}`}
        />
        <Metric label={t.qtSuccess} value={okRate === null ? "—" : `${okRate}%`} />
      </div>

      <div className="flex items-end gap-2">
        <label className="flex-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-600 block mb-0.5">
            {t.qtLimitReq}
          </span>
          <input
            type="number"
            min="0"
            value={req}
            onChange={(e) => setReq(e.target.value)}
            placeholder={t.qtNoLimit}
            className={inputCls}
          />
        </label>
        <label className="flex-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-600 block mb-0.5">
            {t.qtLimitTok}
          </span>
          <input
            type="number"
            min="0"
            value={tok}
            onChange={(e) => setTok(e.target.value)}
            placeholder={t.qtNoLimit}
            className={inputCls}
          />
        </label>
        <button
          onClick={save}
          disabled={!dirty || saving}
          className="shrink-0 flex items-center gap-1 px-2.5 py-1.5 text-[12px] font-medium border border-white/[0.10] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-30"
        >
          {saving ? <CircleNotch size={12} className="animate-spin" /> : <FloppyDisk size={12} />}
          {t.qtSave}
        </button>
      </div>
    </div>
  );
}

export default function QuotaModal({ t, onClose }) {
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const data = await getUsage();
      setAccounts(data.accounts || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const h = setInterval(refresh, 5000); // live counters while the popup is open
    return () => clearInterval(h);
  }, [refresh]);

  const poolReq = accounts.reduce((s, a) => s + (a.today?.calls || 0), 0);
  const poolTok = accounts.reduce((s, a) => s + (a.today?.total_tokens || 0), 0);

  return (
    <SettingsModal
      title={t.qtTitle}
      subtitle={t.qtSubtitle}
      icon={<Gauge size={18} weight="fill" className="text-emerald-400 shrink-0" />}
      onClose={onClose}
    >
      {!loading && accounts.length > 0 && (
        <div className="flex items-center justify-between gap-3 text-[12px] text-zinc-400">
          <span>{t.qtPoolToday(fmt(poolReq), fmt(poolTok))}</span>
          <button
            onClick={async () => {
              if (window.confirm(t.qtResetConfirm)) {
                await resetUsage();
                refresh();
              }
            }}
            className="flex items-center gap-1 text-[11.5px] text-zinc-500 hover:text-red-400 transition-colors"
          >
            <ArrowClockwise size={12} /> {t.qtResetAll}
          </button>
        </div>
      )}

      {loading ? (
        <p className="flex items-center gap-2 text-[13px] text-zinc-500 py-4">
          <CircleNotch size={15} className="animate-spin" /> {t.qtTitle}…
        </p>
      ) : accounts.length === 0 ? (
        <p className="text-[13px] text-zinc-500 py-4">{t.qtNoAccounts}</p>
      ) : (
        <div className="space-y-2.5">
          {accounts.map((a) => (
            <QuotaRow key={a.id} a={a} t={t} onChanged={refresh} />
          ))}
        </div>
      )}
    </SettingsModal>
  );
}
