import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Stack,
  ArrowsClockwise,
  CircleNotch,
  CheckCircle,
  MagnifyingGlass,
} from "@phosphor-icons/react";

import { getModelsOverview, getAccountModels, updateAccount } from "../lib/api";
import SettingsModal from "./SettingsModal";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2 text-[13px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";

// One connected account: shows its current model and lets you switch it, fetching the live
// list on demand (the overview itself is network-free, so probing stays opt-in per account).
function AccountModelRow({ a, t, onChanged }) {
  const [model, setModel] = useState(a.model || "");
  const [live, setLive] = useState([]);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);

  const fetchModels = useCallback(async () => {
    setBusy(true);
    try {
      const r = await getAccountModels(a.id);
      setLive(r.models || []);
    } finally {
      setBusy(false);
    }
  }, [a.id]);

  const apply = useCallback(async () => {
    if (!model.trim() || model === a.model) return;
    setBusy(true);
    try {
      await updateAccount(a.id, { model: model.trim() });
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
      onChanged();
    } finally {
      setBusy(false);
    }
  }, [a.id, model, a.model, onChanged]);

  return (
    <div className="border border-white/[0.07] bg-zinc-900/40 p-3 space-y-2">
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-[12.5px] font-semibold text-zinc-100 truncate">{a.label}</span>
        <span className="text-[10px] font-mono uppercase tracking-wider px-1 py-0.5 border border-white/[0.08] text-zinc-400">
          {a.api_style}
        </span>
        {!a.enabled && <span className="text-[10px] font-mono text-zinc-600">off</span>}
      </div>
      <div className="flex gap-2">
        <input
          value={model}
          onChange={(e) => setModel(e.target.value)}
          placeholder={t.mdCurrent}
          list={`models-${a.id}`}
          className={inputCls}
        />
        {live.length > 0 && (
          <datalist id={`models-${a.id}`}>
            {live.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        )}
        <button
          onClick={fetchModels}
          disabled={busy}
          title={t.mdFetch}
          className="shrink-0 px-2.5 border border-white/[0.08] text-zinc-400 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-40"
        >
          {busy ? (
            <CircleNotch size={14} className="animate-spin" />
          ) : (
            <ArrowsClockwise size={14} />
          )}
        </button>
        <button
          onClick={apply}
          disabled={busy || !model.trim() || model === a.model}
          className="shrink-0 flex items-center gap-1 px-3 text-[12px] font-medium border border-white/[0.10] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-30"
        >
          {saved ? <CheckCircle size={13} weight="fill" className="text-emerald-400" /> : null}
          {saved ? t.mdApplied : t.mdSet}
        </button>
      </div>
      {live.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {live.slice(0, 24).map((m) => (
            <button
              key={m}
              onClick={() => setModel(m)}
              className={`px-2 py-0.5 text-[11px] font-mono border transition-colors ${
                model === m
                  ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/[0.08]"
                  : "border-white/[0.08] text-zinc-400 hover:text-zinc-100 hover:border-white/20"
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ModelsModal({ t, onClose }) {
  const [accounts, setAccounts] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");

  const refresh = useCallback(async () => {
    try {
      const data = await getModelsOverview();
      setAccounts(data.accounts || []);
      setCatalog(data.catalog || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Catalog filtered by the search box (matches provider label or model id).
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return catalog;
    return catalog
      .map((c) => ({
        ...c,
        models: c.models.filter(
          (m) => m.toLowerCase().includes(needle) || c.label.toLowerCase().includes(needle)
        ),
      }))
      .filter((c) => c.models.length > 0);
  }, [catalog, q]);

  return (
    <SettingsModal
      title={t.mdTitle}
      subtitle={t.mdSubtitle}
      icon={<Stack size={18} weight="fill" className="text-emerald-400 shrink-0" />}
      onClose={onClose}
    >
      {loading ? (
        <p className="flex items-center gap-2 text-[13px] text-zinc-500 py-4">
          <CircleNotch size={15} className="animate-spin" /> {t.mdTitle}…
        </p>
      ) : (
        <>
          <div>
            <p className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 mb-2">
              {t.mdAccounts} · {accounts.length}
            </p>
            {accounts.length === 0 ? (
              <p className="text-[13px] text-zinc-500">{t.mdNoAccounts}</p>
            ) : (
              <div className="space-y-2.5">
                {accounts.map((a) => (
                  <AccountModelRow key={a.id} a={a} t={t} onChanged={refresh} />
                ))}
              </div>
            )}
          </div>

          <div className="pt-1">
            <p className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 mb-2">
              {t.mdCatalog}
            </p>
            <div className="relative mb-2">
              <MagnifyingGlass
                size={14}
                className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600"
              />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={t.mdSearch}
                className={`${inputCls} pl-8`}
              />
            </div>
            {filtered.length === 0 ? (
              <p className="text-[12px] text-zinc-500">{t.mdNoModels}</p>
            ) : (
              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {filtered.map((c) => (
                  <div key={c.provider}>
                    <p className="text-[11.5px] font-semibold text-zinc-300 mb-1">{c.label}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {c.models.map((m) => (
                        <span
                          key={m}
                          className="px-2 py-0.5 text-[11px] font-mono border border-white/[0.08] text-zinc-400"
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </SettingsModal>
  );
}
