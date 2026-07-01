import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Plugs,
  PlugsConnected,
  Power,
  Stack,
  Lightning,
  ArrowRight,
  Warning,
} from "@phosphor-icons/react";

import { getAccounts, getProviderTypes, setPolicy, testAccount } from "../lib/api";
import ProviderCard from "./ProviderCard";
import ConnectModal from "./ConnectModal";

// Display order + the i18n key for each category heading.
const CATEGORY_ORDER = [
  { id: "oauth", key: "pvCatOAuth", note: "pvCatOAuthNote" },
  { id: "free", key: "pvCatFree" },
  { id: "apikey", key: "pvCatApiKey" },
  { id: "local", key: "pvCatLocal", note: "pvCatLocalNote" },
  { id: "custom", key: "pvCatCustom" },
];
const CUSTOM_ID = "openai-compat"; // legacy / unknown account kinds fold into this card

// 0 connections → the agent runs offline; 1 → direct; many → a rotating pool.
function runMode(enabled) {
  if (enabled === 0) return { id: "offline", icon: PlugsConnected, accent: "text-zinc-400" };
  if (enabled === 1) return { id: "direct", icon: Power, accent: "text-emerald-400" };
  return { id: "pool", icon: Stack, accent: "text-emerald-400" };
}

export default function Router({ t }) {
  const [policy, setPolicyState] = useState("tiered");
  const [accounts, setAccounts] = useState([]);
  const [providers, setProviders] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [testAll, setTestAll] = useState(null); // {pending} | {ok, total}

  const refresh = useCallback(async () => {
    try {
      const data = await getAccounts();
      setAccounts(data.accounts || []);
      setPolicyState(data.policy || "tiered");
      setErr("");
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    getProviderTypes().then(setProviders).catch(() => {});
  }, [refresh]);

  // Keep health (cooldowns / quotas) current.
  useEffect(() => {
    const h = setInterval(refresh, 5000);
    return () => clearInterval(h);
  }, [refresh]);

  // Connections grouped by the provider id (Account.kind). Unknown kinds fold into the custom card.
  const byProvider = useMemo(() => {
    const known = new Set(providers.map((p) => p.id));
    const map = {};
    for (const a of accounts) {
      const id = known.has(a.kind) ? a.kind : CUSTOM_ID;
      (map[id] ||= []).push(a);
    }
    return map;
  }, [accounts, providers]);

  const sections = useMemo(() => {
    const known = new Set(CATEGORY_ORDER.map((c) => c.id));
    const ordered = CATEGORY_ORDER.map(({ id, key, note }) => ({
      id,
      label: t[key],
      note: note ? t[note] : "",
      items: providers.filter((p) => p.category === id),
    }));
    // Never hide a provider: anything with a missing/unknown category lands in "Other".
    const leftover = providers.filter((p) => !known.has(p.category));
    if (leftover.length) ordered.push({ id: "other", label: t.pvCatOther, items: leftover });
    return ordered.filter((s) => s.items.length > 0);
  }, [providers, t]);

  const onPolicy = useCallback(
    async (p) => {
      setPolicyState(p);
      try {
        await setPolicy(p);
      } catch {
        refresh();
      }
    },
    [refresh]
  );

  const onTestAll = useCallback(async () => {
    const live = accounts.filter((a) => a.enabled);
    if (!live.length) return;
    setTestAll({ pending: true });
    let ok = 0;
    await Promise.all(
      live.map(async (a) => {
        try {
          const r = await testAccount(a.id);
          if (r.ok) ok += 1;
        } catch {
          /* counted as failure */
        }
      })
    );
    setTestAll({ ok, total: live.length });
    refresh();
  }, [accounts, refresh]);

  const enabledCount = useMemo(() => accounts.filter((a) => a.enabled).length, [accounts]);
  const mode = runMode(enabledCount);
  const modeNote =
    mode.id === "offline"
      ? t.pvModeOfflineNote
      : mode.id === "direct"
        ? t.pvModeDirectNote
        : t.pvModePoolNote(enabledCount);
  const modeLabel =
    mode.id === "offline" ? t.pvModeOffline : mode.id === "direct" ? t.pvModeDirect : t.pvModePool;

  const selectedConns = selected ? byProvider[selected.id] || [] : [];

  return (
    <div className="page-enter mx-auto max-w-[1240px] px-5 sm:px-8 lg:px-12 py-10">
      <header className="pb-7">
        <p className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400/80">
          <Plugs size={15} weight="fill" /> {t.routerKicker}
        </p>
        <h1 className="mt-3 text-[2.1rem] sm:text-[2.8rem] font-bold text-zinc-50 tracking-tight leading-[1.08] max-w-[22ch]">
          {t.pvTitle}
        </h1>
        <p className="mt-5 text-[1.05rem] leading-relaxed text-zinc-400 max-w-[70ch]">{t.pvLead}</p>
        <p className="mt-3 text-[12px] font-mono text-zinc-500">{t.pvUsedBy}</p>
      </header>

      {err && (
        <p className="mb-5 text-[12px] text-red-400/90 border border-red-500/20 bg-red-500/[0.05] px-3 py-2">
          {err}
        </p>
      )}

      {/* ── Run-mode banner: mirrors the agent console's Offline/Router state ── */}
      <div className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2 border border-white/[0.08] bg-zinc-900/40 px-4 py-3">
        <span className="flex items-center gap-2">
          <mode.icon size={18} weight="fill" className={mode.accent} />
          <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
            {t.pvModeLabel}
          </span>
          <span className={`text-[13px] font-semibold ${mode.accent}`}>{modeLabel}</span>
        </span>
        <span className="text-[12px] text-zinc-400 flex-1 min-w-[16ch]">{modeNote}</span>
        <a
          href="#/ai"
          className="flex items-center gap-1 text-[12px] font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
        >
          {t.pvOpenAgent} <ArrowRight size={13} />
        </a>
      </div>

      {/* ── toolbar: rotation policy · test all ── */}
      <div className="flex flex-wrap items-center gap-3 mb-6 pb-5 border-b border-white/[0.06]">
        <span className="text-[12px] font-mono text-zinc-500">
          {t.pvPoolCount(accounts.length)}
        </span>

        <div className="flex items-center gap-1.5 ml-auto">
          <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-600 mr-1">
            {t.rtPolicy}
          </span>
          {["tiered", "round_robin"].map((p) => (
            <button
              key={p}
              onClick={() => onPolicy(p)}
              title={p === "tiered" ? t.rtPolicyTieredNote : t.rtPolicyRRNote}
              className={`px-2.5 py-1.5 text-[12px] font-medium border transition-colors ${
                policy === p
                  ? "bg-zinc-800 text-emerald-400 border-emerald-500/30"
                  : "text-zinc-500 border-white/[0.07] hover:text-zinc-200"
              }`}
            >
              {p === "tiered" ? t.rtPolicyTiered : t.rtPolicyRR}
            </button>
          ))}
        </div>

        <button
          onClick={onTestAll}
          disabled={!accounts.length || testAll?.pending}
          className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium border border-white/[0.10] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-40"
        >
          <Lightning size={13} weight="fill" />
          {testAll?.pending
            ? t.pvTesting
            : testAll
              ? t.pvTestAllResult(testAll.ok, testAll.total)
              : t.pvTestAll}
        </button>
      </div>

      {loading ? (
        <p className="text-[13px] text-zinc-500">…</p>
      ) : (
        <div className="space-y-8">
          {sections.map((section) => (
            <section key={section.id}>
              <div className="mb-3 flex items-baseline gap-2.5 flex-wrap">
                <h2 className="text-[12px] font-bold uppercase tracking-wider text-zinc-300">
                  {section.label}
                </h2>
                {section.note && (
                  <span className="text-[11.5px] text-sky-300/70">{section.note}</span>
                )}
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {section.items.map((p) => (
                  <ProviderCard
                    key={p.id}
                    provider={p}
                    connections={byProvider[p.id] || []}
                    onClick={() => setSelected(p)}
                    t={t}
                  />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}

      <div className="mt-8 border border-white/[0.06] bg-zinc-900/20 p-4 flex items-start gap-2.5">
        <Warning size={15} className="text-emerald-400/80 mt-0.5 shrink-0" />
        <p className="text-[12px] leading-relaxed text-zinc-500 max-w-[72ch]">{t.rtHow}</p>
      </div>

      {selected && (
        <ConnectModal
          provider={selected}
          connections={selectedConns}
          t={t}
          onClose={() => setSelected(null)}
          onChanged={refresh}
        />
      )}
    </div>
  );
}
