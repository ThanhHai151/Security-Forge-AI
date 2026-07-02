import { useEffect, useState, useCallback } from "react";
import {
  X,
  Plus,
  Trash,
  Power,
  ArrowsClockwise,
  CircleNotch,
  CheckCircle,
  XCircle,
  Warning,
  Lightning,
} from "@phosphor-icons/react";

import {
  addAccount,
  updateAccount,
  deleteAccount,
  probeModels,
  testConnection,
  testAccount,
} from "../lib/api";
import OAuthConnect from "./OAuthConnect";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2 text-[13px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";
const TIERS = ["subscription", "standard", "free"];

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-zinc-500 mb-1">
        {label}
        {hint && <span className="text-zinc-600 normal-case tracking-normal">· {hint}</span>}
      </span>
      {children}
    </label>
  );
}

// A non-2xx doesn't always mean a bad key. These reasons prove the credential was accepted
// (rate-limited, wrong model, provider hiccup) — show them amber ("valid, but…"), not red.
const SOFT_FAIL = { rate_limited: "pvTestLimited", reachable: "pvTestReachable", server: "pvTestServer" };

function TestPill({ result, t }) {
  if (!result) return null;
  if (result.pending)
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-zinc-400">
        <CircleNotch size={12} className="animate-spin" /> {t.pvTesting}
      </span>
    );
  if (result.ok)
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
        <CheckCircle size={12} weight="fill" /> {t.pvTestOk}
        {result.status ? ` (${result.status})` : ""}
      </span>
    );
  const softKey = SOFT_FAIL[result.reason];
  return (
    <span
      className={`inline-flex items-center gap-1 text-[11px] max-w-[32ch] truncate ${
        softKey ? "text-amber-400" : "text-red-400"
      }`}
      title={result.error || `HTTP ${result.status}`}
    >
      {softKey ? <Warning size={12} weight="fill" /> : <XCircle size={12} weight="fill" />}{" "}
      {softKey ? t[softKey] : t.pvTestFail}
      {result.status ? ` (${result.status})` : ""}
    </span>
  );
}

function ConnectionRow({ a, t, onChanged }) {
  const [test, setTest] = useState(null);
  const h = a.health;

  const onTest = useCallback(async () => {
    setTest({ pending: true });
    try {
      setTest(await testAccount(a.id));
    } catch (e) {
      setTest({ ok: false, status: 0, error: String(e.message || e) });
    }
  }, [a.id]);

  return (
    <div className="border border-white/[0.07] bg-zinc-900/40 p-2.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] font-semibold text-zinc-100 truncate">{a.label}</span>
            <span className="text-[10px] font-mono uppercase tracking-wider px-1 py-0.5 border border-white/[0.08] text-zinc-400">
              {a.tier}
            </span>
            {a.key_set && (
              <span className="text-[10px] font-mono text-emerald-400/70">••••{a.key_hint}</span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] font-mono text-zinc-500 truncate">
            {a.model || t.pvNoModel}
          </p>
          <div className="mt-1 flex items-center gap-3">
            {h?.calls ? (
              <span className="text-[11px] font-mono text-zinc-500">
                {h.ok}/{h.calls} ok
                {h.cooling && <span className="text-amber-400/90"> · {t.rtCooling}</span>}
              </span>
            ) : (
              <span className="text-[11px] text-zinc-600">{t.rtUnused}</span>
            )}
            <TestPill result={test} t={t} />
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            onClick={onTest}
            title={t.pvTest}
            className="flex items-center justify-center w-7 h-7 border border-white/[0.08] text-zinc-500 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors"
          >
            <Lightning size={12} weight="fill" />
          </button>
          <button
            onClick={async () => {
              await updateAccount(a.id, { enabled: !a.enabled });
              onChanged();
            }}
            title={a.enabled ? t.rtDisable : t.rtEnable}
            className={`flex items-center justify-center w-7 h-7 border transition-colors ${
              a.enabled
                ? "border-emerald-500/40 text-emerald-400"
                : "border-white/[0.08] text-zinc-600 hover:text-zinc-300"
            }`}
          >
            <Power size={12} weight="fill" />
          </button>
          <button
            onClick={async () => {
              await deleteAccount(a.id);
              onChanged();
            }}
            title={t.rtDelete}
            className="flex items-center justify-center w-7 h-7 border border-white/[0.08] text-zinc-600 hover:text-red-400 hover:border-red-500/40 transition-colors"
          >
            <Trash size={12} />
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Connect / manage one provider. Prefilled from the catalog preset so connecting a known
 * provider is: paste key → (optionally) Test → Connect.
 *
 * @param {{
 *   provider: { id: string, label: string, base_url: string, default_model: string,
 *               tier: string, auth: string, category: string, note?: string },
 *   connections: Array<object>,
 *   t: Record<string, any>,
 *   onClose: () => void,
 *   onChanged: () => void,
 * }} props
 */
export default function ConnectModal({ provider, connections, t, onClose, onChanged }) {
  const isOAuth = provider.auth === "oauth";
  const needsKey = provider.auth === "key";
  // Local proxies expose an editable host/port too, so a user can point at a custom port
  // (e.g. an Antigravity-Manager proxy on a non-default port) — that's the "manage proxy" knob.
  const editableUrl =
    provider.category === "custom" || provider.category === "local" || !provider.base_url;
  // Localized one-liner under the title (the catalog's English `note` is for developers only).
  const hint = isOAuth
    ? t.oauthHint
    : provider.category === "custom"
      ? t.pvHintCompat
      : provider.auth === "none"
        ? t.pvLocalNote
        : t.pvHintApiKey;

  const [label, setLabel] = useState("");
  const [baseUrl, setBaseUrl] = useState(provider.base_url || "");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(provider.default_model || "");
  const [tier, setTier] = useState(provider.tier || "standard");
  const [formModels, setFormModels] = useState([]);
  const [probing, setProbing] = useState(false);
  const [adding, setAdding] = useState(false);
  const [test, setTest] = useState(null);
  const [err, setErr] = useState("");

  // Reset the form whenever the user opens a different provider.
  useEffect(() => {
    setLabel("");
    setBaseUrl(provider.base_url || "");
    setApiKey("");
    setModel(provider.default_model || "");
    setTier(provider.tier || "standard");
    setFormModels([]);
    setTest(null);
    setErr("");
  }, [provider]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const onProbe = useCallback(async () => {
    if (!baseUrl) return;
    setProbing(true);
    try {
      const r = await probeModels({ base_url: baseUrl, api_key: apiKey });
      setFormModels(r.models || []);
      if (r.models?.length && !model) setModel(r.models[0]);
    } catch {
      setFormModels([]);
    } finally {
      setProbing(false);
    }
  }, [baseUrl, apiKey, model]);

  const onTest = useCallback(async () => {
    if (!baseUrl) return;
    setTest({ pending: true });
    try {
      setTest(
        await testConnection({
          base_url: baseUrl,
          api_key: apiKey,
          model,
          api_style: provider.api_style || "openai",
        })
      );
    } catch (e) {
      setTest({ ok: false, status: 0, error: String(e.message || e) });
    }
  }, [baseUrl, apiKey, model]);

  const canAdd = baseUrl.trim() && (!needsKey || apiKey.trim() || connections.length) && !adding;

  const onAdd = useCallback(async () => {
    if (!baseUrl.trim()) return;
    setAdding(true);
    setErr("");
    try {
      await addAccount({
        label: label.trim() || provider.label,
        kind: provider.id,
        base_url: baseUrl.trim(),
        api_key: apiKey,
        model: model.trim(),
        tier,
        api_style: provider.api_style || "openai",
      });
      setLabel("");
      setApiKey("");
      setTest(null);
      onChanged();
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setAdding(false);
    }
  }, [label, baseUrl, apiKey, model, tier, provider, onChanged]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 sm:p-8 overflow-y-auto">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="drawer-enter relative w-full max-w-[560px] my-auto bg-zinc-950 border border-white/[0.12] shadow-2xl">
        {/* header */}
        <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.08]">
          <div className="min-w-0">
            <h2 className="text-[15px] font-bold text-zinc-100 truncate">{provider.label}</h2>
            <p className="mt-0.5 text-[11.5px] text-zinc-500 truncate">{hint}</p>
          </div>
          <button
            onClick={onClose}
            aria-label={t.pvClose}
            className="shrink-0 text-zinc-500 hover:text-zinc-100 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4 max-h-[calc(100dvh-160px)] overflow-y-auto">
          {/* existing connections */}
          {connections.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                {t.pvExisting} · {connections.length}
              </p>
              {connections.map((a) => (
                <ConnectionRow key={a.id} a={a} t={t} onChanged={onChanged} />
              ))}
            </div>
          )}

          {/* OAuth providers get a sign-in flow instead of the key form. */}
          {isOAuth ? (
            <div className="space-y-3">
              <p className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
                <Plus size={13} className="text-emerald-400" /> {t.oauthAddConn}
              </p>
              <OAuthConnect provider={provider} t={t} onConnected={onChanged} />
            </div>
          ) : (
          /* add-connection form */
          <div className="space-y-3">
            <p className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
              <Plus size={13} className="text-emerald-400" /> {t.pvAddConn}
            </p>

            <Field label={t.rtLabel} hint={t.pvOptional}>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className={inputCls}
                placeholder={provider.label}
              />
            </Field>

            {editableUrl && (
              <Field label={t.rtBaseUrl}>
                <input
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  className={inputCls}
                  placeholder="https://api.../v1"
                />
              </Field>
            )}

            {(needsKey || provider.category === "custom") && (
              <Field label={t.rtApiKey} hint={needsKey ? undefined : t.pvOptional}>
                <input
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  type="password"
                  className={inputCls}
                  placeholder="sk-…"
                />
              </Field>
            )}

            {provider.auth === "none" && (
              <p className="text-[11.5px] text-zinc-500 border-l-2 border-emerald-500/30 pl-2.5">
                {t.pvLocalNote}
              </p>
            )}

            <Field label={t.rtModel}>
              <div className="flex gap-2">
                {formModels.length > 0 ? (
                  <select
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    className={inputCls}
                  >
                    {formModels.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    className={inputCls}
                    placeholder="model id"
                    list="model-suggestions"
                  />
                )}
                {formModels.length === 0 && (provider.models?.length ?? 0) > 0 && (
                  <datalist id="model-suggestions">
                    {provider.models.map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                )}
                <button
                  onClick={onProbe}
                  disabled={!baseUrl || probing}
                  title={t.rtFetchModels}
                  className="shrink-0 px-2.5 border border-white/[0.08] text-zinc-400 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-40"
                >
                  {probing ? (
                    <CircleNotch size={14} className="animate-spin" />
                  ) : (
                    <ArrowsClockwise size={14} />
                  )}
                </button>
              </div>
              {formModels.length === 0 && (provider.models?.length ?? 0) > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <span className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-600 self-center">
                    {t.pvModelSuggest}
                  </span>
                  {provider.models.map((m) => (
                    <button
                      key={m}
                      type="button"
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
            </Field>

            <Field label={t.rtTier}>
              <select value={tier} onChange={(e) => setTier(e.target.value)} className={inputCls}>
                {TIERS.map((x) => (
                  <option key={x} value={x}>
                    {t[`rtTier_${x}`] || x}
                  </option>
                ))}
              </select>
            </Field>

            {err && <p className="text-[12px] text-red-400/90">{err}</p>}

            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={onTest}
                disabled={!baseUrl || test?.pending}
                className="flex items-center gap-1.5 px-3 py-2 text-[13px] font-medium border border-white/[0.10] text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-40"
              >
                <Lightning size={13} weight="fill" /> {t.pvTest}
              </button>
              <TestPill result={test} t={t} />
              <button
                onClick={onAdd}
                disabled={!canAdd}
                className={`ml-auto flex items-center gap-1.5 px-4 py-2 text-[13px] font-semibold transition-colors ${
                  canAdd
                    ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                    : "bg-zinc-800 text-zinc-500 cursor-not-allowed"
                }`}
              >
                {adding ? (
                  <CircleNotch size={14} className="animate-spin" />
                ) : (
                  <Plus size={14} weight="bold" />
                )}
                {t.pvConnectBtn}
              </button>
            </div>
          </div>
          )}
        </div>
      </div>
    </div>
  );
}
