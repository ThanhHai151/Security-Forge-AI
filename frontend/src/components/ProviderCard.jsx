import { CheckCircle, HardDrives, Warning } from "@phosphor-icons/react";

/**
 * One provider in the catalog grid. Clicking it opens the connect/manage modal.
 *
 * @param {{
 *   provider: { id: string, label: string, private?: boolean },
 *   connections: Array<{ enabled: boolean, health?: { cooling?: boolean, last_error?: string } }>,
 *   onClick: () => void,
 *   t: Record<string, any>,
 * }} props
 */
export default function ProviderCard({ provider, connections, onClick, t }) {
  const total = connections.length;
  const live = connections.filter((c) => c.enabled).length;
  const cooling = connections.some((c) => c.health?.cooling);
  const errored = connections.some((c) => c.health?.last_error && !c.health?.cooling);
  const connected = total > 0;

  // First glyph(s) of the brand name — a lightweight, asset-free logo stand-in.
  const initials = provider.label.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";

  return (
    <button
      onClick={onClick}
      className={`group relative flex items-center gap-3 p-3 text-left border transition-colors ${
        connected
          ? "border-emerald-500/30 bg-emerald-500/[0.04] hover:border-emerald-400/50"
          : "border-white/[0.07] bg-zinc-900/30 hover:border-white/20 hover:bg-zinc-900/60"
      }`}
    >
      <span
        className={`flex items-center justify-center w-9 h-9 shrink-0 text-[12px] font-bold tracking-tight ${
          connected
            ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
            : "bg-zinc-800/80 text-zinc-400 border border-white/[0.06]"
        }`}
      >
        {initials}
      </span>

      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-zinc-100 truncate">
            {provider.label}
          </span>
          {provider.private && (
            <span
              title={t.pvCatLocalNote}
              className="inline-flex items-center gap-0.5 shrink-0 text-[9.5px] font-mono uppercase tracking-wider text-sky-300/80 border border-sky-400/25 px-1 py-px"
            >
              <HardDrives size={9} weight="fill" /> {t.pvLocalBadge}
            </span>
          )}
          {provider.risk && (
            <Warning
              size={12}
              weight="fill"
              title={t.oauthRisk}
              className="shrink-0 text-amber-400/80"
            />
          )}
        </span>
        <span className="mt-0.5 flex items-center gap-1.5 text-[11px] font-mono">
          {connected ? (
            <>
              <span
                className={`inline-block w-1.5 h-1.5 rounded-full ${
                  errored ? "bg-red-400" : cooling ? "bg-amber-400" : "bg-emerald-400"
                }`}
                style={
                  !errored && !cooling
                    ? { boxShadow: "0 0 6px rgba(64,212,168,0.9)" }
                    : undefined
                }
              />
              <span className="text-emerald-400/90">{t.pvConnected(live)}</span>
            </>
          ) : (
            <span className="text-zinc-600">{t.pvNoConn}</span>
          )}
        </span>
      </span>

      {connected && (
        <CheckCircle
          size={15}
          weight="fill"
          className="shrink-0 text-emerald-400/80"
        />
      )}
    </button>
  );
}
