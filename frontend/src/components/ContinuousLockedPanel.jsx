import { LockSimple } from "@phosphor-icons/react";

// Continuous (the old autopilot campaign engine) is intentionally locked, not deleted — it's
// being redesigned around the Expert Supervisor and isn't worth rebuilding twice. See
// backend/service.py's AutonomousDisabledError for the matching backend-side gate.
export default function ContinuousLockedPanel({ t }) {
  return (
    <div className="flex-1 min-h-0 flex flex-col items-center justify-center text-center gap-3 border border-white/[0.07] bg-zinc-900/20 px-6 py-10">
      <span className="flex items-center justify-center w-12 h-12 rounded-full bg-zinc-800/80 border border-white/[0.08] text-zinc-500">
        <LockSimple size={20} weight="fill" />
      </span>
      <p className="text-[13px] font-semibold text-zinc-300">{t.agentModeLocked}</p>
      <p className="max-w-[420px] text-[12.5px] leading-relaxed text-zinc-500">{t.termLockedNote}</p>
    </div>
  );
}
