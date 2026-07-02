import { useEffect, useRef, useState } from "react";
import { Gear, Gauge, Stack, ArrowsDownUp } from "@phosphor-icons/react";

import QuotaModal from "./QuotaModal";
import ModelsModal from "./ModelsModal";
import ImportExportModal from "./ImportExportModal";

/**
 * Header gear button. Opens a small dropdown with the three account tools that don't belong in the
 * primary nav — Quota tracker, Models, Import/Export — each of which opens its own popup.
 *
 * @param {{ t: Record<string, any> }} props
 */
export default function SettingsMenu({ t }) {
  const [open, setOpen] = useState(false);
  const [panel, setPanel] = useState(null); // null | "quota" | "models" | "io"
  const ref = useRef(null);

  // Close the dropdown on outside-click or Escape (the popups handle their own Escape).
  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const items = [
    { id: "quota", label: t.setQuota, Icon: Gauge },
    { id: "models", label: t.setModels, Icon: Stack },
    { id: "io", label: t.setIO, Icon: ArrowsDownUp },
  ];

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={t.setMenu}
        title={t.setMenu}
        aria-haspopup="menu"
        aria-expanded={open}
        className={`flex items-center justify-center w-8 h-8 bg-zinc-900/70 border transition-colors shrink-0 ${
          open
            ? "border-emerald-400/40 text-emerald-400"
            : "border-white/[0.06] text-zinc-400 hover:text-emerald-400 hover:border-emerald-400/40"
        }`}
      >
        <Gear size={15} weight="fill" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 mt-1.5 w-56 bg-zinc-950 border border-white/[0.12] shadow-2xl py-1 z-50"
        >
          {items.map(({ id, label, Icon }) => (
            <button
              key={id}
              role="menuitem"
              onClick={() => {
                setPanel(id);
                setOpen(false);
              }}
              className="flex items-center gap-2.5 w-full px-3 py-2 text-[13px] text-zinc-300 hover:bg-white/[0.04] hover:text-emerald-400 transition-colors text-left"
            >
              <Icon size={15} weight="fill" className="text-zinc-500" /> {label}
            </button>
          ))}
        </div>
      )}

      {panel === "quota" && <QuotaModal t={t} onClose={() => setPanel(null)} />}
      {panel === "models" && <ModelsModal t={t} onClose={() => setPanel(null)} />}
      {panel === "io" && <ImportExportModal t={t} onClose={() => setPanel(null)} />}
    </div>
  );
}
