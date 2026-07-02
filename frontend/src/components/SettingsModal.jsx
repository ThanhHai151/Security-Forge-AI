import { useEffect } from "react";
import { X } from "@phosphor-icons/react";

/**
 * Shared popup shell for the header settings tools (Quota / Models / Import-Export). Same visual
 * language as ConnectModal but sits above it (z-60) and takes a title/icon so each tool stays lean.
 *
 * @param {{
 *   title: string, subtitle?: string, icon?: React.ReactNode,
 *   onClose: () => void, children: React.ReactNode, maxW?: string,
 * }} props
 */
export default function SettingsModal({ title, subtitle, icon, onClose, children, maxW = "640px" }) {
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center p-4 sm:p-8 overflow-y-auto">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        className="drawer-enter relative w-full my-auto bg-zinc-950 border border-white/[0.12] shadow-2xl"
        style={{ maxWidth: maxW }}
      >
        <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.08]">
          <div className="flex items-center gap-2.5 min-w-0">
            {icon}
            <div className="min-w-0">
              <h2 className="text-[15px] font-bold text-zinc-100 truncate">{title}</h2>
              {subtitle && <p className="mt-0.5 text-[11.5px] text-zinc-500 truncate">{subtitle}</p>}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 text-zinc-500 hover:text-zinc-100 transition-colors"
          >
            <X size={20} />
          </button>
        </div>
        <div className="px-5 py-4 space-y-4 max-h-[calc(100dvh-160px)] overflow-y-auto">
          {children}
        </div>
      </div>
    </div>
  );
}
