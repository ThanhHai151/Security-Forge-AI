import { useCallback, useState } from "react";
import {
  ArrowsDownUp,
  DownloadSimple,
  UploadSimple,
  CircleNotch,
  CheckCircle,
  FileArrowUp,
} from "@phosphor-icons/react";

import { exportAccounts, importAccounts } from "../lib/api";
import SettingsModal from "./SettingsModal";

export default function ImportExportModal({ t, onClose }) {
  const [busy, setBusy] = useState(false);

  const [rows, setRows] = useState(null); // parsed accounts array, ready to import
  const [fileName, setFileName] = useState("");
  const [mode, setMode] = useState("merge");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const onExport = useCallback(async () => {
    setBusy(true);
    try {
      const data = await exportAccounts();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const stamp = new Date().toISOString().slice(0, 10);
      const link = document.createElement("a");
      link.href = url;
      link.download = `secforge-accounts-${stamp}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  }, []);

  const onFile = useCallback(
    async (e) => {
      const f = e.target.files?.[0];
      setRows(null);
      setFileName("");
      setResult(null);
      setError("");
      if (!f) return;
      try {
        const parsed = JSON.parse(await f.text());
        const accounts = Array.isArray(parsed) ? parsed : parsed.accounts;
        if (!Array.isArray(accounts)) throw new Error("no accounts array");
        setRows(accounts);
        setFileName(f.name);
      } catch {
        setError(t.ioParseError);
      } finally {
        e.target.value = ""; // allow re-selecting the same file
      }
    },
    [t]
  );

  const onImport = useCallback(async () => {
    if (!rows) return;
    setBusy(true);
    setResult(null);
    setError("");
    try {
      setResult(await importAccounts(rows, mode));
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }, [rows, mode]);

  return (
    <SettingsModal
      title={t.ioTitle}
      subtitle={t.ioSubtitle}
      icon={<ArrowsDownUp size={18} weight="fill" className="text-emerald-400 shrink-0" />}
      onClose={onClose}
      maxW="560px"
    >
      {/* ── Export ── */}
      <section className="space-y-2.5">
        <p className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
          <DownloadSimple size={14} weight="bold" className="text-emerald-400" /> {t.ioExport}
        </p>
        <p className="text-[11.5px] text-zinc-500">{t.ioExportNote}</p>
        <button
          onClick={onExport}
          disabled={busy}
          className="flex items-center gap-1.5 px-4 py-2 text-[13px] font-semibold bg-emerald-500 text-zinc-950 hover:bg-emerald-400 transition-colors disabled:opacity-50"
        >
          {busy ? <CircleNotch size={14} className="animate-spin" /> : <DownloadSimple size={14} weight="bold" />}
          {t.ioDownload}
        </button>
      </section>

      <div className="h-px bg-white/[0.08]" />

      {/* ── Import ── */}
      <section className="space-y-2.5">
        <p className="flex items-center gap-1.5 text-[12px] font-semibold text-zinc-200">
          <UploadSimple size={14} weight="bold" className="text-emerald-400" /> {t.ioImport}
        </p>
        <p className="text-[11.5px] text-zinc-500">{t.ioImportNote}</p>

        <label className="flex items-center gap-2 px-3 py-2 border border-dashed border-white/[0.15] text-[13px] text-zinc-400 hover:border-emerald-500/40 hover:text-zinc-200 transition-colors cursor-pointer">
          <FileArrowUp size={16} />
          <span className="truncate">{fileName || t.ioChooseFile}</span>
          <input type="file" accept=".json,application/json" onChange={onFile} className="hidden" />
        </label>

        <div className="flex flex-col gap-1.5">
          {[
            { id: "merge", label: t.ioModeMerge },
            { id: "replace", label: t.ioModeReplace },
          ].map((m) => (
            <label key={m.id} className="flex items-center gap-2 text-[12px] text-zinc-300 cursor-pointer">
              <input
                type="radio"
                name="import-mode"
                checked={mode === m.id}
                onChange={() => setMode(m.id)}
                className="accent-emerald-500"
              />
              <span>{m.label}</span>
            </label>
          ))}
        </div>

        <button
          onClick={onImport}
          disabled={busy || !rows}
          className="flex items-center gap-1.5 px-4 py-2 text-[13px] font-semibold border border-white/[0.10] text-zinc-200 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors disabled:opacity-40"
        >
          {busy ? <CircleNotch size={14} className="animate-spin" /> : <UploadSimple size={14} weight="bold" />}
          {t.ioRun}
        </button>

        {result && (
          <p className="flex items-center gap-1.5 text-[12px] text-emerald-400">
            <CheckCircle size={13} weight="fill" /> {t.ioResult(result.added, result.skipped)}
          </p>
        )}
        {error && <p className="text-[12px] text-red-400/90">{error}</p>}
      </section>
    </SettingsModal>
  );
}
