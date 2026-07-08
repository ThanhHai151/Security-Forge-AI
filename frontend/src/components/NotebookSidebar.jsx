import { useEffect, useRef, useState } from "react";
import { BookOpen, CaretDown, CaretRight, DotsThreeVertical, MapTrifold, Plus, Trash } from "@phosphor-icons/react";

import { useSingleOrDoubleClick } from "../lib/useSingleOrDoubleClick";
import SettingsModal from "./SettingsModal";

// Per-row "..." menu: view this domain's mind map, or delete it. Same click-outside pattern as
// the header's SettingsMenu.
function RowMenu({ onViewMap, onDelete, t }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  return (
    <div className="relative shrink-0" ref={ref}>
      <button
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        aria-label={t.notebookRowMenu}
        title={t.notebookRowMenu}
        aria-haspopup="menu"
        aria-expanded={open}
        className={`w-7 h-7 flex items-center justify-center transition-colors ${
          open ? "text-emerald-400" : "text-zinc-300 hover:text-zinc-100"
        }`}
      >
        <DotsThreeVertical size={14} weight="bold" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute left-0 top-full mt-1 w-40 bg-zinc-950 border border-white/[0.12] shadow-2xl py-1 z-20"
        >
          <button
            role="menuitem"
            onClick={(e) => {
              e.stopPropagation();
              setOpen(false);
              onViewMap();
            }}
            className="flex items-center gap-2 w-full px-2.5 py-1.5 text-[12px] text-zinc-100 hover:bg-white/[0.04] hover:text-emerald-400 transition-colors text-left"
          >
            <MapTrifold size={13} /> {t.notebookViewMap}
          </button>
          <button
            role="menuitem"
            onClick={(e) => {
              e.stopPropagation();
              setOpen(false);
              onDelete();
            }}
            className="flex items-center gap-2 w-full px-2.5 py-1.5 text-[12px] text-zinc-100 hover:bg-red-500/10 hover:text-red-400 transition-colors text-left"
          >
            <Trash size={13} /> {t.notebookDelete}
          </button>
        </div>
      )}
    </div>
  );
}

// Confirmation for a destructive, irreversible action — reuses the same modal shell as the
// header's Quota/Models/Import-Export popups.
function DeleteConfirm({ domain, onConfirm, onClose, t }) {
  const [deleting, setDeleting] = useState(false);
  return (
    <SettingsModal title={t.notebookDeleteConfirmTitle} onClose={onClose} maxW="420px">
      <p className="text-[13px] text-zinc-100 leading-relaxed">{t.notebookDeleteConfirmBody(domain)}</p>
      <div className="flex justify-end gap-2 pt-1">
        <button
          onClick={onClose}
          className="px-3 py-1.5 text-[12.5px] font-medium border border-white/[0.08] text-zinc-300 hover:text-zinc-100 transition-colors"
        >
          {t.chainClose}
        </button>
        <button
          onClick={async () => {
            setDeleting(true);
            await onConfirm();
          }}
          disabled={deleting}
          className="px-3 py-1.5 text-[12.5px] font-medium bg-red-500/15 border border-red-500/30 text-red-400 hover:bg-red-500/25 transition-colors disabled:opacity-60"
        >
          {deleting ? t.notebookDeleting : t.notebookDelete}
        </button>
      </div>
    </SettingsModal>
  );
}

// One row in the root -> subdomain history tree. Recurses into its own `children` so a
// discovered subdomain can itself carry further discovered subdomains, each with its own
// independent notebook (see ai_framework/notebook — a fresh domain always starts untested,
// nothing is ever copied from a sibling or parent). Single-click just selects the domain (the
// vuln catalog to its right updates); double-click jumps straight into that domain's mind map.
// Indentation and the tree guide line both come from nesting each level's children inside a
// bordered wrapper (see the recursive render below) rather than depth * px math on this row.
function DomainRow({ node, depth, activeDomain, onSelectDomain, onOpenDomainMap, onRequestDelete, onAddChild, t }) {
  const [expanded, setExpanded] = useState(depth === 0);
  const [adding, setAdding] = useState(false);
  const [childInput, setChildInput] = useState("");
  const hasChildren = (node.children || []).length > 0;

  const { onClick, onDoubleClick } = useSingleOrDoubleClick(
    () => onSelectDomain(node.domain),
    () => onOpenDomainMap(node.domain)
  );

  const submitChild = () => {
    const value = childInput.trim();
    if (!value) return;
    onAddChild(node.domain, value);
    setChildInput("");
    setAdding(false);
    setExpanded(true);
  };

  return (
    <div>
      <div className="relative flex items-center gap-1">
        {depth > 0 && (
          <span aria-hidden="true" className="absolute -left-3 top-1/2 w-3 h-px bg-white/[0.08]" />
        )}
        <RowMenu
          onViewMap={() => onOpenDomainMap(node.domain)}
          onDelete={() => onRequestDelete(node.domain)}
          t={t}
        />
        {hasChildren ? (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="shrink-0 w-6 h-6 flex items-center justify-center text-zinc-300 hover:text-zinc-100"
            aria-label={expanded ? "Collapse" : "Expand"}
            aria-expanded={expanded}
          >
            {expanded ? <CaretDown size={11} /> : <CaretRight size={11} />}
          </button>
        ) : (
          <span className="w-6 shrink-0" />
        )}
        <button
          onClick={onClick}
          onDoubleClick={onDoubleClick}
          title={t.notebookOpenMapHint}
          className={`flex-1 min-w-0 text-left px-2 py-1.5 border text-[12px] font-medium transition-colors truncate ${
            node.domain === activeDomain
              ? "border-emerald-500/30 bg-emerald-500/[0.07] text-emerald-300"
              : "border-transparent hover:border-white/[0.07] hover:bg-white/[0.02] text-zinc-100"
          }`}
        >
          {node.domain}
          <span className="ml-1.5 text-[11px] font-mono text-zinc-300">
            {node.confirmed}/{node.total}
          </span>
        </button>
        <button
          onClick={() => setAdding((v) => !v)}
          aria-label={t.notebookAddChild}
          title={t.notebookAddChild}
          className="shrink-0 w-7 h-7 flex items-center justify-center text-zinc-300 hover:text-emerald-400"
        >
          <Plus size={13} weight="bold" />
        </button>
      </div>

      {adding && (
        <div className="flex gap-1 mt-1 mb-1 ml-7">
          <label className="flex-1 min-w-0">
            <span className="sr-only">{t.notebookAddChild}</span>
            <input
              value={childInput}
              onChange={(e) => setChildInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submitChild()}
              placeholder={t.notebookChildPlaceholder}
              autoFocus
              className="w-full bg-zinc-900/60 border border-white/[0.08] px-2 py-1.5 text-[12px]
                         text-zinc-100 placeholder:text-zinc-400 focus:border-emerald-500/50 outline-none"
            />
          </label>
          <button
            onClick={submitChild}
            aria-label={t.notebookAddChild}
            className="shrink-0 w-8 flex items-center justify-center text-[11px] font-medium bg-emerald-500/15 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/25"
          >
            <Plus size={12} weight="bold" />
          </button>
        </div>
      )}

      {expanded && hasChildren && (
        <div className="ml-2 pl-3 mt-0.5 space-y-0.5 border-l border-white/[0.08]">
          {node.children.map((child) => (
            <DomainRow
              key={child.domain}
              node={child}
              depth={depth + 1}
              activeDomain={activeDomain}
              onSelectDomain={onSelectDomain}
              onOpenDomainMap={onOpenDomainMap}
              onRequestDelete={onRequestDelete}
              onAddChild={onAddChild}
              t={t}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// The Hermes notebook's target list: every red-team domain tracked so far, root domains with
// their discovered subdomains nested underneath. Selecting a row drives what
// VulnCatalogPanel/SupervisorPanel show next to it — this component only ever picks *which*
// domain is active, it doesn't render that domain's vuln tree itself anymore.
export default function NotebookSidebar({
  roots,
  activeDomain,
  onSelectDomain,
  onOpenDomainMap,
  onDeleteDomain,
  onAddRoot,
  onAddChild,
  t,
}) {
  const [input, setInput] = useState("");
  const [pendingDelete, setPendingDelete] = useState(null); // domain string | null

  const submit = () => {
    const value = input.trim();
    if (!value) return;
    onAddRoot(value);
    setInput("");
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="mb-3 shrink-0">
        <label htmlFor="notebook-domain-input" className="block text-[11px] font-mono uppercase tracking-wider text-zinc-300 mb-1">
          {t.supDomain}
        </label>
        <div className="flex gap-1.5">
          <input
            id="notebook-domain-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder={t.supDomainPlaceholder}
            className="flex-1 min-w-0 bg-zinc-900/60 border border-white/[0.08] px-2.5 py-2 text-[12.5px]
                       text-zinc-100 placeholder:text-zinc-400 focus:border-emerald-500/50 outline-none
                       transition-colors"
          />
          <button
            onClick={submit}
            aria-label={t.notebookNewDomain}
            title={t.notebookNewDomain}
            className="shrink-0 flex items-center justify-center w-9 h-9 bg-emerald-500/15
                       border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/25 transition-colors"
          >
            <Plus size={14} weight="bold" />
          </button>
        </div>
      </div>

      <h2 className="px-0.5 pb-2 text-[11px] font-mono uppercase tracking-wider text-zinc-300 shrink-0 flex items-center gap-1.5">
        <BookOpen size={12} /> {t.notebookHeading}
      </h2>

      <div className="flex-1 min-h-0 overflow-y-auto space-y-0.5 pr-0.5">
        {roots.length === 0 ? (
          <p className="text-[12px] text-zinc-300 px-0.5">{t.notebookNoDomains}</p>
        ) : (
          roots.map((root) => (
            <DomainRow
              key={root.domain}
              node={root}
              depth={0}
              activeDomain={activeDomain}
              onSelectDomain={onSelectDomain}
              onOpenDomainMap={onOpenDomainMap}
              onRequestDelete={setPendingDelete}
              onAddChild={onAddChild}
              t={t}
            />
          ))
        )}
      </div>

      {pendingDelete && (
        <DeleteConfirm
          domain={pendingDelete}
          onClose={() => setPendingDelete(null)}
          onConfirm={async () => {
            await onDeleteDomain(pendingDelete);
            setPendingDelete(null);
          }}
          t={t}
        />
      )}
    </div>
  );
}
