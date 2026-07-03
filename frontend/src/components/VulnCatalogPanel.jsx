import { useMemo, useState } from "react";
import { CaretDown, CaretRight, ListChecks } from "@phosphor-icons/react";

import { buildStatusIndex, chainChildrenOf } from "../lib/notebookGraph";
import { useSingleOrDoubleClick } from "../lib/useSingleOrDoubleClick";

const STATUS_OPTIONS = ["untested", "unconfirmed", "confirmed"];
const FILTER_OPTIONS = ["all", "confirmed", "unconfirmed", "untested"];

const STATUS_CLS = {
  confirmed: "text-red-300 border-red-500/30 bg-red-500/[0.07]",
  unconfirmed: "text-amber-300 border-amber-500/30 bg-amber-500/[0.07]",
  untested: "text-zinc-500 border-white/[0.08] bg-transparent",
};

function statusLabel(status, t) {
  if (status === "confirmed") return t.termConfirmed;
  if (status === "unconfirmed") return t.termUnconfirmed;
  return t.termUntested;
}

function filterLabel(value, t) {
  return value === "all" ? t.vulnFilterAll : statusLabel(value, t);
}

// `capitalize` (CSS text-transform) renders these as "Confirmed"/"Untested"/etc. without
// touching the underlying t.termConfirmed strings, which are also used lowercase elsewhere.
function StatusSelect({ value, onChange, t }) {
  return (
    <select
      value={value}
      onChange={onChange}
      className={`capitalize shrink-0 text-[10.5px] font-mono border px-1 py-0.5 bg-zinc-950 outline-none ${
        STATUS_CLS[value] || STATUS_CLS.untested
      }`}
    >
      {STATUS_OPTIONS.map((s) => (
        <option key={s} value={s}>
          {statusLabel(s, t)}
        </option>
      ))}
    </select>
  );
}

// One hop of a technique's exploit chain, rendered inline (indented under the technique it
// came from) rather than jumping to the mind map. Single-click expands its own follow-on hops
// in place; double-click still opens the full mind map, focused on this hop's real node.
function ChainRow({ node, depth, filterStatus, onSetStatus, onOpenNode, t }) {
  const [open, setOpen] = useState(false);
  const hasChildren = (node.children || []).length > 0;
  const { onClick, onDoubleClick } = useSingleOrDoubleClick(
    () => setOpen((v) => !v),
    () => onOpenNode(node.realId)
  );

  const effectiveStatus = node.status || "untested";
  if (filterStatus !== "all" && effectiveStatus !== filterStatus) return null;

  return (
    <div style={{ paddingLeft: depth * 12 }}>
      <div
        title={node.justification || node.note || undefined}
        className="flex items-center justify-between gap-1.5 px-2 py-1 mt-1 border border-white/[0.04] bg-white/[0.015]"
      >
        <button
          onClick={onClick}
          onDoubleClick={onDoubleClick}
          title={t.vulnOpenMapHint}
          className="flex-1 min-w-0 flex items-center gap-1 text-[11px] text-zinc-400 truncate text-left hover:text-emerald-300 transition-colors"
        >
          {hasChildren ? (
            open ? (
              <CaretDown size={9} />
            ) : (
              <CaretRight size={9} />
            )
          ) : (
            <span className="w-[9px] shrink-0" />
          )}
          <span className="truncate">{node.label}</span>
        </button>
        {node.status && (
          <StatusSelect
            value={node.status}
            onChange={(e) => onSetStatus(node.realId, e.target.value)}
            t={t}
          />
        )}
      </div>
      {open &&
        node.children.map((child) => (
          <ChainRow
            key={child.id}
            node={child}
            depth={depth + 1}
            filterStatus={filterStatus}
            onSetStatus={onSetStatus}
            onOpenNode={onOpenNode}
            t={t}
          />
        ))}
    </div>
  );
}

// A technique node from the catalog. Single-click toggles an inline dropdown of its
// exploit-chain follow-on errors (see ChainRow); double-click opens the full mind map focused
// on this node. The status select is a separate control and never triggers either.
function TechniqueRow({ node, chains, statusById, filterStatus, onSetStatus, onOpenNode, t }) {
  const [chainOpen, setChainOpen] = useState(false);
  const { onClick, onDoubleClick } = useSingleOrDoubleClick(
    () => setChainOpen((v) => !v),
    () => onOpenNode(node.id)
  );
  const chainChildren = useMemo(
    () => chainChildrenOf(chains, statusById, node.id),
    [chains, statusById, node.id]
  );
  const hasChain = chainChildren.length > 0;

  return (
    <div>
      <div
        title={node.justification || undefined}
        className={`flex items-center justify-between gap-1.5 px-2 py-1 border transition-colors ${
          node.in_progress ? "border-amber-400/80 ring-1 ring-amber-400/60" : "border-white/[0.05]"
        }`}
      >
        <button
          onClick={onClick}
          onDoubleClick={onDoubleClick}
          title={t.vulnOpenMapHint}
          className="flex-1 min-w-0 flex items-center gap-1 text-[11.5px] text-zinc-300 truncate text-left hover:text-emerald-300 transition-colors"
        >
          {hasChain && (chainOpen ? <CaretDown size={9} /> : <CaretRight size={9} />)}
          <span className="truncate">{node.label}</span>
        </button>
        <StatusSelect value={node.status} onChange={(e) => onSetStatus(node.id, e.target.value)} t={t} />
      </div>
      {chainOpen &&
        chainChildren.map((child) => (
          <ChainRow
            key={child.id}
            node={child}
            depth={1}
            filterStatus={filterStatus}
            onSetStatus={onSetStatus}
            onOpenNode={onOpenNode}
            t={t}
          />
        ))}
    </div>
  );
}

// The vulnerability catalog for whichever domain is selected in NotebookSidebar: the taxonomy
// category -> technique tree, each leaf's confirmed/unconfirmed/untested status, an amber ring
// on whichever node is `in_progress` (see ai_framework.notebook), a status filter toolbar, and
// a click-through into the mind-map for exploit-chain detail. Split out of NotebookSidebar
// into its own column so the domain list and this catalog each get real room instead of being
// stacked in one narrow strip.
export default function VulnCatalogPanel({ activeDomain, tree, chains, onSetStatus, onOpenNode, t }) {
  const [filterStatus, setFilterStatus] = useState("all");
  const statusById = useMemo(() => buildStatusIndex(tree), [tree]);

  const hasAnyTechniques = (tree || []).some((cat) => (cat.children || []).length > 0);
  const categories = (tree || [])
    .map((cat) => ({
      ...cat,
      children: (cat.children || []).filter((n) => filterStatus === "all" || n.status === filterStatus),
    }))
    .filter((cat) => cat.children.length > 0);

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="pb-2 shrink-0 space-y-1.5">
        <p className="px-0.5 text-[11px] font-mono uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
          <ListChecks size={12} /> {t.supAdviceHeading}
        </p>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="capitalize w-full bg-zinc-900/60 border border-white/[0.08] px-2 py-1.5 text-[11.5px]
                     text-zinc-300 outline-none focus:border-emerald-500/50 transition-colors"
        >
          {FILTER_OPTIONS.map((v) => (
            <option key={v} value={v}>
              {filterLabel(v, t)}
            </option>
          ))}
        </select>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto pr-0.5">
        {!activeDomain ? (
          <p className="text-[12px] text-zinc-600 px-0.5">{t.notebookEmpty}</p>
        ) : categories.length === 0 && hasAnyTechniques ? (
          <p className="text-[12px] text-zinc-600 px-0.5">{t.vulnFilterEmpty}</p>
        ) : (
          categories.map((cat) => (
            <div key={cat.id} className="mb-3">
              <p className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-600 mb-1 px-0.5">
                {cat.label}
              </p>
              <div className="space-y-1">
                {cat.children.map((node) => (
                  <TechniqueRow
                    key={node.id}
                    node={node}
                    chains={chains}
                    statusById={statusById}
                    filterStatus={filterStatus}
                    onSetStatus={onSetStatus}
                    onOpenNode={onOpenNode}
                    t={t}
                  />
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
