import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowsInSimple,
  CaretLeft,
  CaretRight,
  MagnifyingGlassMinus,
  MagnifyingGlassPlus,
  X,
} from "@phosphor-icons/react";

import { buildStatusIndex, chainChildrenOf } from "../lib/notebookGraph";

const PALETTE = ["#8B5CF6", "#14B8A6", "#F59E0B", "#3B82F6", "#F43B72", "#64748B", "#22C55E"];
const STATUS_DOT = { confirmed: "#F87171", unconfirmed: "#FBBF24", untested: "#71717A" };
const NODE_W = 210;
const NODE_H = 34;
const ROW_H = 46;
const COL_W = 250;
const MIN_ZOOM = 0.35;
const MAX_ZOOM = 2.2;
const INITIAL_PAN = { x: 48, y: 48 };
const TWEEN_MS = 280;

function tagChain(nodes) {
  return nodes.map((n) => ({ ...n, kind: "chain", children: tagChain(n.children) }));
}

/** Build the pure node tree (root -> categories -> techniques -> recursive exploit-chain
 * hops) from the same `tree`/`chains` shapes VulnCatalogPanel already renders. */
function buildTree(domain, tree, chains) {
  const statusById = buildStatusIndex(tree);

  const categories = (tree || []).map((cat, i) => ({
    id: cat.id,
    label: cat.label,
    kind: "category",
    color: PALETTE[i % PALETTE.length],
    children: (cat.children || []).map((ch) => ({
      id: ch.id,
      label: ch.label,
      kind: "technique",
      color: PALETTE[i % PALETTE.length],
      status: ch.status,
      inProgress: ch.in_progress,
      justification: ch.justification,
      children: tagChain(chainChildrenOf(chains, statusById, ch.id)),
    })),
  }));

  return { id: "__root__", label: domain, kind: "root", children: categories };
}

function findAncestorPath(node, targetId, path = []) {
  const next = [...path, node.id];
  if (node.id === targetId) return next;
  for (const child of node.children || []) {
    const found = findAncestorPath(child, targetId, next);
    if (found) return found;
  }
  return null;
}

/** Assigns each visible node an (x, y): x by depth, y by a running row counter for leaves
 * (or collapsed subtrees), with a parent centered on the vertical span of its visible
 * children. Only expanded branches contribute rows, so collapsed parts cost nothing. Edges
 * are recorded by node id rather than baked-in coordinates so the animated-position hook can
 * re-derive them from whatever positions are currently on screen (mid-tween or settled). */
function layout(root, expanded) {
  let row = 0;
  const positioned = [];
  const edgesMeta = [];

  const place = (node, depth) => {
    const hasChildren = (node.children || []).length > 0;
    const open = hasChildren && expanded.has(node.id);
    const x = depth * COL_W;
    let y;
    let childEntries = [];
    if (open) {
      childEntries = node.children.map((child) => place(child, depth + 1));
      const childYs = childEntries.map((c) => c.y);
      y = (Math.min(...childYs) + Math.max(...childYs)) / 2;
    } else {
      y = row * ROW_H;
      row += 1;
    }
    const entry = { ...node, x, y, depth, hasChildren, open };
    positioned.push(entry);
    childEntries.forEach((c) => {
      edgesMeta.push({ fromId: node.id, toId: c.id, color: c.color || "#52525B", dashed: c.kind === "chain" });
    });
    return entry;
  };
  place(root, 0);
  return { positioned, edgesMeta };
}

function connectorPath(x1, y1, x2, y2) {
  const midX = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
}

function statusLabel(status, t) {
  if (status === "confirmed") return t.termConfirmed;
  if (status === "unconfirmed") return t.termUnconfirmed;
  return t.termUntested;
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function prefersReducedMotion() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/** Smoothly tweens each node's (x, y) toward its new layout position whenever `positioned`
 * changes (expand/collapse), matched by node id so a persisting node glides instead of
 * snapping. A node with no previous entry (freshly revealed) renders at its final position
 * immediately and gets a CSS mount-in animation instead (see .mindmap-node-enter). */
function useTweenedPositions(positioned) {
  const [rendered, setRendered] = useState(positioned);
  const currentRef = useRef(new Map(positioned.map((n) => [n.id, n])));
  const rafRef = useRef(null);

  useEffect(() => {
    const duration = prefersReducedMotion() ? 0 : TWEEN_MS;
    const startById = currentRef.current;
    const startPositions = positioned.map((n) => startById.get(n.id) || n);
    const startTime = performance.now();

    const tick = (now) => {
      const eased = duration === 0 ? 1 : easeOutCubic(Math.min(1, (now - startTime) / duration));
      const next = positioned.map((n, i) => ({
        ...n,
        x: startPositions[i].x + (n.x - startPositions[i].x) * eased,
        y: startPositions[i].y + (n.y - startPositions[i].y) * eased,
      }));
      currentRef.current = new Map(next.map((n) => [n.id, n]));
      setRendered(next);
      if (eased < 1) rafRef.current = requestAnimationFrame(tick);
    };

    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(tick);
    return () => rafRef.current && cancelAnimationFrame(rafRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [positioned]);

  return rendered;
}

// A real (view-only) mind-map: horizontal collapsible tree — root on the left, branches
// expanding rightward, always-horizontal labels (no rotation math, since nodes are plain
// HTML pills via <foreignObject> rather than raw rotated SVG <text>). Pan/zoom is a custom
// transform-based canvas (scroll wheel zooms toward the cursor, pointer-drag pans) rather than
// native container scrolling, so it behaves like a real graph-explorer (NotebookLM, Figma,
// Maps) instead of a scrollable page. Editing (confirm/unconfirm/untested) stays in
// VulnCatalogPanel; this view never mutates the notebook.
export default function MindMap({ domain, tree, chains, initialFocusId, onClose, t }) {
  const root = useMemo(() => buildTree(domain, tree, chains), [domain, tree, chains]);

  const [expanded, setExpanded] = useState(() => {
    if (initialFocusId) {
      const path = findAncestorPath(root, initialFocusId);
      if (path) return new Set(path);
    }
    return new Set(["__root__"]);
  });
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState(INITIAL_PAN);
  const [isDragging, setIsDragging] = useState(false);

  const viewportRef = useRef(null);
  const zoomRef = useRef(1);
  const dragRef = useRef(null);

  const { positioned, edgesMeta } = useMemo(() => layout(root, expanded), [root, expanded]);
  const rendered = useTweenedPositions(positioned);
  const maxX = Math.max(...positioned.map((n) => n.x)) + NODE_W + 40;
  const maxY = Math.max(...positioned.map((n) => n.y)) + NODE_H + 40;

  const posById = useMemo(() => new Map(rendered.map((n) => [n.id, n])), [rendered]);
  const renderedEdges = useMemo(
    () =>
      edgesMeta
        .map((e) => {
          const from = posById.get(e.fromId);
          const to = posById.get(e.toId);
          if (!from || !to) return null;
          return { ...e, x1: from.x + NODE_W, y1: from.y + NODE_H / 2, x2: to.x, y2: to.y + NODE_H / 2 };
        })
        .filter(Boolean),
    [edgesMeta, posById]
  );

  const toggle = (id) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Zooms so the content point currently under (localX, localY) stays fixed on screen —
  // the "zoom toward cursor" feel of Figma/Maps/NotebookLM, rather than always scaling from
  // the canvas origin.
  const zoomBy = useCallback((factor, localX, localY) => {
    const current = zoomRef.current;
    const nextZoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, current * factor));
    const ratio = nextZoom / current;
    zoomRef.current = nextZoom;
    setZoom(nextZoom);
    setPan((p) => ({ x: localX - (localX - p.x) * ratio, y: localY - (localY - p.y) * ratio }));
  }, []);

  const onZoomButton = (factor) => {
    const rect = viewportRef.current?.getBoundingClientRect();
    zoomBy(factor, (rect?.width ?? 0) / 2, (rect?.height ?? 0) / 2);
  };

  const onRecenter = () => {
    zoomRef.current = 1;
    setZoom(1);
    setPan(INITIAL_PAN);
  };

  // A React onWheel handler can't reliably preventDefault (React 17+ binds it passively), so
  // the wheel listener is attached natively with { passive: false }.
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const factor = Math.exp(-e.deltaY * 0.0018);
      zoomBy(factor, e.clientX - rect.left, e.clientY - rect.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomBy]);

  const onPointerDown = (e) => {
    if (e.target.closest("button, select, a, input")) return;
    dragRef.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y, pointerId: e.pointerId };
    setIsDragging(true);
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onPointerMove = (e) => {
    const drag = dragRef.current;
    if (!drag) return;
    setPan({ x: drag.panX + (e.clientX - drag.startX), y: drag.panY + (e.clientY - drag.startY) });
  };
  const endDrag = (e) => {
    const drag = dragRef.current;
    if (drag && e.currentTarget.hasPointerCapture?.(drag.pointerId)) {
      e.currentTarget.releasePointerCapture(drag.pointerId);
    }
    dragRef.current = null;
    setIsDragging(false);
  };

  return (
    <div className="page-enter fixed inset-0 z-50 bg-zinc-950 flex flex-col">
      <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-white/[0.07] shrink-0">
        <span className="text-[11px] font-mono text-zinc-600 truncate">{domain}</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1">
            <button
              onClick={() => onZoomButton(1 / 1.2)}
              className="w-7 h-7 flex items-center justify-center text-zinc-400 hover:text-zinc-100 border border-white/[0.08] transition-colors"
            >
              <MagnifyingGlassMinus size={13} />
            </button>
            <span className="w-10 text-center text-[10.5px] font-mono text-zinc-500 tabular-nums">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => onZoomButton(1.2)}
              className="w-7 h-7 flex items-center justify-center text-zinc-400 hover:text-zinc-100 border border-white/[0.08] transition-colors"
            >
              <MagnifyingGlassPlus size={13} />
            </button>
            <button
              onClick={onRecenter}
              aria-label={t.mindMapRecenter}
              title={t.mindMapRecenter}
              className="w-7 h-7 flex items-center justify-center text-zinc-400 hover:text-zinc-100 border border-white/[0.08] transition-colors"
            >
              <ArrowsInSimple size={13} />
            </button>
          </div>
          <button onClick={onClose} aria-label={t.chainClose} className="text-zinc-500 hover:text-zinc-100">
            <X size={18} />
          </button>
        </div>
      </div>

      <div
        ref={viewportRef}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        className={`flex-1 min-h-0 relative overflow-hidden touch-none ${
          isDragging ? "cursor-grabbing select-none" : "cursor-grab"
        }`}
      >
        <div
          className="absolute top-0 left-0"
          style={{
            width: maxX,
            height: maxY,
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "0 0",
          }}
        >
          <svg width={maxX} height={maxY}>
            {renderedEdges.map((e) => (
              <path
                key={`${e.fromId}::${e.toId}`}
                className="mindmap-edge-enter"
                d={connectorPath(e.x1, e.y1, e.x2, e.y2)}
                stroke={e.color}
                strokeWidth={e.dashed ? 1.5 : 2.5}
                strokeDasharray={e.dashed ? "4 4" : undefined}
                fill="none"
                opacity={e.dashed ? 0.55 : 0.75}
              />
            ))}
            {rendered.map((n) => {
              const isRoot = n.kind === "root";
              const isCategory = n.kind === "category";
              return (
                <foreignObject key={n.id} x={n.x} y={n.y} width={NODE_W + 24} height={NODE_H}>
                  <div
                    xmlns="http://www.w3.org/1999/xhtml"
                    className="mindmap-node-enter flex items-center gap-1 h-full"
                    style={{ width: NODE_W + 24 }}
                  >
                    <button
                      onClick={() => setSelected(n)}
                      title={n.justification || undefined}
                      className="flex-1 min-w-0 flex items-center gap-1.5 px-2.5 h-[30px] rounded-full border text-[11.5px] font-medium truncate transition-colors"
                      style={
                        isRoot
                          ? { background: "rgba(20,184,166,0.15)", borderColor: "#5EEAD4", color: "#F0FDFA" }
                          : isCategory
                            ? n.open
                              ? { background: `${n.color}30`, borderColor: n.color, color: "#F7F7F9" }
                              : { background: `${n.color}22`, borderColor: n.color, color: n.color }
                            : { background: "#18181B", borderColor: "#3F3F46", color: "#E4E4E7" }
                      }
                    >
                      {!isRoot && !isCategory && n.status && (
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{
                            background: STATUS_DOT[n.status] || STATUS_DOT.untested,
                            boxShadow: n.inProgress ? "0 0 0 2px #FBBF24" : undefined,
                          }}
                        />
                      )}
                      <span className="truncate">{n.label}</span>
                    </button>
                    {n.hasChildren && (
                      <button
                        onClick={() => toggle(n.id)}
                        aria-label={n.open ? "Collapse" : "Expand"}
                        className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center border border-white/[0.15] text-zinc-400 hover:text-emerald-300 hover:border-emerald-400/50 transition-colors"
                      >
                        {n.open ? <CaretLeft size={10} /> : <CaretRight size={10} />}
                      </button>
                    )}
                  </div>
                </foreignObject>
              );
            })}
          </svg>
        </div>

        {selected && (selected.status || selected.justification || selected.note) && (
          <div className="absolute bottom-4 right-4 w-[260px] border border-white/[0.1] bg-zinc-950/95 backdrop-blur p-3 space-y-1.5">
            <p className="text-[12.5px] font-semibold text-zinc-100">{selected.label}</p>
            {selected.status && (
              <p className="text-[11px] font-mono" style={{ color: STATUS_DOT[selected.status] }}>
                {statusLabel(selected.status, t)}
              </p>
            )}
            {selected.justification && <p className="text-[11px] text-zinc-500">{selected.justification}</p>}
            {selected.note && <p className="text-[11px] text-zinc-500 italic">{selected.note}</p>}
          </div>
        )}
      </div>
    </div>
  );
}
