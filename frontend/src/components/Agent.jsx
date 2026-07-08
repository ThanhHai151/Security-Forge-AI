import { useCallback, useEffect, useState } from "react";

import ContinuousLockedPanel from "./ContinuousLockedPanel";
import MindMap from "./MindMap";
import NotebookSidebar from "./NotebookSidebar";
import SupervisorPanel from "./SupervisorPanel";
import VulnCatalogPanel from "./VulnCatalogPanel";
import {
  addNotebookChild,
  advise,
  deleteNotebookDomain,
  getNotebook,
  getNotebookTree,
  getNotebookTreeRoots,
  ingestNotebookOutput,
  notebookSarif,
  updateNotebookNode,
} from "../lib/api";

// The Agent page is the Expert Supervisor console: it advises whichever coding agent (e.g.
// Claude Code) the operator drives, it never executes pentest actions itself. "Single run"
// is the live advisory flow; "Continuous" (the old autopilot campaign engine) is locked
// pending a redesign — see ContinuousLockedPanel and backend/service.py's
// AutonomousDisabledError. Red-team only: source-code review is Defense's job, not this
// page's notebook.
export default function Agent({ t }) {
  const [agentMode, setAgentMode] = useState("single"); // "single" | "continuous" (locked)

  const [roots, setRoots] = useState([]);
  const [activeDomain, setActiveDomain] = useState("");
  const [tree, setTree] = useState([]);
  const [chains, setChains] = useState([]);

  const [question, setQuestion] = useState("");
  const [scanMode, setScanMode] = useState("standard"); // "quick" | "standard" | "deep"
  const [advice, setAdvice] = useState(null);
  const [adviceErr, setAdviceErr] = useState("");
  const [asking, setAsking] = useState(false);

  const [ingestText, setIngestText] = useState("");
  const [ingesting, setIngesting] = useState(false);
  const [ingestResult, setIngestResult] = useState(null);
  const [ingestErr, setIngestErr] = useState("");

  const [mindMapOpen, setMindMapOpen] = useState(false);
  const [mindMapFocusId, setMindMapFocusId] = useState(null);

  const loadRoots = useCallback(() => {
    getNotebookTreeRoots()
      .then((d) => setRoots(d.roots || []))
      .catch(() => {});
  }, []);
  useEffect(() => loadRoots(), [loadRoots]);

  const loadTree = useCallback((domain) => {
    if (!domain) return setTree([]);
    getNotebookTree(domain)
      .then((d) => setTree(d.tree || []))
      .catch(() => setTree([]));
  }, []);
  useEffect(() => loadTree(activeDomain), [activeDomain, loadTree]);

  const loadChains = useCallback((domain) => {
    if (!domain) return setChains([]);
    getNotebook(domain)
      .then((nb) => setChains(nb.chains || []))
      .catch(() => setChains([]));
  }, []);
  useEffect(() => loadChains(activeDomain), [activeDomain, loadChains]);

  const refreshActiveDomain = useCallback(() => {
    loadTree(activeDomain);
    loadChains(activeDomain);
    loadRoots();
  }, [activeDomain, loadTree, loadChains, loadRoots]);

  // Single-click a domain: just select it, so the vuln catalog to its right updates. Opening
  // the (heavier) full mind map is reserved for a deliberate double-click or a vuln row —
  // see onOpenDomainMap/onOpenNode below.
  const onSelectDomain = useCallback((domain) => {
    setActiveDomain(domain);
    setAdvice(null);
    setAdviceErr("");
    setIngestResult(null);
    setIngestErr("");
  }, []);

  const onOpenDomainMap = useCallback((domain) => {
    setActiveDomain(domain);
    setMindMapFocusId(null);
    setMindMapOpen(true);
  }, []);

  const onOpenNode = useCallback((nodeId) => {
    setMindMapFocusId(nodeId);
    setMindMapOpen(true);
  }, []);

  // A new root domain is just selected — the backend seeds a fresh, all-untested notebook for
  // any target it hasn't seen before (get_or_create), so there's nothing else to do here.
  const onAddRoot = onSelectDomain;

  const onAddChild = useCallback(
    async (parentDomain, child) => {
      try {
        await addNotebookChild(parentDomain, child);
        loadRoots();
        onSelectDomain(child);
      } catch (e) {
        setAdviceErr(String(e.message || e));
      }
    },
    [loadRoots, onSelectDomain]
  );

  const onDeleteDomain = useCallback(
    async (domain) => {
      try {
        await deleteNotebookDomain(domain);
        if (domain === activeDomain) {
          setActiveDomain("");
          setAdvice(null);
          setAdviceErr("");
          setIngestResult(null);
          setIngestErr("");
        }
        loadRoots();
      } catch (e) {
        setAdviceErr(String(e.message || e));
      }
    },
    [activeDomain, loadRoots]
  );

  const onSetStatus = useCallback(
    async (nodeId, status) => {
      if (!activeDomain) return;
      try {
        await updateNotebookNode(activeDomain, nodeId, status);
        refreshActiveDomain();
      } catch (e) {
        setAdviceErr(String(e.message || e));
      }
    },
    [activeDomain, refreshActiveDomain]
  );

  const onAsk = useCallback(async () => {
    if (!activeDomain || !question.trim()) return;
    setAsking(true);
    setAdviceErr("");
    try {
      const result = await advise({
        domain: activeDomain,
        question: question.trim(),
        mode: "blackbox",
        scanMode,
      });
      setAdvice(result);
      refreshActiveDomain();
    } catch (e) {
      setAdviceErr(String(e.message || e));
    } finally {
      setAsking(false);
    }
  }, [activeDomain, question, scanMode, refreshActiveDomain]);

  const onIngest = useCallback(async () => {
    if (!activeDomain || !ingestText.trim()) return;
    setIngesting(true);
    setIngestErr("");
    try {
      const result = await ingestNotebookOutput(activeDomain, ingestText.trim());
      setIngestResult(result);
      setIngestText("");
      refreshActiveDomain();
    } catch (e) {
      setIngestErr(String(e.message || e));
    } finally {
      setIngesting(false);
    }
  }, [activeDomain, ingestText, refreshActiveDomain]);

  // Export this domain's confirmed/unconfirmed findings as a SARIF 2.1.0 file (CI upload).
  const onExportSarif = useCallback(async () => {
    if (!activeDomain) return;
    try {
      const doc = await notebookSarif(activeDomain);
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${activeDomain}.sarif.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setIngestErr(String(e.message || e));
    }
  }, [activeDomain]);

  return (
    <div className="page-enter agent-page-shell w-full px-3 sm:px-4 lg:px-6 py-4 flex flex-col">
      {/* Visually hidden — gives screen-reader users a page landmark heading to jump to;
          the visible chrome (TopNav's "Agent" link + this page's own labels) already
          communicates the same thing sighted users see. */}
      <h1 className="sr-only">{t.supHeading}</h1>

      {/* Single run / Continuous toggle — Continuous is a locked placeholder, not a dead
          route. Real tab semantics so assistive tech announces it as a 2-way switch, not
          two unrelated buttons. */}
      <div
        role="tablist"
        aria-label={t.agentViewModeLabel}
        className="shrink-0 mb-3 flex gap-1.5"
      >
        {[
          { id: "single", label: t.agentModeSingle },
          { id: "continuous", label: `${t.agentModeContinuous} · ${t.agentModeLocked}` },
        ].map((m) => (
          <button
            key={m.id}
            role="tab"
            aria-selected={agentMode === m.id}
            onClick={() => setAgentMode(m.id)}
            className={`px-3 py-1.5 text-[12.5px] font-medium border transition-colors ${
              agentMode === m.id
                ? "bg-zinc-800 text-emerald-400 border-emerald-500/30"
                : "text-zinc-300 border-white/[0.07] hover:text-zinc-100"
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Three columns filling the full width: targets -> that target's vuln catalog -> the
          supervisor panel (which absorbs whatever width is left on wide screens). Stacks
          vertically below `lg`. */}
      <main
        aria-label={t.supHeading}
        className="flex flex-col lg:flex-row gap-3 lg:flex-1 lg:min-h-0"
      >
        <aside aria-label={t.notebookHeading} className="lg:w-[240px] shrink-0 flex flex-col min-h-0 lg:max-h-full">
          <NotebookSidebar
            roots={roots}
            activeDomain={activeDomain}
            onSelectDomain={onSelectDomain}
            onOpenDomainMap={onOpenDomainMap}
            onDeleteDomain={onDeleteDomain}
            onAddRoot={onAddRoot}
            onAddChild={onAddChild}
            t={t}
          />
        </aside>

        <aside aria-label={t.vulnCatalogHeading} className="lg:w-[300px] shrink-0 flex flex-col min-h-0 lg:max-h-full">
          <VulnCatalogPanel
            activeDomain={activeDomain}
            tree={tree}
            chains={chains}
            onSetStatus={onSetStatus}
            onOpenNode={onOpenNode}
            t={t}
          />
        </aside>

        {agentMode === "single" ? (
          <SupervisorPanel
            activeDomain={activeDomain}
            question={question}
            setQuestion={setQuestion}
            scanMode={scanMode}
            setScanMode={setScanMode}
            onExportSarif={onExportSarif}
            onAsk={onAsk}
            asking={asking}
            advice={advice}
            adviceErr={adviceErr}
            ingestText={ingestText}
            setIngestText={setIngestText}
            onIngest={onIngest}
            ingesting={ingesting}
            ingestResult={ingestResult}
            ingestErr={ingestErr}
            t={t}
          />
        ) : (
          <div className="flex-1 min-w-0 flex flex-col lg:min-h-0">
            <ContinuousLockedPanel t={t} />
          </div>
        )}
      </main>

      {mindMapOpen && (
        <MindMap
          domain={activeDomain}
          tree={tree}
          chains={chains}
          initialFocusId={mindMapFocusId}
          onClose={() => setMindMapOpen(false)}
          t={t}
        />
      )}
    </div>
  );
}
