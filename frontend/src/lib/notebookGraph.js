// Shared helpers for the notebook's category -> technique -> exploit-chain graph, used by both
// MindMap (renders the whole tree) and VulnCatalogPanel (renders a per-node chain preview
// inline). Kept separate so the two views can't drift on how a chain hop is resolved.

/** Maps every real notebook node id (technique, not category) to its label/status/justification. */
export function buildStatusIndex(tree) {
  const statusById = new Map();
  (tree || []).forEach((cat) =>
    (cat.children || []).forEach((c) =>
      statusById.set(c.id, { label: c.label, status: c.status, justification: c.justification })
    )
  );
  return statusById;
}

const MAX_CHAIN_DEPTH = 4;

/** Recursively walks `chains` (from_node -> to_node hops) starting at `nodeId`, resolving each
 * hop's label/status via `statusById`. A per-branch visited set stops a chain loop from
 * recursing forever. Each hop gets both a path-unique `id` (safe as a React key even if the
 * same real node is reachable via two different chains) and the underlying `realId` (the
 * actual notebook node id, needed to persist a status change or focus the mind map on it). */
export function chainChildrenOf(
  chains,
  statusById,
  nodeId,
  keyPrefix = nodeId,
  depth = 1,
  visited = new Set([nodeId])
) {
  if (depth > MAX_CHAIN_DEPTH) return [];
  return (chains || [])
    .filter((c) => c.from_node === nodeId && !visited.has(c.to_node))
    .map((c) => {
      const known = statusById.get(c.to_node);
      const nextVisited = new Set(visited);
      nextVisited.add(c.to_node);
      const key = `${keyPrefix}::${c.to_node}`;
      return {
        id: key,
        realId: c.to_node,
        label: known?.label || c.to_node,
        note: c.note,
        status: known?.status,
        justification: known?.justification,
        children: chainChildrenOf(chains, statusById, c.to_node, key, depth + 1, nextVisited),
      };
    });
}
