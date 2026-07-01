import { CheckCircle, PencilSimpleLine } from "@phosphor-icons/react";

/** Small state pill — complete vs. draft — using the semantic (not accent) hues. */
export default function StatusBadge({ status, labels }) {
  const complete = status === "complete";
  const Icon = complete ? CheckCircle : PencilSimpleLine;
  const color = complete
    ? "text-emerald-400 border-emerald-500/25 bg-emerald-500/10"
    : "text-amber-400 border-amber-400/25 bg-amber-400/10";
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 border text-[10.5px] font-semibold uppercase tracking-wider ${color}`}
      style={{ color: complete ? undefined : "#F5B547" }}
    >
      <Icon size={12} weight="fill" />
      {complete ? labels.complete : labels.stub}
    </span>
  );
}
