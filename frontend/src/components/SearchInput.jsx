import { MagnifyingGlass, X } from "@phosphor-icons/react";

export default function SearchInput({ value, onChange, placeholder, inputRef }) {
  return (
    <div className="relative group">
      <MagnifyingGlass
        size={16}
        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500 transition-colors group-focus-within:text-emerald-400 pointer-events-none"
      />
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        className="w-full h-10 bg-zinc-900 border border-white/[0.07] text-[13.5px] text-zinc-100 placeholder:text-zinc-500 pl-10 pr-9 focus:outline-none focus:border-emerald-500/40 focus:ring-2 focus:ring-emerald-500/15 transition-all"
      />
      {value && (
        <button
          onClick={() => onChange("")}
          aria-label="Clear search"
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-200 transition-colors"
        >
          <X size={15} />
        </button>
      )}
    </div>
  );
}
