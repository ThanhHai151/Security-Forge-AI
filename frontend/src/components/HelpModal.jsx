import { useMemo } from "react";
import { BookOpen } from "@phosphor-icons/react";

import { getGuide } from "../content/guides";
import { renderDoc } from "../lib/markdown";
import SettingsModal from "./SettingsModal";

/**
 * "How to use" instructions modal. Renders the markdown guide for a page (`agent` | `defense`)
 * in the active locale through the shared doc renderer + `.prose` styles, inside the standard
 * modal shell. Content lives in `content/guides/<page>.<locale>.md`.
 */
export default function HelpModal({ page, locale = "en", title, onClose }) {
  const { html } = useMemo(() => renderDoc(getGuide(page, locale)), [page, locale]);
  return (
    <SettingsModal
      title={title}
      icon={<BookOpen size={18} weight="bold" className="text-emerald-400" />}
      onClose={onClose}
      maxW="820px"
    >
      <div className="prose" dangerouslySetInnerHTML={{ __html: html }} />
    </SettingsModal>
  );
}
