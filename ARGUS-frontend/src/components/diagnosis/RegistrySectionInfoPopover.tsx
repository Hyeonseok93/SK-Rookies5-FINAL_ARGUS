import { SectionInfoPopoverShell } from "./SectionInfoPopoverShell";
import { hasRegistrySectionInfo, SECTION_INFO_CONTENT } from "./sectionInfoContent";

export function RegistrySectionInfoPopover({ sectionId }: { sectionId: string }) {
  const content = SECTION_INFO_CONTENT[sectionId];
  if (!content) return null;
  return <SectionInfoPopoverShell content={content} />;
}

export { hasRegistrySectionInfo };
