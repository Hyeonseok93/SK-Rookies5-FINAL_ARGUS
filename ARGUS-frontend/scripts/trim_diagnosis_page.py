from pathlib import Path

src = Path("src/components/DiagnosisPage.tsx")
lines = src.read_text(encoding="utf-8").splitlines()
kept = lines[:213] + lines[1135:]
text = "\n".join(kept)
if "DiagnosisReportPanel" not in text:
    insert_at = None
    for i, line in enumerate(kept):
        if line.startswith("import type { DiagnosisCatalogModule"):
            insert_at = i + 1
            break
    if insert_at:
        kept.insert(insert_at, 'import { DiagnosisReportPanel } from "./diagnosis/DiagnosisReportPanel";')
        kept.insert(insert_at, 'import { sectionHasStartDialog } from "../lib/diagnosisRegistry";')
        kept.insert(insert_at, 'import { useProgressPoll } from "../hooks/useProgressPoll";')
text = "\n".join(kept)
text = text.replace("<ReportPanel report={report} />", "<DiagnosisReportPanel report={report} />")
src.write_text(text + "\n", encoding="utf-8")
print("DiagnosisPage lines", len(kept))
