from pathlib import Path

src = Path("src/components/DiagnosisPage.tsx")
lines = src.read_text(encoding="utf-8").splitlines()
header = 'import type { DiagnosisSectionReport } from "../types";\n\n'
body = "\n".join(lines[213:1135])
body = body.replace("function ReportPanel", "export function DiagnosisReportPanel")
out = Path("src/components/diagnosis/DiagnosisReportPanel.tsx")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(header + body + "\n", encoding="utf-8")
print("wrote", out, "lines", len(body.splitlines()))
