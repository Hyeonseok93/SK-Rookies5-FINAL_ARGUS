import { useState } from "react";

import { ChevronDown } from "lucide-react";

import { CollapsibleReportSection } from "./CollapsibleReportSection";

import {

  mergeG36Findings,

  type G36Finding,

  type G36MergedFinding,

} from "../../lib/g36ReportView";



const SEVERITY_STYLES: Record<string, string> = {

  high: "text-rose-300",

  medium: "text-amber-300",

  low: "text-sky-300",

  info: "text-cyber-muted",

};



const G36_SUMMARY_COLGROUP = (

  <colgroup>

    <col style={{ width: "28%" }} />

    <col style={{ width: "14%" }} />

    <col style={{ width: "34%" }} />

    <col style={{ width: "12%" }} />

    <col style={{ width: "6%" }} />

    <col style={{ width: "6%" }} />

  </colgroup>

);



function G36EllipsisCell({

  value,

  className = "",

  mono = false,

}: {

  value: string | null | undefined;

  className?: string;

  mono?: boolean;

}) {

  const full = (value ?? "").trim() || "—";

  return (

    <span

      className={`block min-w-0 truncate ${mono ? "font-mono" : ""} ${className}`}

      title={full !== "—" ? full : undefined}

    >

      {full}

    </span>

  );

}



function G36SummaryTable({ merged }: { merged: G36MergedFinding[] }) {

  return (

    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">

      <div className="border-b border-cyber-border/30 px-3 py-2">

        <span className="text-xs font-semibold text-white">노출된 백업·테스트 파일</span>

        {merged.length === 0 ? (

          <p className="mt-0.5 text-[10px] text-emerald-300/90">노출 없음</p>

        ) : null}

      </div>

      {merged.length > 0 ? (

        <table className="w-full min-w-[40rem] table-fixed text-left text-[10px]">

          {G36_SUMMARY_COLGROUP}

          <thead>

            <tr className="border-b border-cyber-border/20 text-cyber-muted">

              <th className="px-2 py-1.5 font-normal">경로</th>

              <th className="px-2 py-1.5 font-normal">유형</th>

              <th className="px-2 py-1.5 font-normal">사유</th>

              <th className="px-2 py-1.5 font-normal">인증</th>

              <th className="px-1 py-1.5 text-center font-normal">HTTP</th>

              <th className="px-1 py-1.5 text-center font-normal">Sev</th>

            </tr>

          </thead>

          <tbody>

            {merged.map((row) => (

              <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">

                <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">

                  <G36EllipsisCell
                    value={
                      row.baseLabel
                        ? `${row.pathSummary} · ${row.baseLabel}`
                        : row.pathSummary
                    }
                    className="text-cyan-300/90"
                    mono
                  />

                </td>

                <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/85">

                  <G36EllipsisCell value={row.fileTypeLabel} />

                </td>

                <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">

                  <G36EllipsisCell value={row.reason} className="text-white/75" />

                </td>

                <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">

                  <G36EllipsisCell value={row.authLabel} className="text-cyan-300/85" mono />

                </td>

                <td className="px-1 py-1.5 text-center align-middle font-mono text-cyan-300/70">

                  {row.httpStatus ?? "—"}

                </td>

                <td className="px-1 py-1.5 text-center align-middle">

                  <span

                    className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}

                  >

                    {row.severity}

                  </span>

                </td>

              </tr>

            ))}

          </tbody>

        </table>

      ) : null}

    </div>

  );

}



function G36FindingDetail({ row }: { row: G36MergedFinding }) {

  return (

    <div className="mt-1.5 space-y-2 border-t border-cyber-border/20 pt-1.5 text-[10px]">

      {row.reason ? (

        <p>

          <span className="text-cyber-muted">사유 · </span>

          <span className="break-words text-white/80">{row.reason}</span>

        </p>

      ) : null}

      {row.urls.length > 0 ? (

        <div>

          <span className="text-cyber-muted">URL · </span>

          <ul className="mt-1 max-h-40 space-y-1 overflow-y-auto">

            {row.urls.map((url) => (

              <li

                key={url}

                className="break-all rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1 font-mono text-cyan-300/80"

              >

                {url}

              </li>

            ))}

          </ul>

        </div>

      ) : null}

      {row.remediation ? (

        <p className="rounded border border-cyber-border/20 bg-cyber-bg/30 px-2 py-1.5">

          <span className="text-cyber-muted">조치 · </span>

          <span className="break-words text-white/75">{row.remediation}</span>

        </p>

      ) : null}

    </div>

  );

}



function G36DetailRow({ row }: { row: G36MergedFinding }) {

  const [open, setOpen] = useState(false);



  return (

    <li className="rounded border border-cyber-border/25 bg-cyber-panel/20 px-2.5 py-1.5">

      <button

        type="button"

        onClick={() => setOpen((v) => !v)}

        className="flex w-full items-start gap-2 text-left"

      >

        <ChevronDown

          className={`mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}

        />

        <span

          className={`shrink-0 font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}

        >

          {row.severity}

        </span>

        <span className="min-w-0 flex-1 truncate font-mono text-xs text-cyan-300/90">{row.pathSummary}</span>

        <span className="shrink-0 text-[10px] text-white/75">{row.fileTypeLabel}</span>

      </button>

      {open ? <G36FindingDetail row={row} /> : null}

    </li>

  );

}



export function G36FindingsPanel({

  findings,

}: {

  findings: G36Finding[];

  stats?: Record<string, unknown> | null;

  status?: string;

}) {

  const { merged, other } = mergeG36Findings(findings);



  return (

    <>

      <G36SummaryTable merged={merged} />

      {merged.length > 0 ? (

        <CollapsibleReportSection title="상세" defaultOpen={false}>

          <p className="mb-2 text-[10px] text-cyber-muted">

            노출 파일별 URL·조치. 요약에서 잘린 경로는 여기서 전체 확인할 수 있습니다.

          </p>

          <ul className="space-y-1.5">

            {merged.map((row) => (

              <G36DetailRow key={row.rowKey} row={row} />

            ))}

          </ul>

        </CollapsibleReportSection>

      ) : null}

      {other.length > 0 ? (

        <CollapsibleReportSection title="기타" defaultOpen={false}>

          <ul className="space-y-2">

            {other.map((f, i) => (

              <li

                key={`other-${i}`}

                className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2"

              >

                <div className="flex items-start gap-2">

                  <span

                    className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}

                  >

                    {f.severity}

                  </span>

                  <span className="text-xs text-white/90">{f.message}</span>

                </div>

              </li>

            ))}

          </ul>

        </CollapsibleReportSection>

      ) : null}

    </>

  );

}

