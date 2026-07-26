"""Build 2-2 diagnosis PDF report from latest.yaml + evidence screenshots."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_DIR = Path(__file__).resolve().parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

from content import (  # noqa: E402
    SK_FILTER_CHARS,
    SK_FILTER_TABLE_TITLE,
    SK_REMEDIATION_AFTER_TABLE,
    SK_REMEDIATION_BEFORE_TABLE,
    build_result_rows,
    copy_for_rule,
)
from shots import load_shots_for_finding  # noqa: E402

# Width keeps A4; height is measured so everything fits on one continuous page.
PAGE_W = A4[0]
MARGIN = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN
IMG_MAX_W = CONTENT_W - 8 * mm
IMG_MAX_H = 150 * mm
TOP_MARGIN = 14 * mm
BOTTOM_MARGIN = 14 * mm


def _register_font() -> tuple[str, str]:
    """Return (regular, bold) font names registered for Korean."""
    candidates = [
        (Path(r"C:\Windows\Fonts\malgun.ttf"), Path(r"C:\Windows\Fonts\malgunbd.ttf")),
        (Path(r"C:\Windows\Fonts\malgunsl.ttf"), Path(r"C:\Windows\Fonts\malgunbd.ttf")),
        # Docker/Linux: TrueType (reportlab cannot use CFF/PostScript CJK .ttc)
        (Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"), Path("/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
    ]
    for regular, bold in candidates:
        if not regular.is_file():
            continue
        try:
            pdfmetrics.registerFont(TTFont("G22Report", str(regular)))
        except Exception:
            continue
        bold_name = "G22Report"
        if bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont("G22Report-Bold", str(bold)))
                bold_name = "G22Report-Bold"
            except Exception:
                bold_name = "G22Report"
        return "G22Report", bold_name
    return "Helvetica", "Helvetica-Bold"


def _styles(font: str, font_bold: str) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "G22Title",
            parent=base["Title"],
            fontName=font_bold,
            fontSize=18,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "meta": ParagraphStyle(
            "G22Meta",
            parent=base["Normal"],
            fontName=font,
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#444444"),
            spaceAfter=4,
        ),
        "h1": ParagraphStyle(
            "G22H1",
            parent=base["Heading1"],
            fontName=font_bold,
            fontSize=13,
            leading=18,
            spaceBefore=14,
            spaceAfter=8,
            textColor=colors.HexColor("#111827"),
        ),
        "h2": ParagraphStyle(
            "G22H2",
            parent=base["Heading2"],
            fontName=font_bold,
            fontSize=11,
            leading=15,
            spaceBefore=8,
            spaceAfter=4,
            textColor=colors.HexColor("#1f2937"),
        ),
        "body": ParagraphStyle(
            "G22Body",
            parent=base["Normal"],
            fontName=font,
            fontSize=10,
            leading=15,
            alignment=TA_JUSTIFY,
            spaceAfter=4,
        ),
        "caption": ParagraphStyle(
            "G22Caption",
            parent=base["Normal"],
            fontName=font_bold,
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=0,
            spaceAfter=0,
        ),
        "note": ParagraphStyle(
            "G22Note",
            parent=base["Normal"],
            fontName=font,
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=6,
        ),
        "table_title": ParagraphStyle(
            "G22TableTitle",
            parent=base["Normal"],
            fontName=font_bold,
            fontSize=10,
            leading=14,
            spaceBefore=6,
            spaceAfter=4,
            textColor=colors.HexColor("#111827"),
        ),
        "table_header": ParagraphStyle(
            "G22TableHeader",
            parent=base["Normal"],
            fontName=font_bold,
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
        ),
        "table_cell": ParagraphStyle(
            "G22TableCell",
            parent=base["Normal"],
            fontName=font,
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
        ),
    }


def _escape(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _select_findings(raw: list[Any]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "").lower()
        msg = str(item.get("message") or "")
        if sev == "info" and "scan statistics" in msg.lower():
            continue
        if sev == "info":
            continue
        ev = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        fid = str(ev.get("finding_id") or "").strip()
        if not fid:
            continue
        if fid in seen:
            continue
        seen.add(fid)
        selected.append(item)
    return selected


def _fit_image(path: Path) -> Image | None:
    try:
        img = Image(str(path))
    except Exception:
        return None
    w, h = float(img.imageWidth), float(img.imageHeight)
    if w <= 0 or h <= 0:
        return None
    scale = min(IMG_MAX_W / w, IMG_MAX_H / h, 1.0)
    img.drawWidth = w * scale
    img.drawHeight = h * scale
    img.hAlign = "CENTER"
    return img


def _shot_card(label: str, path: Path, styles: dict[str, ParagraphStyle]) -> Any:
    """Screenshot + caption in a light framed card."""
    caption = Paragraph(_escape(label), styles["caption"])
    img = _fit_image(path)
    if img is None:
        body: Any = Paragraph(
            _escape(f"(이미지를 불러오지 못함: {path.name})"),
            styles["note"],
        )
    else:
        body = img

    inner = Table(
        [[caption], [body]],
        colWidths=[IMG_MAX_W],
    )
    inner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#d1d5db")),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
                ("TOPPADDING", (0, 1), (-1, 1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    outer = Table([[inner]], colWidths=[CONTENT_W])
    outer.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return outer


def _filter_chars_table(styles: dict[str, ParagraphStyle]) -> list[Any]:
    """Render SK download filter-character list as a compact table."""
    header_label = "필터링 문자"
    data = [[Paragraph(_escape(header_label), styles["table_header"])]]
    for ch in SK_FILTER_CHARS:
        data.append([Paragraph(_escape(ch), styles["table_cell"])])
    table = Table(data, colWidths=[70 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    return [
        Paragraph(_escape(SK_FILTER_TABLE_TITLE), styles["table_title"]),
        table,
        Spacer(1, 6),
    ]


def _result_table(rows: list[tuple[str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    """Compact URL / parameter table for section 2."""
    label_style = ParagraphStyle(
        "G22ResultLabel",
        parent=styles["table_header"],
        alignment=TA_LEFT,
        fontSize=9,
    )
    value_style = ParagraphStyle(
        "G22ResultValue",
        parent=styles["table_cell"],
        alignment=TA_LEFT,
        fontName=styles["table_cell"].fontName,
        fontSize=9,
        leading=12,
    )
    data = [
        [
            Paragraph(_escape("구분"), styles["table_header"]),
            Paragraph(_escape("내용"), styles["table_header"]),
        ]
    ]
    for label, value in rows:
        data.append(
            [
                Paragraph(_escape(label), label_style),
                Paragraph(_escape(value), value_style),
            ]
        )
    table = Table(data, colWidths=[28 * mm, CONTENT_W - 28 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f3f4f6")),
                ("ROWBACKGROUNDS", (1, 1), (1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    return table


def _measure_story_height(story: list[Any], avail_width: float) -> float:
    """Wrap flowables once to estimate total vertical size."""
    from io import BytesIO

    from reportlab.pdfgen.canvas import Canvas

    canv = Canvas(BytesIO())
    total = 0.0
    for item in story:
        space_before = float(getattr(item, "getSpaceBefore", lambda: 0)() or 0)
        space_after = float(getattr(item, "getSpaceAfter", lambda: 0)() or 0)
        _w, h = item.wrapOn(canv, avail_width, 1e9)
        total += space_before + float(h) + space_after
    return total


def _render_story_pdf(
    story: list[Any],
    *,
    section_id: str,
) -> bytes:
    """Render story onto one continuous vertical page sized to content."""
    from io import BytesIO

    content_h = _measure_story_height(story, CONTENT_W)
    page_h = max(A4[1] * 0.4, content_h + TOP_MARGIN + BOTTOM_MARGIN + 24)
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=(PAGE_W, page_h),
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title=f"ARGUS {section_id} Report",
        author="ARGUS",
    )
    doc.build(story)
    return buf.getvalue()


def _finding_story(
    *,
    idx: int,
    finding: dict[str, Any],
    evidence_root: Path,
    styles: dict[str, ParagraphStyle],
    section_id: str,
    title: str,
) -> list[Any]:
    """Build flowables for a single finding page."""
    story: list[Any] = []
    story.append(Paragraph(_escape(f"{section_id} 진단 결과서"), styles["title"]))
    story.append(Paragraph(_escape(title), styles["meta"]))
    story.append(Spacer(1, 8))

    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    rule_id = str(ev.get("rule_id") or "").strip() or None
    finding_id = str(ev.get("finding_id") or "").strip()
    copy = copy_for_rule(rule_id)
    header = f"[Finding {idx}] {copy['type_label']}"
    story.append(Paragraph(_escape(header), styles["h1"]))

    story.append(Paragraph(_escape("1. 탐지 기법"), styles["h2"]))
    story.append(Paragraph(_escape(copy["technique"]), styles["body"]))
    story.append(Spacer(1, 4))

    shots = load_shots_for_finding(evidence_root, finding_id) if finding_id else []
    if not shots:
        story.append(Paragraph(_escape("증거 이미지 없음"), styles["note"]))
    else:
        for shot in shots:
            story.append(_shot_card(shot.label, shot.path, styles))

    story.append(Paragraph(_escape("2. 취약점 확인 결과"), styles["h2"]))
    story.append(_result_table(build_result_rows(finding), styles))
    story.append(Spacer(1, 6))

    story.append(Paragraph(_escape("3. 대응방안"), styles["h2"]))
    story.append(Paragraph(_escape(SK_REMEDIATION_BEFORE_TABLE), styles["body"]))
    story.extend(_filter_chars_table(styles))
    story.append(Paragraph(_escape(SK_REMEDIATION_AFTER_TABLE), styles["body"]))
    return story


def build_pdf(report_dir: Path, out_path: Path | None = None) -> Path:
    from io import BytesIO

    from pypdf import PdfReader, PdfWriter

    report_dir = report_dir.resolve()
    yaml_path = report_dir / "latest.yaml"
    evidence_root = report_dir / "evidence"
    if out_path is None:
        out_path = report_dir / "result.pdf"
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not yaml_path.is_file():
        raise FileNotFoundError(f"missing report yaml: {yaml_path}")

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("latest.yaml root must be a mapping")

    findings = _select_findings(list(data.get("findings") or []))
    font, font_bold = _register_font()
    styles = _styles(font, font_bold)
    title = str(data.get("title") or "중요 정보 파일 다운로드 가능성")
    section_id = str(data.get("section_id") or "2-2")

    writer = PdfWriter()

    if not findings:
        empty_story: list[Any] = [
            Paragraph(_escape(f"{section_id} 진단 결과서"), styles["title"]),
            Paragraph(_escape(title), styles["meta"]),
            Spacer(1, 12),
            Paragraph(
                _escape("포함할 finding이 없습니다. (finding_id + evidence 폴더가 있는 항목만 출력)"),
                styles["note"],
            ),
        ]
        chunk = _render_story_pdf(empty_story, section_id=section_id)
        writer.append(PdfReader(BytesIO(chunk)))
    else:
        # One continuous tall page per finding (not one huge page for all)
        for idx, finding in enumerate(findings, start=1):
            story = _finding_story(
                idx=idx,
                finding=finding,
                evidence_root=evidence_root,
                styles=styles,
                section_id=section_id,
                title=title,
            )
            chunk = _render_story_pdf(story, section_id=section_id)
            writer.append(PdfReader(BytesIO(chunk)))

    with out_path.open("wb") as fh:
        writer.write(fh)
    return out_path
