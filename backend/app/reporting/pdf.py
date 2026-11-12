"""Print-quality PDF renderer built on ReportLab Platypus.

The PDF is generated from the same normalised model as the HTML report, with
repeating headers/footers, page numbering, a dedicated cover page and
break-resistant evidence blocks.
"""
from __future__ import annotations

import io
import re
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    HRFlowable,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .model import COMPANY, PRODUCT, TAGLINE

NAVY = colors.HexColor("#0b1730")
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#5b6b82")
LINE = colors.HexColor("#dbe3ee")
BLUE = colors.HexColor("#2563eb")
CYAN = colors.HexColor("#0891b2")
PALE = colors.HexColor("#f6f8fc")
WHITE = colors.white
SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}
SEV_BG = {"critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb", "low": "#eff6ff", "info": "#f8fafc"}
CLASS_COLOR = {
    "confirmed_vulnerability": "#b91c1c", "likely_vulnerability": "#c2410c", "unsafe_behavior": "#a16207",
    "potential_vulnerability": "#1d4ed8", "inconclusive": "#475569", "false_positive": "#64748b",
}
CLASS_BG = {
    "confirmed_vulnerability": "#fef2f2", "likely_vulnerability": "#fff7ed", "unsafe_behavior": "#fefce8",
    "potential_vulnerability": "#eff6ff", "inconclusive": "#f1f5f9", "false_positive": "#f8fafc",
}

_FONT = "Vera"
_FONT_B = "VeraBd"
_FONT_I = "VeraIt"
_FONT_BI = "VeraBI"
_ASSET_DIR = Path(__file__).resolve().parents[1] / "assets"


def _asset(name: str) -> str | None:
    p = _ASSET_DIR / name
    return str(p) if p.exists() else None


def _register_fonts() -> None:
    import os
    import reportlab
    base = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
    for name, file in ((_FONT, "Vera.ttf"), (_FONT_B, "VeraBd.ttf"), (_FONT_I, "VeraIt.ttf"), (_FONT_BI, "VeraBI.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, os.path.join(base, file)))
    try:
        pdfmetrics.registerFontFamily(_FONT, normal=_FONT, bold=_FONT_B, italic=_FONT_I, boldItalic=_FONT_BI)
    except Exception:
        pass


_register_fonts()

STYLES = {
    "h1": ParagraphStyle("h1", fontName=_FONT_B, fontSize=20, leading=25, textColor=NAVY, spaceAfter=5),
    "h2": ParagraphStyle("h2", fontName=_FONT_B, fontSize=15, leading=19, textColor=NAVY, spaceBefore=12, spaceAfter=6),
    "h3": ParagraphStyle("h3", fontName=_FONT_B, fontSize=11, leading=14, textColor=NAVY, spaceBefore=9, spaceAfter=4),
    "h4": ParagraphStyle("h4", fontName=_FONT_B, fontSize=8.4, leading=11, textColor=MUTED, spaceBefore=8, spaceAfter=3),
    "body": ParagraphStyle("body", fontName=_FONT, fontSize=8.8, leading=12.4, textColor=INK, spaceAfter=5, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName=_FONT, fontSize=7.6, leading=10.4, textColor=MUTED, spaceAfter=3),
    "tiny": ParagraphStyle("tiny", fontName=_FONT, fontSize=6.8, leading=9.2, textColor=MUTED, spaceAfter=2),
    "kicker": ParagraphStyle("kicker", fontName=_FONT_B, fontSize=7, leading=9, textColor=CYAN, spaceAfter=1),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=6.9, leading=9.4, textColor=INK, wordWrap="CJK"),
    "mono_small": ParagraphStyle("mono_small", fontName="Courier", fontSize=6.2, leading=8.4, textColor=MUTED, wordWrap="CJK"),
    "bullet": ParagraphStyle("bullet", fontName=_FONT, fontSize=8.1, leading=11.2, textColor=INK, leftIndent=10, bulletIndent=2, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName=_FONT, fontSize=7.2, leading=9.8, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName=_FONT_B, fontSize=7.2, leading=9.8, textColor=INK),
    "cellhdr": ParagraphStyle("cellhdr", fontName=_FONT_B, fontSize=6.3, leading=8.4, textColor=colors.HexColor("#334155")),
    "cellmono": ParagraphStyle("cellmono", fontName="Courier", fontSize=6.4, leading=8.6, textColor=INK, wordWrap="CJK"),
}


def _s(v) -> str:
    s = "" if v is None else str(v)
    # Vera covers Latin/Greek/Cyrillic; keep PDF generation robust for any
    # Unicode that may appear in model output.
    return s.encode("cp1252", "replace").decode("cp1252")


def _x(v) -> str:
    return _xml_escape(_s(v), {"'": "&apos;", '"': "&quot;"})


def P(v, style="body") -> Paragraph:
    return Paragraph(_x(v).replace("\n", "<br/>"), STYLES[style])


def R(markup: str, style="body") -> Paragraph:
    """Paragraph from trusted internal markup (all interpolated values escaped first)."""
    return Paragraph(markup, STYLES[style])


def _pct(v) -> str:
    try:
        return f"{float(v):.0%}"
    except (TypeError, ValueError):
        return "n/a"


def _ts(v, suffix: bool = False) -> str:
    """Compact an ISO timestamp for display without losing the UTC date."""
    if v is None or v == "":
        return "—"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", str(v))
    if not m:
        return str(v)
    return f"{m.group(1)} {m.group(2)}" + (" UTC" if suffix else "")


def _yes(v) -> str:
    return "Yes" if v else "No"


def _hr(space_before=2, space_after=4):
    return HRFlowable(width="100%", thickness=0.6, color=LINE, spaceBefore=space_before, spaceAfter=space_after)


def _section(kicker: str, title: str) -> list:
    return [CondPageBreak(28 * mm), P(kicker, "kicker"), P(title, "h2"), _hr()]


def _table(rows, widths, header=True, repeat=True, bg_header="#f1f5fb", font_size=7.2, grid=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header and repeat else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [WHITE, colors.HexColor("#fbfdff")]),
    ]
    if grid:
        style += [("GRID", (0, 0), (-1, -1), 0.4, LINE)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(bg_header))]
    t.setStyle(TableStyle(style))
    return t


def _kv(rows, widths=(40 * mm, 142 * mm), label_style="cellb", value_style="cell") -> Table:
    data = [[P(k, label_style), P(v, value_style)] for k, v in rows]
    t = Table(data, colWidths=list(widths))
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f9fd")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    return t


def _callout(title: str, text: str, kind: str = "info") -> Table:
    bg = {"info": "#eff6ff", "warn": "#fffbeb", "danger": "#fef2f2", "ok": "#f0fdf4"}[kind]
    border = {"info": "#bfdbfe", "warn": "#fde68a", "danger": "#fecaca", "ok": "#bbf7d0"}[kind]
    markup = f'<font name="{_FONT_B}" color="{NAVY}">{_x(title)}</font><br/>{_x(text).replace(chr(10), "<br/>")}'
    t = Table([[Paragraph(markup, STYLES["cell"])]], colWidths=[182 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(border)),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


class _Spacer(Flowable):
    def __init__(self, h):
        super().__init__()
        self.height = h

    def wrap(self, availWidth, availHeight):
        return (0, self.height)

    def draw(self):
        pass


def _wrap_lines(c, text, font, size, max_width):
    words = text.split()
    lines, current = [], ""
    for word in words:
        candidate = (current + " " + word).strip()
        if c.stringWidth(candidate, font, size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines[:8]


def _meta_value(c, value, x, y, width, label):
    c.setFont(_FONT_B, 6)
    c.setFillColor(colors.HexColor("#8fb6dd"))
    c.drawString(x, y + 9, label.upper())
    c.setFont(_FONT, 7.2)
    c.setFillColor(WHITE)
    lines = _wrap_lines(c, _s(value), _FONT, 7.2, width)
    for i, line in enumerate(lines[:2]):
        c.drawString(x, y - i * 9, line)


def _cover(c, doc):
    W, H = A4
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#0f2a52"))
    c.circle(W - 30 * mm, H - 35 * mm, 68 * mm, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#123a6b"))
    c.circle(-25 * mm, 20 * mm, 55 * mm, fill=1, stroke=0)
    logo = _asset("logo.jpg")
    if logo:
        c.drawImage(logo, 18 * mm, H - 84 * mm, width=56 * mm, height=56 * mm, mask="auto", preserveAspectRatio=True, anchor="sw")
    c.setFont(_FONT_B, 13)
    c.setFillColor(WHITE)
    c.drawString(81 * mm, H - 44 * mm, PRODUCT)
    c.setFont(_FONT, 6.8)
    c.setFillColor(colors.HexColor("#9fd8ef"))
    for i, line in enumerate(_wrap_lines(c, TAGLINE.upper(), _FONT, 6.8, W - 98 * mm)):
        c.drawString(80 * mm, H - 50 * mm - i * 4 * mm, line)
    c.setFont(_FONT, 7.2)
    c.setFillColor(colors.HexColor("#cfe3ff"))
    for i, line in enumerate(_wrap_lines(c, "Evidence-aware AI security assessment", _FONT, 7.2, W - 98 * mm)):
        c.drawString(80 * mm, H - 62 * mm - i * 4 * mm, line)

    c.setFont(_FONT_B, 7.5)
    c.setFillColor(colors.HexColor("#7dd3fc"))
    c.drawString(18 * mm, H - 102 * mm, "AI SECURITY ASSESSMENT REPORT")

    title = _s(doc._report_model["assessment"].get("name") or "Assessment")
    c.setFont(_FONT_B, 25)
    c.setFillColor(WHITE)
    lines = _wrap_lines(c, title, _FONT_B, 25, W - 36 * mm)
    y = H - 116 * mm
    for line in lines:
        c.drawString(18 * mm, y, line)
        y -= 13 * mm

    t = doc._report_model["target"]
    subject = f"Evidence-aware assessment of {_s(t.get('provider'))} / {_s(t.get('model'))}. Findings are classified by observed evidence, not by attack name."
    c.setFont(_FONT, 9)
    c.setFillColor(colors.HexColor("#cfe3ff"))
    y -= 2 * mm
    for line in _wrap_lines(c, subject, _FONT, 9, W - 36 * mm):
        c.drawString(18 * mm, y, line)
        y -= 5 * mm

    score = doc._report_model["score"].get("overall")
    c.setFillColor(colors.HexColor("#12305c"))
    c.setStrokeColor(colors.HexColor("#3b6ea8"))
    c.roundRect(18 * mm, y - 20 * mm, 88 * mm, 17 * mm, 3 * mm, fill=1, stroke=1)
    c.setFont(_FONT_B, 24)
    c.setFillColor(colors.HexColor("#7dd3fc"))
    c.drawString(23 * mm, y - 14 * mm, "N/A" if score is None else str(score))
    c.setFont(_FONT, 6.8)
    c.setFillColor(colors.HexColor("#cfe3ff"))
    c.drawString(44 * mm, y - 10 * mm, "SECURITY SCORE / 100")
    c.drawString(44 * mm, y - 15 * mm, f"{_s(doc._report_model['score'].get('grade'))} · {'Provisional' if doc._report_model['score'].get('provisional') else 'Final'}")

    a = doc._report_model["assessment"]
    meta_y = 48 * mm
    c.setStrokeColor(colors.HexColor("#3b6ea8"))
    c.setLineWidth(0.6)
    c.line(18 * mm, meta_y + 17 * mm, W - 18 * mm, meta_y + 17 * mm)
    col_w = (W - 36 * mm) / 4
    for i, (label, value) in enumerate((
        ("Assessment ID", a.get("id")),
        ("Report", f"{doc._report_model['report_id']} v{doc._report_model['version']}"),
        ("Generated", _ts(doc._report_model["generated_at"], True)),
        ("Organization", a.get("organization")),
    )):
        _meta_value(c, value, 18 * mm + i * col_w, meta_y, col_w - 4 * mm, label)

    c.setFont(_FONT_B, 6.2)
    c.setFillColor(colors.HexColor("#8fb6dd"))
    c.drawRightString(W - 18 * mm, 18 * mm, "CONFIDENTIAL — AUTHORIZED RECIPIENTS ONLY")
    c.restoreState()


def _body_page(c, doc):
    W, H = A4
    model = doc._report_model
    c.saveState()
    c.setStrokeColor(LINE)
    c.setLineWidth(0.5)
    c.line(18 * mm, H - 15 * mm, W - 18 * mm, H - 15 * mm)
    c.setFont(_FONT_B, 7.2)
    c.setFillColor(NAVY)
    c.drawString(18 * mm, H - 11.5 * mm, f"{PRODUCT} · {COMPANY}")
    c.setFont(_FONT, 6.6)
    c.setFillColor(MUTED)
    c.drawRightString(W - 18 * mm, H - 11.5 * mm, f"{model['report_id']} v{model['version']} · {model['assessment'].get('id')}")
    c.line(18 * mm, 14 * mm, W - 18 * mm, 14 * mm)
    c.setFont(_FONT, 6.4)
    c.setFillColor(MUTED)
    c.drawString(18 * mm, 9.5 * mm, f"{PRODUCT} · {COMPANY}")
    c.drawCentredString(W / 2, 9.5 * mm, f"Generated {_ts(model['generated_at'], True)}")
    c.drawRightString(W - 18 * mm, 9.5 * mm, f"Page {doc.page}")
    c.restoreState()


def _tool_states(f: dict) -> list:
    tool = f.get("tool_execution") or {}
    out = f.get("output_security") or {}
    svc = f.get("service_impact") or {}
    story = []
    if tool.get("applicable"):
        story += [P("Tool execution states", "h4"), _kv([
            ("Proposed", _yes(tool.get("proposed"))), ("Emitted in response", _yes(tool.get("emitted"))),
            ("Authorized", _yes(tool.get("authorized"))), ("Executed", _yes(tool.get("executed"))),
            ("Execution confirmed", _yes(tool.get("execution_confirmed"))),
            ("Emitted calls", ", ".join(tool.get("emitted_calls") or []) or "None"),
            ("Evidence note", tool.get("evidence")),
        ]), Spacer(1, 3 * mm)]
    if out.get("applicable"):
        story += [P("Output security states", "h4"), _kv([
            ("Unsafe output generated", _yes(out.get("unsafe_output_generated"))),
            ("Output type", out.get("output_type") or "n/a"),
            ("Rendered", _yes(out.get("rendered"))),
            ("Script executed", _yes(out.get("script_executed"))),
            ("Data transfer observed", _yes(out.get("data_transfer_observed"))),
            ("Impact demonstrated", _yes(out.get("impact_demonstrated"))),
            ("Evidence note", out.get("notes")),
        ]), Spacer(1, 3 * mm)]
    if svc.get("applicable"):
        story += [P("Service impact states", "h4"), _kv([
            ("Requests observed", svc.get("requests_observed")), ("Timeouts", svc.get("timeouts")),
            ("Server errors", svc.get("server_errors")), ("Rate-limited responses", svc.get("rate_limited_responses")),
            ("Service impact demonstrated", _yes(svc.get("service_impact_demonstrated"))),
            ("Availability impact", svc.get("availability_impact")), ("Evidence note", svc.get("notes")),
        ]), Spacer(1, 3 * mm)]
    return story


def _matched_rules(f: dict) -> list:
    ev = f.get("evidence_validation") or {}
    rules = (ev.get("detection_rule") or {}).get("matched_rules") or (f.get("evidence") or {}).get("matched_rules") or []
    if not rules:
        return [P("No matched rule was persisted for this finding.", "small")]
    rows = [[P("Rule", "cellhdr"), P("Conf.", "cellhdr"), P("Type", "cellhdr"), P("Detail", "cellhdr")]]
    for r in rules[:8]:
        if isinstance(r, dict):
            rows.append([P(r.get("rule"), "cellmono"), P(r.get("conf"), "cell"),
                         P("soft" if r.get("soft") else "deterministic", "cell"),
                         P(r.get("detail") or r.get("note") or "", "cell")])
        else:
            rows.append([P(r, "cellmono"), P("—", "cell"), P("—", "cell"), P("—", "cell")])
    return [_table(rows, [40 * mm, 14 * mm, 26 * mm, 102 * mm])]


def _transcript(f: dict) -> list:
    tr = f.get("transcript") or {}
    story = []
    if tr.get("system"):
        story.append(_callout("System prompt (redacted, may be harness default)", tr.get("system")))
    for m in (tr.get("messages") or [])[:8]:
        label = str(m.get("role") or "user").title()
        story.append(_callout(label, m.get("content") or ""))
        story.append(Spacer(1, 1.5 * mm))
    for i, r in enumerate((tr.get("responses") or [])[:6], 1):
        meta = f"status={r.get('status')} · latency={r.get('latency_ms')} ms"
        body = str(r.get("text") or "(no text)")
        for call in (r.get("tool_calls") or []):
            body += f"\n-> {call.get('name')}({call.get('arguments')})"
        if r.get("error"):
            body += f"\nERROR: {r.get('error')}"
        story.append(_callout(f"Model response {i} · {meta}", body, "warn" if r.get("status") not in (None, "ok") else "info"))
        story.append(Spacer(1, 1.5 * mm))
    if not story:
        story.append(P("No transcript was persisted.", "small"))
    return story


def _finding(f: dict, idx: int) -> list:
    cls = f.get("classification") or {}
    code = f.get("classification_code") or "inconclusive"
    ev = f.get("evidence_validation") or {}
    color = CLASS_COLOR.get(code, "#64748b")
    bg = CLASS_BG.get(code, "#f1f5f9")
    sev = f.get("severity") or "info"
    head = R(
        f'<font name="{_FONT_B}" size="8" color="{color}">{_x(f.get("classification_label"))}</font>'
        f' <font name="{_FONT_B}" size="7" color="{SEV_COLOR.get(sev, "#64748b")}">[{_x(str(sev).upper())}]</font>'
        f' <font name="{_FONT_B}" size="11" color="{NAVY}">{idx}. {_x(f.get("title"))}</font>'
        f' <font name="Courier" size="6.6" color="#64748b"> {_x(f.get("finding_id"))}</font>',
        "body",
    )
    facts = [
        ("Test ID", f.get("attack_id")), ("Category", f.get("category_label")),
        ("Effective severity", f.get("severity")), ("Potential severity", f.get("potential_severity")),
        ("Confidence", _pct(f.get("confidence"))), ("Validation", (cls.get("validation_status") or "needs_review").replace("_", " ")),
        ("Evidence quality", cls.get("evidence_quality")), ("Impact scope", cls.get("impact_scope")),
        ("Detected at (UTC)", _ts(f.get("detected_at"))), ("Status / triage", f"{f.get('status')} / {f.get('triage')}"),
        ("Target", ev.get("target_model")), ("Provider", ev.get("provider")),
    ]
    fact_rows = []
    for i in range(0, len(facts), 2):
        pair = facts[i:i + 2]
        row = []
        for k, v in pair:
            row += [P(k, "cellb"), P(v, "cell")]
        if len(row) < 4:
            row += [P("", "cell"), P("", "cell")]
        fact_rows.append(row)
    fact_table = _table(fact_rows, [24 * mm, 67 * mm, 24 * mm, 67 * mm], header=False, grid=True)
    fact_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f9fd")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f7f9fd")),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story = [CondPageBreak(70 * mm), _hr(0, 3), head, Spacer(1, 2 * mm), fact_table, Spacer(1, 2 * mm)]
    story.append(P("Observed behaviour. " + (ev.get("actual_behavior") or "No actual behaviour was recorded.")))
    exp = ev.get("expected_behavior") or ""
    rat = cls.get("rationale") or ""
    try:
        story.append(Table([[P("Expected secure behaviour", "cellb"), P("Classification rationale", "cellb")],
                            [P(exp, "cell"), P(rat, "cell")]], colWidths=[91 * mm, 91 * mm], style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5fb")),
            ("BOX", (0, 0), (-1, -1), 0.4, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3)])))
    except Exception:
        story += [P("Expected: " + exp), P("Rationale: " + rat)]
    story.append(Spacer(1, 1.5 * mm))
    story.append(P("Severity basis. " + (f.get("severity_basis") or ""), "small"))
    cv = f.get("cvss")
    if cv:
        story.append(_callout(f"CVSS {cv.get('score')} · {cv.get('vector')}", cv.get("basis") or "", "info"))
    else:
        story.append(_callout("CVSS not assigned", f.get("cvss_suppressed_reason") or "No defensible CVSS score could be derived from the available evidence.", "warn"))
    story.append(Spacer(1, 2 * mm))
    story.append(P("Detection evidence", "h4"))
    det = f.get("detection") or {}
    story.append(P("Method: " + str(det.get("method") or (ev.get("detection_rule") or {}).get("method") or "n/a"), "small"))
    story.append(P("Reason: " + str(det.get("reason") or (ev.get("detection_rule") or {}).get("reason") or "n/a"), "small"))
    story += _matched_rules(f)
    story += _tool_states(f)
    story.append(P("Procedure and redacted evidence", "h4"))
    story += _transcript(f)
    story.append(P("Reproduction steps", "h4"))
    steps = f.get("reproduction_steps") or []
    if steps:
        for i, s in enumerate(steps, 1):
            story.append(Paragraph(f"<b>{i}.</b> {_x(s)}", STYLES["bullet"]))
    else:
        story.append(P("No reproduction steps were persisted.", "small"))
    story.append(P("Remediation", "h4"))
    story.append(P(f.get("remediation") or "No remediation guidance was recorded."))
    story.append(P("Evidence limitations specific to this finding", "h4"))
    lims = ev.get("limitations") or ["Evidence is limited to the model/API boundary."]
    for lim in lims:
        story.append(Paragraph("• " + _x(lim), STYLES["bullet"]))
    story.append(P("Evidence SHA-256: " + str(f.get("evidence_sha256") or "not available for legacy record"), "mono_small"))
    return story


def _front(model: dict) -> list:
    a, t, sc, sm, st = model["assessment"], model["target"], model["score"], model["summary"], model["statistics"]
    story = []
    story += _section("01", "Executive summary")
    overall = sc.get("overall")
    score_line = f"Security score: {overall if overall is not None else 'N/A'} / 100 · {sc.get('grade')} · {'Provisional' if sc.get('provisional') else 'Final'} · Coverage {_pct(sc.get('coverage'))}"
    story.append(_callout(score_line, sm["posture"], "ok" if (overall or 0) >= 75 else "warn" if (overall or 0) >= 50 else "danger"))
    story.append(Spacer(1, 2 * mm))
    story.append(P("Key points", "h4"))
    for point in sm["key_points"]:
        story.append(Paragraph("• " + _x(point), STYLES["bullet"]))
    story.append(Spacer(1, 2 * mm))
    counts = st["classifications"]
    rows = [[P("Classification", "cellhdr"), P("Count", "cellhdr"), P("Meaning", "cellhdr")]]
    for code in ("confirmed_vulnerability", "likely_vulnerability", "unsafe_behavior", "potential_vulnerability", "inconclusive", "false_positive"):
        tx = {x["code"]: x for x in model["taxonomy"]}[code]
        rows.append([P(tx["label"], "cellb"), P(counts[code], "cell"), P(tx["definition"], "cell")])
    story.append(_table(rows, [40 * mm, 14 * mm, 128 * mm]))
    story.append(P("Stored score reconciliation: " + model["score_reconciliation"]["note"], "small"))
    if sm.get("recorded_narrative"):
        story.append(_callout("Recorded narrative (context only)", sm["recorded_narrative"], "warn"))

    story += _section("02", "Scope and limitations")
    story.append(P("In scope", "h4"))
    for x in model["scope"]["in_scope"]:
        story.append(Paragraph("• " + _x(x), STYLES["bullet"]))
    story.append(P("Out of scope", "h4"))
    for x in model["scope"]["out_of_scope"]:
        story.append(Paragraph("• " + _x(x), STYLES["bullet"]))
    story.append(P("Authorization", "h4"))
    story.append(_kv([
        ("Authorization confirmed", _yes(a.get("authorization_confirmed"))),
        ("Endpoint owner confirmed", _yes(a.get("endpoint_owner_confirmed"))),
        ("Statement", a.get("authorization_statement") or "Not recorded"),
    ]))
    story.append(P("Limitations", "h4"))
    for x in model["scope"]["limitations"]:
        story.append(Paragraph("• " + _x(x), STYLES["bullet"]))

    story += _section("03", "Target configuration")
    story.append(_kv([
        ("Provider", t.get("provider")), ("Model", t.get("model")),
        ("Endpoint", t.get("endpoint") or "Provider default"), ("Intensity profile", t.get("intensity")),
        ("Request budget", (t.get("limits") or {}).get("max_requests")),
        ("Max retries", (t.get("limits") or {}).get("retries")),
        ("System prompt", "Configured — content intentionally not reproduced" if t.get("system_prompt_configured") else "Harness default"),
        ("AI-assisted analysis", _yes(t.get("ai_analysis"))),
        ("Parameters", ", ".join(f"{k}={v}" for k, v in (t.get("params") or {}).items()) or "Provider defaults"),
    ]))

    story += _section("04", "Assessment methodology")
    story.append(P(model["methodology"]["description"]))
    rows = [[P("Phase", "cellhdr"), P("What happens", "cellhdr")]]
    for p in model["methodology"]["phases"]:
        rows.append([P(p["phase"], "cellb"), P(p["detail"], "cell")])
    story.append(_table(rows, [38 * mm, 144 * mm]))
    story.append(P("Detection layers", "h4"))
    rows = [[P("Layer", "cellhdr"), P("Use in this assessment", "cellhdr")]]
    for d in model["methodology"]["detection"]:
        rows.append([P(d["method"], "cellb"), P(d["use"], "cell")])
    story.append(_table(rows, [60 * mm, 122 * mm]))

    story += _section("05", "Finding classification")
    story.append(P("A detector firing is an observation. A vulnerability claim requires evidence that supports the specific impact. The six classifications below are used consistently across every finding, score and export."))
    rows = [[P("Classification", "cellhdr"), P("Definition", "cellhdr"), P("CVSS policy", "cellhdr"), P("Factor", "cellhdr")]]
    for tx in model["taxonomy"]:
        rows.append([P(tx["label"], "cellb"), P(tx["definition"], "cell"), P(tx["cvss_policy"], "cell"), P(f'{tx["score_factor"]:.2f}', "cell")])
    story.append(_table(rows, [34 * mm, 65 * mm, 71 * mm, 12 * mm]))

    story += _section("06", "Vulnerability statistics and risk overview")
    rows = [[P("Severity", "cellhdr"), P("Validated findings", "cellhdr"), P("Count", "cellhdr")]]
    for s in ("critical", "high", "medium", "low", "info"):
        rows.append([P(s.title(), "cellb"), P("", "cell"), P(st["severity"][s], "cell")])
    story.append(P("Effective severity of validated findings", "h4"))
    story.append(_table(rows, [50 * mm, 100 * mm, 32 * mm]))
    story.append(P("Test execution summary", "h4"))
    test = st["tests"]
    story.append(_kv([
        ("Selected", test["total"]), ("Passed", test["passed"]),
        ("Failed (indicator observed)", test["failed"]), ("Inconclusive", test["inconclusive"]),
        ("Not tested / error", test["skipped"] + test["not_started"] + test["error"]),
        ("Coverage", _pct(sc.get("coverage"))),
    ]))
    story.append(P("Security score by category", "h4"))
    rows = [[P("Category", "cellhdr"), P("Score", "cellhdr"), P("Selected", "cellhdr"), P("Tested", "cellhdr"), P("Passed", "cellhdr"), P("Failed", "cellhdr"), P("Inconclusive", "cellhdr"), P("Not tested", "cellhdr")]]
    for c in model["category_scores"]:
        rows.append([P(c["label"], "cellb"), P("N/A" if c["score"] is None else c["score"], "cell"), P(c["selected"], "cell"),
                     P(c["tested"], "cell"), P(c["passed"], "cell"), P(c["failed"], "cell"), P(c["inconclusive"], "cell"), P(c["not_tested"], "cell")])
    story.append(_table(rows, [52 * mm, 16 * mm, 18 * mm, 16 * mm, 16 * mm, 16 * mm, 22 * mm, 26 * mm]))
    story.append(P("A category score of N/A means no test in that category produced a pass/fail result. Untested categories are not treated as secure.", "small"))
    return story


def _inventory(model: dict) -> list:
    story = _section("07", "Detailed findings")
    findings = model["findings"]
    if not findings:
        story.append(_callout("No findings recorded", "No findings were recorded by the executed tests. This is not a statement that the system is free of vulnerabilities. Untested modules and application integration remain outside the evidence base.", "info"))
    for i, f in enumerate(findings, 1):
        story += _finding(f, i)
        story.append(Spacer(1, 4 * mm))
    story += _section("08", "Test inventory")
    story.append(P("Every selected test is listed. 'Not tested' is never reported as secure. Timestamps are UTC."))
    rows = [[P("Test ID", "cellhdr"), P("Test", "cellhdr"), P("Result", "cellhdr"), P("Classification", "cellhdr"),
             P("Conf.", "cellhdr"), P("Finding", "cellhdr"), P("Started / finished", "cellhdr"), P("ms", "cellhdr")]]
    for t in model["tests"]:
        rows.append([
            P(t.get("test_id"), "cellmono"),
            P(f"{t.get('name')}\n{t.get('category_label')}", "cell"),
            P(f"{t.get('result')}" + (f"\n{t.get('reason')}" if t.get("reason") else ""), "cell"),
            P(t.get("classification_label") or "—", "cell"),
            P(_pct(t.get("confidence")) if t.get("confidence") is not None else "—", "cell"),
            P(t.get("finding_id") or "—", "cellmono"),
            P(f"{_ts(t.get('started_at'))}\n{_ts(t.get('finished_at'))}", "tiny"),
            P(t.get("duration_ms") if t.get("duration_ms") is not None else "—", "cell"),
        ])
    story.append(_table(rows, [18 * mm, 43 * mm, 29 * mm, 22 * mm, 11 * mm, 18 * mm, 30 * mm, 11 * mm]))
    return story


def _back(model: dict) -> list:
    st = model["statistics"]
    story = _section("09", "Risk analysis and remediation recommendations")
    rows = [[P("Priority", "cellhdr"), P("Window", "cellhdr"), P("Classification", "cellhdr"), P("Count", "cellhdr"), P("Required action", "cellhdr")]]
    for r in model["risk_analysis"]["roadmap"]:
        rows.append([P(r["priority"], "cellb"), P(r["window"], "cell"), P(r["label"], "cell"), P(r["count"], "cell"), P(r["action"], "cell")])
    if len(rows) == 1:
        rows.append([P("—", "cell"), P("—", "cell"), P("No findings", "cell"), P("0", "cell"), P("No remediation action is required for the executed tests.", "cell")])
    story.append(_table(rows, [17 * mm, 18 * mm, 42 * mm, 12 * mm, 93 * mm]))
    story.append(P("Finding-specific remediation", "h4"))
    rows = [[P("Finding", "cellhdr"), P("Title", "cellhdr"), P("Remediation", "cellhdr")]]
    for f in model["findings"]:
        if f["classification_code"] == "false_positive":
            continue
        rows.append([P(f["finding_id"], "cellmono"), P(f["title"], "cell"), P(f["remediation"], "cell")])
    if len(rows) == 1:
        rows.append([P("—", "cell"), P("—", "cell"), P("No remediation required for executed tests.", "cell")])
    story.append(_table(rows, [20 * mm, 40 * mm, 122 * mm]))

    story += _section("10", "Conclusion")
    story.append(P(model["summary"]["posture"]))
    for line in (
        f"Confirmed vulnerabilities: {st['classifications']['confirmed_vulnerability']}. Confirmed findings require remediation and verification before release.",
        f"Likely vulnerabilities: {st['classifications']['likely_vulnerability']}. Reproduce and triage; heuristic evidence is not a confirmed exploit.",
        f"Unsafe behaviour and potential vulnerabilities: {st['classifications']['unsafe_behavior'] + st['classifications']['potential_vulnerability']}. Integration testing is required before claiming application impact.",
        f"Inconclusive and false positives: {st['classifications']['inconclusive'] + st['classifications']['false_positive']}. Retained for audit and excluded from validated risk.",
        f"Coverage: {_pct(model['score'].get('coverage'))} ({st['tests']['passed'] + st['tests']['failed']} pass/fail results out of {st['tests']['total']} selected tests).",
    ):
        story.append(Paragraph("• " + _x(line), STYLES["bullet"]))
    story.append(Spacer(1, 5 * mm))
    story.append(_callout("Report sign-off", f"{COMPANY} · {PRODUCT}. This report was generated from persisted assessment records. The JSON export and its SHA-256 manifest are the canonical evidence record. Re-test after remediation or material configuration change.", "info"))

    story += _section("11", "Appendix")
    story.append(P("Evidence integrity hashes", "h4"))
    rows = [[P("Finding", "cellhdr"), P("Evidence SHA-256", "cellhdr")]]
    for h in model["integrity"].get("evidence_hashes", []):
        rows.append([P(h["finding_id"], "cellmono"), P(h["evidence_sha256"], "cellmono")])
    if len(rows) == 1:
        rows.append([P("—", "cell"), P("No evidence hashes were recorded.", "cell")])
    story.append(_table(rows, [28 * mm, 154 * mm], repeat=True))
    story.append(Spacer(1, 2 * mm))
    story.append(_kv([
        ("Manifest SHA-256", model["integrity"]["manifest_sha256"]),
        ("Algorithm", model["integrity"]["algorithm"]),
        ("Integrity note", model["integrity"]["note"]),
        ("Scoring weights", ", ".join(f"{k}={v}" for k, v in model["appendix"]["scoring_weights"].items())),
        ("Report generated by", f"{COMPANY} — {PRODUCT}"),
    ]))
    story.append(P("Glossary", "h4"))
    rows = [[P("Term", "cellhdr"), P("Definition", "cellhdr")]]
    for k, v in model["appendix"]["glossary"]:
        rows.append([P(k, "cellb"), P(v, "cell")])
    story.append(_table(rows, [32 * mm, 150 * mm]))
    return story


def render_pdf(model: dict) -> bytes:
    buf = io.BytesIO()
    a = model["assessment"]
    doc = BaseDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm, bottomMargin=18 * mm,
        title=f"{PRODUCT} report — {a.get('name')}", author=COMPANY, subject=TAGLINE, creator=f"{COMPANY} {PRODUCT}",
        keywords="AI security assessment, LLM, evidence-aware reporting, ZeroDay",
    )
    doc._report_model = model
    cover_frame = Frame(18 * mm, 18 * mm, A4[0] - 36 * mm, A4[1] - 36 * mm, id="cover", showBoundary=0)
    body_frame = Frame(18 * mm, 18 * mm, A4[0] - 36 * mm, A4[1] - 40 * mm, id="body", showBoundary=0)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_cover),
        PageTemplate(id="body", frames=[body_frame], onPage=_body_page),
    ])
    story = [NextPageTemplate("body"), Spacer(1, 1), PageBreak()]
    story += _front(model)
    story += _inventory(model)
    story += _back(model)
    doc.build(story)
    return buf.getvalue()
