"""Deterministic PDF rendering helpers (reportlab, invariant mode: identical input gives identical bytes).

Page streams are left uncompressed so reviewers and leak tests can inspect text directly.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


@dataclass
class Section:
    heading: str
    paragraphs: list[str] = field(default_factory=list)
    table: list[list[str]] | None = None
    col_widths: list[float] | None = None
    page_break_before: bool = False


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=17, leading=21),
        "sub": ParagraphStyle("s", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#444444")),
        "h": ParagraphStyle("h", parent=ss["Heading2"], fontSize=12.5, leading=16, spaceBefore=8),
        "p": ParagraphStyle("p", parent=ss["BodyText"], fontSize=9.5, leading=13),
        "cell": ParagraphStyle("c", parent=ss["BodyText"], fontSize=8, leading=10),
    }


def render(title: str, subtitle_lines: list[str], sections: list[Section], *, footer: str = "") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, invariant=1, pageCompression=0, title=title, author="Tripline Scope",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    st = _styles()
    flow = [Paragraph(escape(title), st["title"])]
    for line in subtitle_lines:
        flow.append(Paragraph(escape(line), st["sub"]))
    flow.append(Spacer(1, 6 * mm))
    for s in sections:
        if s.page_break_before:
            flow.append(PageBreak())
        flow.append(Paragraph(escape(s.heading), st["h"]))
        for p in s.paragraphs:
            flow.append(Paragraph(escape(p), st["p"]))
            flow.append(Spacer(1, 1.5 * mm))
        if s.table:
            data = [[Paragraph(escape(str(c)), st["cell"]) for c in row] for row in s.table]
            t = Table(data, colWidths=s.col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8ECF1")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9AA5B1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            flow.append(t)
            flow.append(Spacer(1, 3 * mm))

    def _footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18 * mm, 9 * mm, footer[:150])
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"page {d.page}")
        canvas.restoreState()

    doc.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def pdf_text(data: bytes) -> str:
    """Best-effort text extraction (for tests): decompresses Flate streams and returns all bytes as latin-1."""
    import re
    import zlib

    out = [data.decode("latin-1")]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        chunk = m.group(1)
        try:
            out.append(zlib.decompress(chunk).decode("latin-1"))
        except zlib.error:
            out.append(chunk.decode("latin-1"))
    return "\n".join(out)
