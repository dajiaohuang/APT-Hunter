"""
Converts the LLM-drafted incident report (Markdown) into a formatted Word
document. Supports the common subset of Markdown the report prompt asks the
model to use: level 1-4 headings, bullet/numbered lists, horizontal rules,
and inline **bold**/*italic* — enough to render a professional-looking
report without pulling in an external converter (e.g. pandoc).
"""
import io
import re

from docx import Document
from docx.shared import Pt

INLINE_RE = re.compile(r'(\*\*.+?\*\*|\*.+?\*|_.+?_)')
HEADING_RE = re.compile(r'^(#{1,4})\s+(.*)')
BULLET_RE = re.compile(r'^[-*]\s+(.*)')
NUMBERED_RE = re.compile(r'^\d+\.\s+(.*)')
HR_RE = re.compile(r'^-{3,}$')


def _add_inline_runs(paragraph, text):
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith('**') and part.endswith('**') and len(part) > 3:
            paragraph.add_run(part[2:-2]).bold = True
        elif len(part) > 1 and ((part[0] == '*' and part[-1] == '*') or (part[0] == '_' and part[-1] == '_')):
            paragraph.add_run(part[1:-1]).italic = True
        else:
            paragraph.add_run(part)


def markdown_to_docx_bytes(markdown_text, title=None, subtitle=None):
    doc = Document()

    style = doc.styles['Normal']
    style.font.name = 'Calibri'
    style.font.size = Pt(11)

    if title:
        doc.add_heading(title, level=0)
    if subtitle:
        p = doc.add_paragraph()
        run = p.add_run(subtitle)
        run.italic = True
        run.font.size = Pt(10)

    for raw_line in (markdown_text or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        heading_match = HEADING_RE.match(line)
        if heading_match:
            level = min(len(heading_match.group(1)), 4)
            doc.add_heading(heading_match.group(2).strip(), level=level)
            continue

        if HR_RE.match(line):
            continue

        bullet_match = BULLET_RE.match(line)
        if bullet_match:
            p = doc.add_paragraph(style='List Bullet')
            _add_inline_runs(p, bullet_match.group(1))
            continue

        numbered_match = NUMBERED_RE.match(line)
        if numbered_match:
            p = doc.add_paragraph(style='List Number')
            _add_inline_runs(p, numbered_match.group(1))
            continue

        p = doc.add_paragraph()
        _add_inline_runs(p, line)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf
