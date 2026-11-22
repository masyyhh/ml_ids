#!/usr/bin/env python3
"""Convert Markdown Capstone Project Report to a styled Microsoft Word (.docx) document."""

import re
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    """Set the background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner cell padding in dxa."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def add_styled_paragraph(doc, text, style='Normal', space_after=4, space_before=0, align=WD_ALIGN_PARAGRAPH.LEFT):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.line_spacing = 1.15

    # Parse inline formatting: **bold**, *italic*, `code`, and plain text
    # Regex splits by tokens while keeping delimiters
    tokens = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`|\$\$.*?\$\$|\$.*?\$)', text)
    for token in tokens:
        if not token:
            continue
        if token.startswith('**') and token.endswith('**') and len(token) >= 4:
            run = p.add_run(token[2:-2])
            run.bold = True
        elif token.startswith('*') and token.endswith('*') and len(token) >= 2:
            run = p.add_run(token[1:-1])
            run.italic = True
        elif token.startswith('`') and token.endswith('`') and len(token) >= 2:
            run = p.add_run(token[1:-1])
            run.font.name = 'Consolas'
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(180, 40, 60)
        elif token.startswith('$') and token.endswith('$'):
            content = token.strip('$')
            run = p.add_run(content)
            run.font.name = 'Cambria Math'
            run.italic = True
        else:
            p.add_run(token)
    return p

def convert_md_to_docx(md_path: Path, docx_path: Path):
    doc = Document()

    # Set page margins (1 inch)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Set base font
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(11)
    style_normal.font.color.rgb = RGBColor(35, 39, 42)

    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False
    code_block_lines = []
    in_table = False
    table_lines = []

    def flush_table():
        nonlocal in_table, table_lines
        if not table_lines:
            return
        
        # Parse markdown table
        rows_data = []
        for tl in table_lines:
            stripped = tl.strip()
            if not stripped.startswith('|'):
                continue
            cells = [c.strip() for c in stripped.strip('|').split('|')]
            # Check if separator row (e.g. :--- | :---)
            if all(re.match(r'^:?-+:?$', c) for c in cells if c):
                continue
            rows_data.append(cells)

        if rows_data:
            num_cols = max(len(r) for r in rows_data)
            # Normalize row lengths
            for r in rows_data:
                while len(r) < num_cols:
                    r.append('')
            
            table = doc.add_table(rows=len(rows_data), cols=num_cols)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            table.autofit = True

            for r_idx, row in enumerate(rows_data):
                is_header = (r_idx == 0)
                for c_idx, cell_value in enumerate(row):
                    cell = table.cell(r_idx, c_idx)
                    cell.text = ''
                    p = cell.paragraphs[0]
                    p.paragraph_format.space_after = Pt(2)
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.line_spacing = 1.05

                    tokens = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`|\$.*?\$)', cell_value)
                    for token in tokens:
                        if not token:
                            continue
                        if token.startswith('**') and token.endswith('**'):
                            run = p.add_run(token[2:-2])
                            run.bold = True
                        elif token.startswith('*') and token.endswith('*'):
                            run = p.add_run(token[1:-1])
                            run.italic = True
                        elif token.startswith('`') and token.endswith('`'):
                            run = p.add_run(token[1:-1])
                            run.font.name = 'Consolas'
                            run.font.size = Pt(9)
                        elif token.startswith('$') and token.endswith('$'):
                            run = p.add_run(token.strip('$'))
                            run.font.name = 'Cambria Math'
                            run.italic = True
                        else:
                            p.add_run(token)

                    if is_header:
                        for run in p.runs:
                            run.bold = True
                            run.font.color.rgb = RGBColor(255, 255, 255)
                        set_cell_background(cell, '1E293B') # Dark slate header
                    else:
                        bg_hex = 'F8FAFC' if r_idx % 2 == 1 else 'FFFFFF'
                        set_cell_background(cell, bg_hex)
                    
                    set_cell_margins(cell, top=80, bottom=80, left=120, right=120)

            # Add space after table
            p_after = doc.add_paragraph()
            p_after.paragraph_format.space_after = Pt(6)

        table_lines = []
        in_table = False

    def flush_code_block():
        nonlocal in_code_block, code_block_lines
        if not code_block_lines:
            return
        
        block_text = "".join(code_block_lines).strip()
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        set_cell_background(cell, '0F172A') # Dark background
        set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
        cell.text = ''
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.line_spacing = 1.05
        run = p.add_run(block_text)
        run.font.name = 'Consolas'
        run.font.size = Pt(8.5)
        run.font.color.rgb = RGBColor(226, 232, 240)

        p_after = doc.add_paragraph()
        p_after.paragraph_format.space_after = Pt(6)

        code_block_lines = []
        in_code_block = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Handle code blocks (e.g. ```mermaid or ```)
        if stripped.startswith('```'):
            if in_code_block:
                flush_code_block()
            else:
                if in_table:
                    flush_table()
                in_code_block = True
                code_block_lines = []
            i += 1
            continue

        if in_code_block:
            code_block_lines.append(line)
            i += 1
            continue

        # Handle markdown tables
        if stripped.startswith('|') and stripped.endswith('|'):
            if not in_table:
                in_table = True
                table_lines = [line]
            else:
                table_lines.append(line)
            i += 1
            continue
        elif in_table:
            flush_table()

        # Handle empty lines
        if not stripped:
            i += 1
            continue

        # Horizontal rules
        if stripped in ('---', '***', '___'):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(8)
            p_border = parse_xml(f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="8" w:space="4" w:color="CBD5E1"/></w:pBdr>')
            p._p.get_or_add_pPr().append(p_border)
            i += 1
            continue

        # Headings
        if stripped.startswith('# '):
            h_text = stripped[2:].strip()
            add_styled_paragraph(doc, h_text, style='Heading 1', space_after=6, space_before=14)
        elif stripped.startswith('## '):
            h_text = stripped[3:].strip()
            add_styled_paragraph(doc, h_text, style='Heading 2', space_after=5, space_before=10)
        elif stripped.startswith('### '):
            h_text = stripped[4:].strip()
            add_styled_paragraph(doc, h_text, style='Heading 3', space_after=4, space_before=8)
        elif stripped.startswith('#### '):
            h_text = stripped[5:].strip()
            add_styled_paragraph(doc, h_text, style='Heading 4', space_after=3, space_before=6)
        # Bullet list items
        elif stripped.startswith(('- ', '* ')):
            item_text = stripped[2:].strip()
            add_styled_paragraph(doc, item_text, style='List Bullet', space_after=2, space_before=0)
        # Numbered list items
        elif re.match(r'^\d+\.\s+', stripped):
            num_match = re.match(r'^\d+\.\s+', stripped)
            item_text = stripped[num_match.end():].strip()
            p = add_styled_paragraph(doc, f"{num_match.group(0).strip()}  {item_text}", style='Normal', space_after=2, space_before=0)
            p.paragraph_format.left_indent = Inches(0.25)
        # Blockquotes
        elif stripped.startswith('> '):
            quote_text = stripped[2:].strip()
            p = add_styled_paragraph(doc, quote_text, style='Normal', space_after=4, space_before=4)
            p.paragraph_format.left_indent = Inches(0.4)
            p.runs[0].italic = True if p.runs else False
        else:
            # Regular paragraph
            add_styled_paragraph(doc, stripped, style='Normal', space_after=5, space_before=0)

        i += 1

    if in_table:
        flush_table()
    if in_code_block:
        flush_code_block()

    # Apply typography polish to Headings
    h1_style = doc.styles['Heading 1']
    h1_style.font.name = 'Calibri'
    h1_style.font.size = Pt(18)
    h1_style.font.bold = True
    h1_style.font.color.rgb = RGBColor(15, 23, 42)

    h2_style = doc.styles['Heading 2']
    h2_style.font.name = 'Calibri'
    h2_style.font.size = Pt(14)
    h2_style.font.bold = True
    h2_style.font.color.rgb = RGBColor(30, 41, 59)

    h3_style = doc.styles['Heading 3']
    h3_style.font.name = 'Calibri'
    h3_style.font.size = Pt(12)
    h3_style.font.bold = True
    h3_style.font.color.rgb = RGBColor(51, 65, 85)

    doc.save(str(docx_path))
    print(f"Successfully generated: {docx_path}")

if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    in_file = root / 'IT3005_Capstone_Project_Report.md'
    out_file = root / 'IT3005_Capstone_Project_Report.docx'
    convert_md_to_docx(in_file, out_file)
