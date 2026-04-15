"""
PDF Report Generator — Hebrew RTL using reportlab.

Requires:
  pip install reportlab arabic-reshaper python-bidi

Falls back to an English-only PDF if Hebrew support libs are missing.
"""
from io import BytesIO
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, PageBreak, HRFlowable,
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.enums import TA_RIGHT, TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

import os

# Try Hebrew text processing
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    BIDI_AVAILABLE = True
except ImportError:
    BIDI_AVAILABLE = False


# -----------------------------------------------------------------------
# Font registration
# -----------------------------------------------------------------------

_FONT_REGISTERED = False
_FONT_NAME = 'NotoHebrew'
_FALLBACK_FONT = 'Helvetica'

def _register_hebrew_font():
    global _FONT_REGISTERED, _FONT_NAME
    if _FONT_REGISTERED:
        return

    # Look for font in several locations
    font_candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     'static', 'fonts', 'NotoSansHebrew-Regular.ttf'),
        r'C:\Windows\Fonts\arial.ttf',
        r'C:\Windows\Fonts\David.ttf',
    ]

    for font_path in font_candidates:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont(_FONT_NAME, font_path))
                _FONT_REGISTERED = True
                return
            except Exception:
                continue

    # No Hebrew font found — use built-in (will not render Hebrew correctly
    # but won't crash)
    _FONT_NAME = _FALLBACK_FONT
    _FONT_REGISTERED = True


def _heb(text: str) -> str:
    """Apply BiDi reshaping for correct Hebrew rendering in PDF."""
    if not text:
        return ''
    if BIDI_AVAILABLE:
        try:
            reshaped = arabic_reshaper.reshape(str(text))
            return get_display(reshaped)
        except Exception:
            pass
    return str(text)


# -----------------------------------------------------------------------
# Color palette
# -----------------------------------------------------------------------

DARK_BLUE    = colors.HexColor('#1F4E79')
MID_BLUE     = colors.HexColor('#2E75B6')
LIGHT_BLUE   = colors.HexColor('#BDD7EE')
LIGHT_GREY   = colors.HexColor('#F2F2F2')
RED          = colors.HexColor('#FF0000')
ORANGE       = colors.HexColor('#FF6600')
YELLOW       = colors.HexColor('#FFCC00')
GREEN        = colors.HexColor('#92D050')
WHITE        = colors.white
BLACK        = colors.black


# -----------------------------------------------------------------------
# Styles
# -----------------------------------------------------------------------

def _make_styles():
    _register_hebrew_font()
    fn = _FONT_NAME

    title_style = ParagraphStyle(
        'Hebrew-Title',
        fontName=fn, fontSize=22, leading=28,
        alignment=TA_CENTER, textColor=DARK_BLUE,
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        'Hebrew-Heading',
        fontName=fn, fontSize=14, leading=18,
        alignment=TA_RIGHT, textColor=DARK_BLUE,
        spaceBefore=12, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        'Hebrew-Body',
        fontName=fn, fontSize=10, leading=14,
        alignment=TA_RIGHT, textColor=BLACK,
    )
    small_style = ParagraphStyle(
        'Hebrew-Small',
        fontName=fn, fontSize=8, leading=10,
        alignment=TA_RIGHT, textColor=colors.HexColor('#555555'),
    )
    return title_style, heading_style, body_style, small_style


# -----------------------------------------------------------------------
# Table helpers
# -----------------------------------------------------------------------

def _header_style(table, num_cols: int):
    return TableStyle([
        ('BACKGROUND',    (0, 0), (num_cols - 1, 0), DARK_BLUE),
        ('TEXTCOLOR',     (0, 0), (num_cols - 1, 0), WHITE),
        ('FONTNAME',      (0, 0), (num_cols - 1, 0), _FONT_NAME),
        ('FONTSIZE',      (0, 0), (num_cols - 1, 0), 9),
        ('ALIGN',         (0, 0), (-1, -1), 'RIGHT'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
        ('FONTNAME',      (0, 1), (-1, -1), _FONT_NAME),
        ('FONTSIZE',      (0, 1), (-1, -1), 8),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#BFBFBF')),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
    ])


# -----------------------------------------------------------------------
# Cover page
# -----------------------------------------------------------------------

def _build_cover(story, assets: list, meta: dict, styles):
    title_s, heading_s, body_s, small_s = styles

    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph(_heb('דוח מלאי נכסי רשת ארגוני'), title_s))
    story.append(HRFlowable(width='100%', thickness=2, color=DARK_BLUE))
    story.append(Spacer(1, 0.5 * cm))

    # Summary stats table
    total = len(assets)
    alive = sum(1 for a in assets if a.get('is_alive'))
    os_counts = {}
    type_counts = {}
    critical_total = sum(a.get('critical_ports', 0) for a in assets)

    for a in assets:
        os_counts[a.get('os_family') or _heb('לא ידוע')] = \
            os_counts.get(a.get('os_family') or _heb('לא ידוע'), 0) + 1
        type_counts[a.get('asset_type') or _heb('לא ידוע')] = \
            type_counts.get(a.get('asset_type') or _heb('לא ידוע'), 0) + 1

    story.append(Spacer(1, 0.8 * cm))
    cover_data = [
        [_heb('פרמטר'), _heb('ערך')],
        [_heb('Subnet / Target'), meta.get('target', '')],
        [_heb('תאריך סריקה'), meta.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M'))],
        [_heb('משך סריקה'), meta.get('duration', '')],
        [_heb('סה"כ נכסים מזוהים'), str(total)],
        [_heb('נכסים פעילים'), str(alive)],
        [_heb('ממצאים קריטיים'), str(critical_total)],
    ]
    t = Table(cover_data, colWidths=[8 * cm, 10 * cm])
    t.setStyle(_header_style(t, 2))
    story.append(t)

    # OS breakdown
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(_heb('התפלגות לפי מערכת הפעלה'), heading_s))
    os_data = [[_heb('משפחת OS'), _heb('כמות'), _heb('%')]]
    for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
        pct = f'{100 * count / total:.1f}%' if total else '0%'
        os_data.append([_heb(os_name), str(count), pct])
    t2 = Table(os_data, colWidths=[8 * cm, 5 * cm, 5 * cm])
    t2.setStyle(_header_style(t2, 3))
    story.append(t2)

    # Asset type breakdown
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(_heb('התפלגות לפי סוג נכס'), heading_s))
    type_data = [[_heb('סוג נכס'), _heb('כמות'), _heb('%')]]
    for t_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        pct = f'{100 * count / total:.1f}%' if total else '0%'
        type_data.append([_heb(t_name), str(count), pct])
    t3 = Table(type_data, colWidths=[8 * cm, 5 * cm, 5 * cm])
    t3.setStyle(_header_style(t3, 3))
    story.append(t3)

    story.append(PageBreak())


# -----------------------------------------------------------------------
# Asset Inventory table (paginated)
# -----------------------------------------------------------------------

ASSET_TABLE_HEADERS = [
    'IP', _heb('MAC'), _heb('שם מחשב'), _heb('גרסת OS'),
    _heb('Build'), _heb('סוג'), _heb('פורטים'), _heb('גילוי'),
]
ASSET_COL_WIDTHS = [3*cm, 4*cm, 4*cm, 5*cm, 2.5*cm, 3.5*cm, 4*cm, 3*cm]


def _build_asset_table(story, assets: list, styles):
    _, heading_s, body_s, _ = styles

    story.append(Paragraph(_heb('טבלת מלאי נכסים'), heading_s))
    story.append(Spacer(1, 0.2 * cm))

    rows = [ASSET_TABLE_HEADERS]
    ts_extras = []

    for row_i, a in enumerate(assets, 1):
        ports_str = ', '.join(str(p.get('port', ''))
                              for p in (a.get('open_ports') or [])[:8])
        if len(a.get('open_ports') or []) > 8:
            ports_str += '...'

        row = [
            a.get('ip', ''),
            a.get('mac', '') or '',
            _heb(a.get('hostname', '') or ''),
            _heb((a.get('os_version', '') or '')[:35]),
            a.get('os_build', '') or '',
            _heb(a.get('asset_type', '') or ''),
            ports_str,
            ', '.join(a.get('discovery_methods') or [])[:30],
        ]
        rows.append(row)

        # Color rows with critical/high ports
        if a.get('critical_ports', 0) > 0:
            ts_extras.append(('BACKGROUND', (0, row_i), (-1, row_i),
                               colors.HexColor('#FFCCCC')))
        elif a.get('high_ports', 0) > 0:
            ts_extras.append(('BACKGROUND', (0, row_i), (-1, row_i),
                               colors.HexColor('#FFE6CC')))

    t = Table(rows, colWidths=ASSET_COL_WIDTHS, repeatRows=1)
    style = _header_style(t, len(ASSET_TABLE_HEADERS))
    for extra in ts_extras:
        style.add(*extra)
    t.setStyle(style)
    story.append(t)
    story.append(PageBreak())


# -----------------------------------------------------------------------
# Critical findings page
# -----------------------------------------------------------------------

def _build_critical(story, assets: list, styles):
    _, heading_s, body_s, small_s = styles

    critical_assets = [a for a in assets if a.get('critical_ports', 0) > 0]
    if not critical_assets:
        return

    story.append(Paragraph(_heb('ממצאים קריטיים'), heading_s))
    story.append(Spacer(1, 0.2 * cm))

    for a in critical_assets:
        story.append(Paragraph(
            f'<b>{a.get("ip")}</b>  {_heb(a.get("hostname") or "")}  '
            f'{_heb(a.get("os_version") or "")}',
            body_s))

        crit_ports = [p for p in (a.get('open_ports') or [])
                      if p.get('risk') == 'CRITICAL']
        port_data = [[_heb('פורט'), _heb('שירות'), _heb('באנר')]]
        for p in crit_ports:
            port_data.append([
                str(p.get('port', '')),
                p.get('service', ''),
                (p.get('banner', '') or '')[:80],
            ])

        t = Table(port_data, colWidths=[2*cm, 4*cm, 14*cm])
        ts = _header_style(t, 3)
        ts.add('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#FFEEEE'))
        t.setStyle(ts)
        story.append(t)
        story.append(Spacer(1, 0.4 * cm))

    story.append(PageBreak())


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def generate_pdf(assets: list, meta: dict = None) -> bytes:
    """
    Generate a Hebrew RTL PDF report.

    Args:
        assets: List of Asset.to_dict() results
        meta:   Optional dict with {target, scan_date, duration}

    Returns:
        Raw PDF bytes
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError('reportlab is not installed. Run: pip install reportlab')

    if meta is None:
        meta = {}

    _register_hebrew_font()
    styles = _make_styles()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=2 * cm,
        bottomMargin=1.5 * cm,
    )

    story = []
    _build_cover(story, assets, meta, styles)
    _build_asset_table(story, assets, styles)
    _build_critical(story, assets, styles)

    doc.build(story)
    buf.seek(0)
    return buf.read()
