# network_scanner.spec — PyInstaller spec file for Network Scanner
# Build with:  pyinstaller network_scanner.spec --clean
# Output:      dist\NetworkScanner\NetworkScanner.exe

import sys
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# ── Data files to bundle ──────────────────────────────────────────────────────
added_datas = [
    # Flask templates
    ('templates', 'templates'),

    # Application modules (source copies so discovery/ imports work at runtime)
    ('discovery', 'discovery'),
    ('models',    'models'),
    ('reports',   'reports'),

    # scanner.py lives in the root bundle dir
    ('scanner.py', '.'),
]

# Bundle static/ only if the directory exists and has content
if os.path.isdir('static') and any(
    os.scandir('static')  # non-empty
):
    added_datas.append(('static', 'static'))

# Collect embedded data from installed packages
# pysnmp ships MIB definitions as data files — required at runtime
try:
    added_datas += collect_data_files('pysnmp')
except Exception:
    pass

# reportlab bundles its own fonts (Type1, TTF) needed for PDF generation
try:
    added_datas += collect_data_files('reportlab')
except Exception:
    pass

# arabic_reshaper ships Unicode data files for Hebrew/RTL reshaping
try:
    added_datas += collect_data_files('arabic_reshaper')
except Exception:
    pass


# ── Hidden imports ────────────────────────────────────────────────────────────
hidden_imports = [
    # Flask / Werkzeug
    'flask',
    'flask.templating',
    'jinja2',
    'jinja2.ext',
    'werkzeug',
    'werkzeug.serving',
    'werkzeug.routing',
    'werkzeug.exceptions',

    # Discovery modules
    'discovery.orchestrator',
    'discovery.arp_discovery',
    'discovery.netbios_discovery',
    'discovery.snmp_discovery',
    'discovery.docker_discovery',
    'discovery.dns_sweep',
    'discovery.os_fingerprint',
    'discovery.ldap_discovery',

    # Models / reports
    'models.asset',
    'reports.excel_report',
    'reports.pdf_report',

    # SNMP (pysnmp-lextudio — uses heavy dynamic imports)
    'pysnmp',
    'pysnmp.hlapi',
    'pysnmp.smi',
    'pysnmp.carrier',
    'pysnmp.carrier.asyncio',
    'pyasn1',

    # Docker SDK
    'docker',
    'docker.api',
    'docker.api.client',

    # LDAP
    'ldap3',

    # Report libraries
    'reportlab',
    'reportlab.pdfbase',
    'reportlab.pdfbase.ttfonts',
    'reportlab.pdfbase.pdfmetrics',
    'reportlab.platypus',
    'reportlab.lib',
    'reportlab.lib.styles',
    'openpyxl',
    'openpyxl.styles',
    'arabic_reshaper',
    'bidi',
    'bidi.algorithm',

    # Tray icon & splash
    'pystray',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'tkinter',
    'tkinter.messagebox',

    # Standard lib sometimes missed by the analyser
    'email',
    'email.mime',
    'email.mime.multipart',
    'encodings.utf_8',
    'encodings.ascii',
    'encodings.latin_1',
    'uuid',
    'threading',
    'socket',
    'struct',
    'ctypes',
    'ctypes.util',
]

# pysnmp and pyasn1 use aggressive dynamic imports — collect all submodules
hidden_imports += collect_submodules('pysnmp')
hidden_imports += collect_submodules('pyasn1')


# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=added_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Heavyweight libs not used by this app
        'matplotlib', 'numpy', 'scipy', 'pandas',
        'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
        'wx', 'gi', 'gtk',
        'IPython', 'notebook', 'jupyter',
        'test', 'unittest',
        'distutils',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── EXE ───────────────────────────────────────────────────────────────────────
# Detect whether the icon was generated
_icon_path = 'static/icon.ico'
_icon_arg  = _icon_path if os.path.isfile(_icon_path) else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,          # onedir mode (DLLs live beside the EXE)
    name='NetworkScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                  # no CMD window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,                 # trigger UAC elevation on launch
    manifest='app.manifest',        # requireAdministrator + DPI awareness
    icon=_icon_arg,                 # None = default PyInstaller icon
)

# ── COLLECT (onedir bundle) ───────────────────────────────────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetworkScanner',
)
