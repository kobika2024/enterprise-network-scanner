# network_scanner.spec — PyInstaller spec file for Network Scanner
# Build with:  pyinstaller network_scanner.spec --clean
# Output:      dist/NetworkScanner/NetworkScanner.exe

import sys
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# ── Data files to bundle ──────────────────────────────────────────────────────
added_datas = [
    # Flask templates & static assets
    ('templates',          'templates'),
    ('static',             'static'),

    # Application modules (discovery, models, reports)
    ('discovery',          'discovery'),
    ('models',             'models'),
    ('reports',            'reports'),

    # scanner.py (used by orchestrator)
    ('scanner.py',         '.'),
]

# ── Hidden imports ────────────────────────────────────────────────────────────
hidden_imports = [
    # Flask internals
    'flask',
    'flask.templating',
    'jinja2',
    'jinja2.ext',
    'werkzeug',
    'werkzeug.serving',
    'werkzeug.routing',

    # Discovery modules
    'discovery.orchestrator',
    'discovery.arp_discovery',
    'discovery.netbios_discovery',
    'discovery.snmp_discovery',
    'discovery.docker_discovery',
    'discovery.dns_sweep',
    'discovery.os_fingerprint',
    'discovery.ldap_discovery',

    # Models
    'models.asset',

    # Reports
    'reports.excel_report',
    'reports.pdf_report',

    # SNMP (pysnmp-lextudio)
    'pysnmp',
    'pysnmp.hlapi',
    'pysnmp.smi',
    'pysnmp.carrier',
    'pysnmp.carrier.asyncio',
    'pyasn1',

    # Docker SDK
    'docker',
    'docker.api',

    # LDAP
    'ldap3',

    # Reports
    'reportlab',
    'reportlab.pdfbase',
    'reportlab.pdfbase.ttfonts',
    'reportlab.platypus',
    'openpyxl',
    'arabic_reshaper',
    'bidi',
    'bidi.algorithm',

    # Tray icon
    'pystray',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',

    # Standard lib often missed
    'tkinter',
    'tkinter.messagebox',
    'email',
    'email.mime',
    'email.mime.multipart',
]

# Collect all pysnmp submodules (it uses dynamic imports)
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
        'matplotlib', 'numpy', 'scipy', 'pandas',
        'PyQt5', 'PyQt6', 'wx', 'gi',
        'IPython', 'notebook',
        'test', 'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,      # onedir mode
    name='NetworkScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,              # no CMD window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,             # request UAC elevation
    manifest='app.manifest',   # custom manifest for requireAdministrator
    # icon='static/favicon.ico',  # uncomment if you add an icon file
)

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
