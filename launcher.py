"""
launcher.py — Entry point for the packaged Network Scanner EXE.

Responsibilities:
  1. Find a free port in the range 5000-5010.
  2. Start Flask in a background daemon thread.
  3. Wait (with timeout) until the server is responding.
  4. Open the default browser to http://localhost:{port}.
  5. Run the pystray system-tray icon on the main thread (keeps process alive).
"""

import sys
import os
import time
import socket
import threading
import webbrowser
import tkinter as tk
from tkinter import messagebox

# ── Resource-path helper (works both frozen and from source) ──────────────────
def resource_path(relative: str) -> str:
    """Return absolute path — works for PyInstaller onedir bundle AND plain source."""
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS          # type: ignore[attr-defined]
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative)


# ── Patch Flask template/static folders before importing app ──────────────────
os.environ['FLASK_TEMPLATE_FOLDER'] = resource_path('templates')
os.environ['FLASK_STATIC_FOLDER']   = resource_path('static')

# Patch sys.path so that discovery/, models/, reports/ are importable
_bundle_dir = resource_path('.')
if _bundle_dir not in sys.path:
    sys.path.insert(0, _bundle_dir)


# ── Port helpers ──────────────────────────────────────────────────────────────
def _is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


def _find_free_port(start: int = 5000, end: int = 5010) -> int:
    for p in range(start, end + 1):
        if _is_port_free(p):
            return p
    raise RuntimeError(
        f'No free port found in range {start}–{end}. '
        'Close any other running instances and try again.'
    )


def _wait_for_server(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ── Flask thread ──────────────────────────────────────────────────────────────
_flask_thread: threading.Thread | None = None
_server_port: int = 5000


def _start_flask(port: int) -> None:
    # Import here so resource_path patches are already applied
    from app import app

    # Override template and static folders from env vars set above
    app.template_folder = os.environ['FLASK_TEMPLATE_FOLDER']
    app.static_folder   = os.environ['FLASK_STATIC_FOLDER']

    app.run(host='127.0.0.1', port=port, debug=False, threaded=True, use_reloader=False)


# ── Tray icon (pystray) ───────────────────────────────────────────────────────
def _build_tray_icon(port: int):
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        # pystray / Pillow not installed — skip tray, just block via event
        return None

    # Draw a simple 64×64 icon (blue shield / radar look)
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Outer circle
    draw.ellipse([4, 4, size - 4, size - 4], fill=(30, 120, 200, 255))
    # Inner cross-hairs
    draw.line([size // 2, 8, size // 2, size - 8], fill='white', width=2)
    draw.line([8, size // 2, size - 8, size // 2], fill='white', width=2)
    # Small center dot
    r = 6
    cx, cy = size // 2, size // 2
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill='white')

    url = f'http://127.0.0.1:{port}'

    def on_open(icon, item):
        webbrowser.open(url)

    def on_quit(icon, item):
        icon.stop()
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem('פתח ממשק',   on_open, default=True),
        pystray.MenuItem('הפסק שרת',   on_quit),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('יציאה',      on_quit),
    )

    icon = pystray.Icon('NetworkScanner', img, f'Network Scanner :{port}', menu)
    return icon


# ── Splash (tkinter) ──────────────────────────────────────────────────────────
def _show_splash() -> tk.Tk:
    root = tk.Tk()
    root.title('Network Scanner')
    root.resizable(False, False)
    root.configure(bg='#0a1628')

    # Center on screen
    w, h = 360, 140
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f'{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}')

    # Remove title bar decorations for a cleaner splash
    root.overrideredirect(True)

    tk.Label(root, text='🔍  Network Scanner',
             font=('Segoe UI', 18, 'bold'), fg='#4db8ff', bg='#0a1628').pack(pady=(24, 6))
    tk.Label(root, text='מאתחל שרת…',
             font=('Segoe UI', 11), fg='#8abfff', bg='#0a1628').pack()
    tk.Label(root, text='Enterprise Asset Discovery',
             font=('Segoe UI', 9), fg='#4a6fa5', bg='#0a1628').pack(pady=(4, 0))

    root.update()
    return root


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global _server_port

    # 1. Find a free port
    try:
        _server_port = _find_free_port()
    except RuntimeError as exc:
        messagebox.showerror('Network Scanner', str(exc))
        sys.exit(1)

    # 2. Show splash
    splash = _show_splash()

    # 3. Start Flask in background thread
    flask_t = threading.Thread(
        target=_start_flask, args=(_server_port,), daemon=True, name='FlaskServer'
    )
    flask_t.start()

    # 4. Wait for server to be ready (pump splash events while waiting)
    deadline = time.time() + 15
    ready = False
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', _server_port), timeout=0.3):
                ready = True
                break
        except OSError:
            pass
        try:
            splash.update()
        except Exception:
            break
        time.sleep(0.15)

    # 5. Destroy splash
    try:
        splash.destroy()
    except Exception:
        pass

    if not ready:
        messagebox.showerror(
            'Network Scanner',
            f'השרת לא הצליח להתחיל בפורט {_server_port}.\n'
            'נסה להפעיל את האפליקציה שוב.'
        )
        sys.exit(1)

    # 6. Open browser
    webbrowser.open(f'http://127.0.0.1:{_server_port}')

    # 7. Run tray icon (blocks main thread — keeps process alive)
    tray = _build_tray_icon(_server_port)
    if tray:
        tray.run()
    else:
        # Fallback: keep alive via a simple Tk window hidden in taskbar
        root = tk.Tk()
        root.withdraw()
        root.title('Network Scanner')
        root.mainloop()


if __name__ == '__main__':
    main()
