"""
launcher.py — Entry point for the packaged Network Scanner EXE.

Responsibilities:
  1. Find a free port in the range 5000–5010.
  2. Show an animated splash screen while Flask starts.
  3. Start Flask in a background thread (using werkzeug make_server
     so we can call server.shutdown() later for a clean stop).
  4. Wait (with timeout + animated progress bar) until the server responds.
  5. Open the default browser to http://localhost:{port}.
  6. Run the pystray system-tray icon on the main thread (keeps process alive).

Tray menu actions:
  • פתח ממשק  — open browser
  • הפסק שרת  — gracefully stop the Flask server, then exit
  • יציאה      — force-exit immediately (os._exit)
"""

import sys
import os
import time
import socket
import threading
import webbrowser
import tkinter as tk
from tkinter import messagebox

# ── Resource-path helper (frozen bundle AND plain source) ─────────────────────
def resource_path(relative: str) -> str:
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS          # type: ignore[attr-defined]
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative)


# ── Patch Flask template/static folders before importing app ──────────────────
os.environ['FLASK_TEMPLATE_FOLDER'] = resource_path('templates')
os.environ['FLASK_STATIC_FOLDER']   = resource_path('static')

# Ensure discovery/, models/, reports/ are importable when frozen
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


# ── Flask thread (uses make_server so we can call .shutdown() later) ──────────
_flask_server = None          # werkzeug BaseWSGIServer instance
_server_port:  int = 5000


def _start_flask(port: int) -> None:
    global _flask_server

    from app import app
    app.template_folder = os.environ['FLASK_TEMPLATE_FOLDER']
    app.static_folder   = os.environ['FLASK_STATIC_FOLDER']

    from werkzeug.serving import make_server
    _flask_server = make_server('127.0.0.1', port, app, threaded=True)
    _flask_server.serve_forever()   # blocks until .shutdown() is called


def _stop_flask() -> None:
    """Gracefully stop the Werkzeug server (called from tray thread)."""
    global _flask_server
    if _flask_server is not None:
        try:
            _flask_server.shutdown()
        except Exception:
            pass
        _flask_server = None


# ── Tray icon (pystray) ───────────────────────────────────────────────────────
def _build_tray_icon(port: int):
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        return None

    # Draw a 64×64 radar / network icon
    size = 64
    img  = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx, cy = size // 2, size // 2

    # Dark filled circle
    draw.ellipse([3, 3, size - 3, size - 3], fill=(13, 17, 23, 255))
    # Blue ring
    draw.ellipse([3, 3, size - 3, size - 3], outline=(88, 166, 255, 255), width=3)
    # Cross-hairs
    arm = size // 3
    draw.line([cx, cy - arm, cx, cy + arm], fill=(88, 166, 255, 180), width=2)
    draw.line([cx - arm, cy, cx + arm, cy], fill=(88, 166, 255, 180), width=2)
    # Center dot
    r = 6
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(88, 166, 255, 255))
    # Two green satellite nodes
    for dx, dy in [(-arm // 2, -arm // 2), (arm // 2, arm // 2)]:
        nr = 4
        draw.ellipse([cx + dx - nr, cy + dy - nr, cx + dx + nr, cy + dy + nr],
                     fill=(63, 185, 80, 255))

    url = f'http://127.0.0.1:{port}'

    def on_open(icon, item):
        webbrowser.open(url)

    def on_stop_server(icon, item):
        """Gracefully stop Flask, then exit cleanly."""
        icon.stop()         # stop the tray loop (returns from icon.run())
        _stop_flask()
        sys.exit(0)

    def on_quit(icon, item):
        """Immediate force-exit."""
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem('פתח ממשק',  on_open, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('הפסק שרת',  on_stop_server),
        pystray.MenuItem('יציאה',     on_quit),
    )

    icon = pystray.Icon('NetworkScanner', img, f'Network Scanner :{port}', menu)
    return icon


# ── Splash screen with animated progress bar ──────────────────────────────────
_BAR_W = 320   # progress bar canvas width in pixels

class _Splash:
    """Borderless splash window with animated progress bar."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title('Network Scanner')
        self.root.resizable(False, False)
        self.root.configure(bg='#0a1628')
        self.root.overrideredirect(True)        # remove title bar
        self.root.attributes('-topmost', True)  # stay on top

        W, H = 380, 160
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f'{W}x{H}+{(sw - W) // 2}+{(sh - H) // 2}')

        # Title
        tk.Label(self.root, text='🔍  Network Scanner',
                 font=('Segoe UI', 16, 'bold'),
                 fg='#4db8ff', bg='#0a1628').pack(pady=(20, 2))

        # Sub-title
        tk.Label(self.root, text='Enterprise Asset Discovery',
                 font=('Segoe UI', 9),
                 fg='#4a6fa5', bg='#0a1628').pack()

        # Animated status line
        self._status = tk.StringVar(value='מאתחל…')
        tk.Label(self.root, textvariable=self._status,
                 font=('Segoe UI', 9),
                 fg='#8abfff', bg='#0a1628').pack(pady=(10, 4))

        # Progress bar track
        track = tk.Canvas(self.root, width=_BAR_W, height=8,
                          bg='#1c2d4a', highlightthickness=0, bd=0)
        track.pack()

        # Progress bar fill (starts at 0 width)
        self._bar_canvas = track
        self._bar = track.create_rectangle(0, 0, 0, 8, fill='#4db8ff', outline='')

        self.root.update()

    # ── public helpers ────────────────────────────────────────────────────────

    def set_progress(self, fraction: float, status: str = '') -> None:
        """Update bar fill (0.0–1.0) and optional status text."""
        w = int(min(1.0, max(0.0, fraction)) * _BAR_W)
        self._bar_canvas.coords(self._bar, 0, 0, w, 8)
        if status:
            self._status.set(status)

    def pump(self) -> None:
        """Process pending Tk events (call in a tight loop)."""
        try:
            self.root.update()
        except tk.TclError:
            pass

    def close(self) -> None:
        try:
            self.root.destroy()
        except Exception:
            pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    global _server_port

    # 1. Find a free port (before showing splash so we can report errors early)
    try:
        _server_port = _find_free_port()
    except RuntimeError as exc:
        messagebox.showerror('Network Scanner', str(exc))
        sys.exit(1)

    # 2. Show animated splash
    splash = _Splash()
    splash.set_progress(0.05, 'מאתחל שרת…')

    # 3. Start Flask in a background daemon thread
    flask_t = threading.Thread(
        target=_start_flask, args=(_server_port,),
        daemon=True, name='FlaskServer'
    )
    flask_t.start()

    # 4. Wait for server with animated progress bar (max 20 s)
    _TIMEOUT   = 20.0
    _READY_PCT = 0.90   # bar fills to 90 % while waiting; jumps to 100 % on ready
    t_start    = time.time()
    ready      = False
    dot_cycle  = 0

    while True:
        elapsed  = time.time() - t_start
        if elapsed >= _TIMEOUT:
            break

        # Animate bar from 5 % → 90 % linearly over the timeout period
        pct = 0.05 + _READY_PCT * (elapsed / _TIMEOUT)
        dots = '.' * (dot_cycle % 4)
        splash.set_progress(pct, f'מחכה לשרת{dots}  (:{_server_port})')
        splash.pump()
        dot_cycle += 1

        try:
            with socket.create_connection(('127.0.0.1', _server_port), timeout=0.3):
                ready = True
                break
        except OSError:
            pass

        time.sleep(0.15)

    # 5. Finalize splash
    if ready:
        splash.set_progress(1.0, 'מוכן!')
        splash.pump()
        time.sleep(0.4)
    splash.close()

    if not ready:
        messagebox.showerror(
            'Network Scanner',
            f'השרת לא הצליח להתחיל בפורט {_server_port}.\n'
            'נסה להפעיל את האפליקציה שוב.'
        )
        sys.exit(1)

    # 6. Open browser
    webbrowser.open(f'http://127.0.0.1:{_server_port}')

    # 7. Run tray icon (blocks until user chooses Stop Server / Quit)
    tray = _build_tray_icon(_server_port)
    if tray:
        tray.run()          # blocks here; returns only when icon.stop() is called
    else:
        # pystray / Pillow not installed — fall back to hidden Tk window
        root = tk.Tk()
        root.withdraw()
        root.title('Network Scanner')
        root.mainloop()


if __name__ == '__main__':
    main()
