@echo off
:: build.bat — Build NetworkScanner.exe (PyInstaller onedir, no console, UAC admin)
:: Run this from the network-scanner\ directory as Administrator for best results.

setlocal EnableDelayedExpansion

echo.
echo  ======================================================
echo   Network Scanner — Windows EXE Builder
echo  ======================================================
echo.

:: ── Check Python ────────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found in PATH. Install Python 3.11+ and try again.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  Python: %%v

:: ── Check / install PyInstaller ─────────────────────────────────────────────
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [INFO] Installing PyInstaller...
    python -m pip install pyinstaller --quiet
)

:: ── Check / install pystray + Pillow (tray icon) ────────────────────────────
python -c "import pystray" >nul 2>&1
if errorlevel 1 (
    echo  [INFO] Installing pystray...
    python -m pip install pystray --quiet
)
python -c "from PIL import Image" >nul 2>&1
if errorlevel 1 (
    echo  [INFO] Installing Pillow...
    python -m pip install Pillow --quiet
)

:: ── Install all project dependencies ────────────────────────────────────────
echo.
echo  [INFO] Installing project requirements...
python -m pip install -r requirements.txt --quiet

:: ── Clean previous build ─────────────────────────────────────────────────────
echo.
echo  [INFO] Cleaning previous build artifacts...
if exist dist\NetworkScanner rmdir /s /q dist\NetworkScanner
if exist build\NetworkScanner rmdir /s /q build\NetworkScanner

:: ── Run PyInstaller ──────────────────────────────────────────────────────────
echo.
echo  [INFO] Building EXE (this may take 2-5 minutes)...
echo.
python -m PyInstaller network_scanner.spec --clean --noconfirm

if errorlevel 1 (
    echo.
    echo  [ERROR] Build failed. Check output above for details.
    pause & exit /b 1
)

:: ── Report success ───────────────────────────────────────────────────────────
echo.
echo  ======================================================
echo   Build complete!
echo   Output: dist\NetworkScanner\NetworkScanner.exe
echo  ======================================================
echo.
echo  To run: double-click dist\NetworkScanner\NetworkScanner.exe
echo  (Windows will prompt for administrator elevation)
echo.

:: Open the output folder in Explorer
if exist dist\NetworkScanner (
    explorer dist\NetworkScanner
)

pause
endlocal
