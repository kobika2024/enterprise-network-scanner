@echo off
:: build.bat — Build NetworkScanner.exe  (PyInstaller onedir, no console, UAC admin)
:: Run this from the network-scanner\ directory.
:: Tip: run as Administrator so PyInstaller can read all system DLLs correctly.

setlocal EnableDelayedExpansion

echo.
echo  ============================================================
echo   Network Scanner ^| Windows EXE Builder
echo  ============================================================
echo.

:: ── 1. Verify Python ─────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found in PATH.
    echo         Install Python 3.11+ from https://python.org and try again.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  Python : %%v
echo.

:: ── 2. Install / upgrade build-time tools ─────────────────────────────────────
echo  [1/5] Checking build tools...

:: setuptools must be up-to-date FIRST — Python 3.12/3.13 removed distutils from
:: stdlib; PyInstaller hooks rely on setuptools to provide it.  An old setuptools
:: causes "ValueError: distutils already imported as ExcludedModule" at analysis time.
python -m pip install "setuptools>=70.0" --upgrade --quiet

python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo        Installing PyInstaller...
    python -m pip install "pyinstaller>=6.0" --quiet
)

python -c "import pystray" >nul 2>&1
if errorlevel 1 (
    echo        Installing pystray...
    python -m pip install "pystray>=0.19" --quiet
)

python -c "from PIL import Image" >nul 2>&1
if errorlevel 1 (
    echo        Installing Pillow...
    python -m pip install "Pillow>=10.0" --quiet
)

:: ── 3. Install project runtime dependencies ────────────────────────────────────
echo.
echo  [2/5] Installing project requirements...
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install requirements.
    pause & exit /b 1
)

:: ── 4. Generate application icon ──────────────────────────────────────────────
echo.
echo  [3/5] Generating application icon...
python make_icon.py static\icon.ico
if errorlevel 1 (
    echo  [WARN] Icon generation failed — EXE will use the default PyInstaller icon.
)

:: ── 5. Clean previous build artifacts ─────────────────────────────────────────
echo.
echo  [4/5] Cleaning previous build...
if exist dist\NetworkScanner  rmdir /s /q dist\NetworkScanner
if exist build\NetworkScanner rmdir /s /q build\NetworkScanner

:: ── 6. Run PyInstaller ────────────────────────────────────────────────────────
echo.
echo  [5/5] Building EXE with PyInstaller (may take 2-5 minutes)...
echo.
python -m PyInstaller network_scanner.spec --clean --noconfirm

if errorlevel 1 (
    echo.
    echo  [ERROR] Build failed. Review the output above for details.
    echo.
    pause & exit /b 1
)

:: ── Verify output ─────────────────────────────────────────────────────────────
if not exist "dist\NetworkScanner\NetworkScanner.exe" (
    echo  [ERROR] EXE not found after build — something went wrong.
    pause & exit /b 1
)

echo.
echo  ============================================================
echo   Build successful!
echo.
echo   Output : dist\NetworkScanner\NetworkScanner.exe
echo.
echo   To distribute: zip or copy the entire dist\NetworkScanner\
echo   folder — the EXE needs all DLLs in the same directory.
echo.
echo   First run will trigger a Windows UAC elevation prompt.
echo  ============================================================
echo.

:: Open the output folder in Explorer so the user can find the EXE
explorer dist\NetworkScanner

pause
endlocal
