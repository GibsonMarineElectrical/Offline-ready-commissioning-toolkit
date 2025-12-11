@echo off
setlocal
REM Build single-file EXE (console shown) for the network web server viewer.
REM Prereq: Python installed; if PyInstaller missing, run: python -m pip install pyinstaller

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found in PATH.
  exit /b 1
)

python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
if errorlevel 1 (
  echo PyInstaller not found. Install with: python -m pip install pyinstaller
  exit /b 1
)

python -m PyInstaller --onefile --name GME-NetPulse server.py
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo Build succeeded. Portable EXE: dist\GME-NetPulse.exe
pause
