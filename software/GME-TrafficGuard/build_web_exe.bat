@echo off
setlocal
REM Build single-file EXE for GME TrafficGuard Web
REM Prereq: Python installed; PyInstaller installed (python -m pip install pyinstaller)

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found in PATH.
  pause
  exit /b 1
)

python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
if errorlevel 1 (
  echo PyInstaller not found. Install with: python -m pip install pyinstaller
  pause
  exit /b 1
)

python -m PyInstaller --onefile --name GME-TrafficGuard-Web traffic_guard_web.py
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)

echo Build succeeded. Portable EXE: dist\GME-TrafficGuard-Web.exe
pause
