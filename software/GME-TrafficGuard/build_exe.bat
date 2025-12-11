@echo off
setlocal EnableDelayedExpansion
set LOG=build_log.txt
echo [build] Starting build at %DATE% %TIME% > %LOG%

REM Clean old artifacts (ignore errors)
if exist build rmdir /s /q build >> %LOG% 2>&1
if exist dist rmdir /s /q dist >> %LOG% 2>&1
if exist TrafficUsage.spec del /q TrafficUsage.spec >> %LOG% 2>&1

REM Check PyInstaller availability via Python module (doesn't require PATH)
py -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('PyInstaller') else 1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build] PyInstaller module not found. >> %LOG%
  echo [build] Cannot auto-install without internet. Install manually: py -m pip install --user pyinstaller >> %LOG%
  echo [build] PyInstaller not found. Please install it with: py -m pip install --user pyinstaller
  echo [build] See %LOG% for details.
  pause
  exit /b 1
)

echo [build] Building portable EXE (windowed)... >> %LOG%
echo [build] Building portable EXE (windowed)...
py -m PyInstaller --noconfirm --onefile --windowed --name GME-TrafficGuard --hidden-import=tkinter --hidden-import=_tkinter "pcap_usage_gui.py" >> %LOG% 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build] Build failed. See %LOG% for details.
  type %LOG%
  pause
  exit /b 1
)

echo [build] Done. Output: dist\GME-TrafficGuard.exe >> %LOG%
echo [build] Done. Output: dist\GME-TrafficGuard.exe
pause
exit /b 0
