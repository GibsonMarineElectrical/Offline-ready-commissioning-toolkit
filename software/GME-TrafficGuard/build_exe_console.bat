@echo off
setlocal EnableDelayedExpansion
set LOG=build_log_console.txt
echo [build-console] Starting build at %DATE% %TIME% > %LOG%

if exist build rmdir /s /q build >> %LOG% 2>&1
if exist dist rmdir /s /q dist >> %LOG% 2>&1
if exist TrafficUsage.spec del /q TrafficUsage.spec >> %LOG% 2>&1

REM Check PyInstaller via Python module presence
py -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('PyInstaller') else 1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build-console] PyInstaller not found. Please install with: py -m pip install --user pyinstaller
  echo [build-console] See %LOG% for details.
  pause
  exit /b 1
)

echo [build-console] Building console EXE... >> %LOG%
echo [build-console] Building console EXE...
py -m PyInstaller --noconfirm --onefile --console --name TrafficUsageConsole --hidden-import=tkinter --hidden-import=_tkinter "pcap_usage_gui.py" >> %LOG% 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build-console] Build failed. See %LOG% for details.
  type %LOG%
  pause
  exit /b 1
)

echo [build-console] Done. Output: dist\TrafficUsageConsole.exe >> %LOG%
echo [build-console] Done. Output: dist\TrafficUsageConsole.exe
pause
exit /b 0
