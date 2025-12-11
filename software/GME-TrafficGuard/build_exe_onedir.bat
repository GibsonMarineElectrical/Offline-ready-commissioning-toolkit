@echo off
setlocal EnableDelayedExpansion
set LOG=build_log_onedir.txt
echo [build-onedir] Starting build at %DATE% %TIME% > %LOG%

if exist build rmdir /s /q build >> %LOG% 2>&1
if exist dist rmdir /s /q dist >> %LOG% 2>&1
if exist TrafficUsage.spec del /q TrafficUsage.spec >> %LOG% 2>&1

py -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('PyInstaller') else 1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build-onedir] PyInstaller not found. Please install with: py -m pip install --user pyinstaller
  echo [build-onedir] See %LOG% for details.
  pause
  exit /b 1
)

echo [build-onedir] Building onedir EXE (easier debugging)... >> %LOG%
echo [build-onedir] Building onedir EXE (easier debugging)...
py -m PyInstaller --noconfirm --onedir --windowed --name TrafficUsage "pcap_usage_gui.py" --hidden-import=tkinter --hidden-import=_tkinter >> %LOG% 2>&1
if %ERRORLEVEL% neq 0 (
  echo [build-onedir] Build failed. See %LOG% for details.
  type %LOG%
  pause
  exit /b 1
)

echo [build-onedir] Done. Output: dist\TrafficUsage\TrafficUsage.exe >> %LOG%
echo [build-onedir] Done. Output: dist\TrafficUsage\TrafficUsage.exe
pause
exit /b 0

