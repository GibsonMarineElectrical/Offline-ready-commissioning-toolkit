@echo off
setlocal EnableExtensions

rem ---- config ----
set "TASKNAME=RDP Disconnect Watcher"
set "LOGFILE=C:\Scripts\Logs\rdp_disconnect_watch.log"
set "WATCHER=C:\Scripts\RdpDiscWatch.ps1"
set "PS1=%~dp0RdpDiscinstaller.ps1"
set "LOGDIR=C:\Scripts\Logs"

rem ---- preflight ----
if not exist "%PS1%" (
  cls
  echo ERROR: Installer script not found:
  echo "%PS1%"
  echo.
  echo Files in this folder:
  dir /b "%~dp0"
  echo.
  pause
  exit /b 1
)

rem ---- admin check ----
net session >nul 2>&1
if %errorlevel%==0 ( set "ISADMIN=1" ) else ( set "ISADMIN=0" )

goto menu

:TaskExists
schtasks /query /tn "%TASKNAME%" >nul 2>&1
exit /b %errorlevel%

:WatcherExists
if exist "%WATCHER%" ( exit /b 0 ) else ( exit /b 1 )

:RequireAdmin
if "%ISADMIN%"=="1" exit /b 0
echo.
echo ERROR: This option requires Administrator privileges.
echo Select option 8 to relaunch as ADMIN.
echo.
pause
exit /b 1

:menu
call :TaskExists
set "TASKEXISTS=%errorlevel%"
call :WatcherExists
set "WATCHEREXISTS=%errorlevel%"

cls
echo ==========================================
echo   RDP Disconnect Watcher - Menu
echo ==========================================
echo Installer:  %PS1%
echo Watcher:    %WATCHER%
echo Log:        %LOGFILE%
if "%WATCHEREXISTS%"=="0" (echo Watcher:    PRESENT) else (echo Watcher:    MISSING)
if "%TASKEXISTS%"=="0"   (echo Task:       PRESENT) else (echo Task:       MISSING)
if "%ISADMIN%"=="1"      (echo Privileges: ADMIN)  else (echo Privileges: NOT ADMIN)
echo.
echo  1) Full install (folders + watcher + task + start)   [admin]
echo  2) Update      (rewrite watcher + reinstall task)    [admin]
echo  3) Start task                                        [admin]
echo  4) Stop task                                         [admin]
echo  5) Open log
echo  6) Show qwinsta sessions
echo  7) Remove everything (task + watcher + logs)         [admin]
echo  8) Relaunch as ADMIN
echo  0) Exit
echo.
set /p choice=Select option:

if "%choice%"=="1" goto fullinstall
if "%choice%"=="2" goto update
if "%choice%"=="3" goto starttask
if "%choice%"=="4" goto stoptask
if "%choice%"=="5" goto openlog
if "%choice%"=="6" goto qwinsta
if "%choice%"=="7" goto removeall
if "%choice%"=="8" goto elevate
if "%choice%"=="0" goto end

echo Invalid choice.
pause
goto menu

:fullinstall
call :RequireAdmin
if not "%errorlevel%"=="0" goto menu
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoWriteWatcher -DoInstallScheduledTask -DoStartScheduledTask
pause
goto menu

:update
call :RequireAdmin
if not "%errorlevel%"=="0" goto menu
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoWriteWatcher -DoInstallScheduledTask
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoStartScheduledTask
pause
goto menu

:starttask
call :RequireAdmin
if not "%errorlevel%"=="0" goto menu
call :TaskExists
if not "%errorlevel%"=="0" (
  echo ERROR: Task not found: "%TASKNAME%"
  echo Use option 1 to create it.
  pause
  goto menu
)
schtasks /run /tn "%TASKNAME%"
pause
goto menu

:stoptask
call :RequireAdmin
if not "%errorlevel%"=="0" goto menu
call :TaskExists
if not "%errorlevel%"=="0" (
  echo ERROR: Task not found: "%TASKNAME%"
  pause
  goto menu
)
schtasks /end /tn "%TASKNAME%"
pause
goto menu

:openlog
if exist "%LOGFILE%" (
  notepad "%LOGFILE%"
) else (
  echo Log file not found: %LOGFILE%
  echo Run option 1 first to create it.
  pause
)
goto menu

:qwinsta
cmd /c qwinsta
pause
goto menu

:removeall
call :RequireAdmin
if not "%errorlevel%"=="0" goto menu

cls
echo ==========================================
echo   REMOVE EVERYTHING
echo ==========================================
echo This will:
echo  - Stop and delete the scheduled task: "%TASKNAME%"
echo  - Delete watcher file: "%WATCHER%"
echo  - Delete log directory: "%LOGDIR%"
echo.
set /p confirm=Type YES to confirm:

if /I not "%confirm%"=="YES" (
  echo Cancelled.
  pause
  goto menu
)

call :TaskExists
if "%errorlevel%"=="0" (
  schtasks /end /tn "%TASKNAME%" >nul 2>&1
  schtasks /delete /f /tn "%TASKNAME%" >nul 2>&1
)

if exist "%WATCHER%" del /f /q "%WATCHER%" >nul 2>&1
if exist "%LOGDIR%" rmdir /s /q "%LOGDIR%" >nul 2>&1

echo Done. Everything removed.
pause
goto menu

:elevate
if "%ISADMIN%"=="1" goto menu

rem Relaunch via cmd.exe so RunAs works reliably for .bat files
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','""%~f0""' -Verb RunAs"
exit /b

:end
endlocal
exit /b 0
