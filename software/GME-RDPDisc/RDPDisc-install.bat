@echo off
setlocal

rem ---- config ----
set "TASKNAME=RDP Disconnect Watcher"
set "LOGFILE=C:\Scripts\Logs\rdp_disconnect_watch.log"
set "WATCHER=C:\Scripts\RdpDiscWatch.ps1"
set "PS1=%~dp0RdpDiscinstaller.ps1"

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

rem ---- admin check (needed for task install/remove/start/stop) ----
net session >nul 2>&1
if %errorlevel%==0 ( set "ISADMIN=1" ) else ( set "ISADMIN=0" )

rem ---- helpers ----
call :TaskExists
set "TASKEXISTS=%errorlevel%"

goto menu

:TaskExists
schtasks /query /tn "%TASKNAME%" >nul 2>&1
exit /b %errorlevel%

:WatcherExists
if exist "%WATCHER%" ( exit /b 0 ) else ( exit /b 1 )

:menu
call :TaskExists
set "TASKEXISTS=%errorlevel%"
call :WatcherExists
set "WATCHEREXISTS=%errorlevel%"

cls
echo ==========================================
echo   RDP Disconnect Watcher - Installer Menu
echo ==========================================
echo Script:  %PS1%
echo Watcher: %WATCHER%
if "%WATCHEREXISTS%"=="0" (echo Watcher: PRESENT) else (echo Watcher: MISSING)
if "%TASKEXISTS%"=="0" (echo Task:   PRESENT) else (echo Task:   MISSING)
if "%ISADMIN%"=="1" (echo Privileges: ADMIN) else (echo Privileges: NOT ADMIN)
echo.
echo  1) Dry run (preview actions only)
echo  2) Write watcher (update if exists, create if missing)
echo  3) Install scheduled task (update if exists, create if missing)   [admin]
echo  4) Install scheduled task + start now (update/create)            [admin]
echo  5) Full install (folders + watcher + task + start)               [admin]
echo  6) One-time test run (ForceCleanup + RunOnce)
echo  7) Start scheduled task                                          [admin]
echo  8) Stop scheduled task                                           [admin]
echo  9) Remove scheduled task                                         [admin]
echo 10) Open log file
echo 11) Show qwinsta (current sessions)
echo 12) Relaunch this menu as ADMIN
echo 13) Update watcher ONLY if it exists (no create)
echo 14) Update task ONLY if it exists (no create)                     [admin]
echo  0) Exit
echo.
set /p choice=Select option:

if "%choice%"=="1" goto dryrun
if "%choice%"=="2" goto write_or_create_watcher
if "%choice%"=="3" goto install_or_update_task
if "%choice%"=="4" goto install_or_update_task_start
if "%choice%"=="5" goto fullinstall
if "%choice%"=="6" goto testrun
if "%choice%"=="7" goto starttask
if "%choice%"=="8" goto stoptask
if "%choice%"=="9" goto removetask
if "%choice%"=="10" goto openlog
if "%choice%"=="11" goto qwinsta
if "%choice%"=="12" goto elevate
if "%choice%"=="13" goto update_watcher_only_if_exists
if "%choice%"=="14" goto update_task_only_if_exists
if "%choice%"=="0" goto end

echo Invalid choice.
pause
goto menu

:dryrun
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoDryRun -DoEnsureFolders -DoWriteWatcher -DoInstallScheduledTask -DoStartScheduledTask
pause
goto menu

:write_or_create_watcher
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoWriteWatcher
pause
goto menu

:install_or_update_task
if "%ISADMIN%"=="0" goto needadmin
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoInstallScheduledTask
pause
goto menu

:install_or_update_task_start
if "%ISADMIN%"=="0" goto needadmin
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoInstallScheduledTask -DoStartScheduledTask
pause
goto menu

:fullinstall
if "%ISADMIN%"=="0" goto needadmin
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoWriteWatcher -DoInstallScheduledTask -DoStartScheduledTask
pause
goto menu

:testrun
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoEnsureFolders -DoOneTimeTestRun
pause
goto menu

:starttask
if "%ISADMIN%"=="0" goto needadmin
call :TaskExists
if not "%errorlevel%"=="0" (
  echo ERROR: Task not found: "%TASKNAME%"
  echo Use option 3, 4, or 5 to create it.
  pause
  goto menu
)
schtasks /run /tn "%TASKNAME%"
pause
goto menu

:stoptask
if "%ISADMIN%"=="0" goto needadmin
call :TaskExists
if not "%errorlevel%"=="0" (
  echo ERROR: Task not found: "%TASKNAME%"
  pause
  goto menu
)
schtasks /end /tn "%TASKNAME%"
pause
goto menu

:removetask
if "%ISADMIN%"=="0" goto needadmin
call :TaskExists
if not "%errorlevel%"=="0" (
  echo Task already missing: "%TASKNAME%"
  pause
  goto menu
)
schtasks /delete /f /tn "%TASKNAME%"
pause
goto menu

:openlog
if exist "%LOGFILE%" (
  notepad "%LOGFILE%"
) else (
  echo Log file not found: %LOGFILE%
  echo Run option 2 or 5 first to create it.
  pause
)
goto menu

:qwinsta
cmd /c qwinsta
pause
goto menu

:update_watcher_only_if_exists
call :WatcherExists
if not "%errorlevel%"=="0" (
  echo ERROR: Watcher not found: "%WATCHER%"
  echo Use option 2 or 5 to create it.
  pause
  goto menu
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoWriteWatcher
pause
goto menu

:update_task_only_if_exists
if "%ISADMIN%"=="0" goto needadmin
call :TaskExists
if not "%errorlevel%"=="0" (
  echo ERROR: Task not found: "%TASKNAME%"
  echo Use option 3, 4, or 5 to create it.
  pause
  goto menu
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DoInstallScheduledTask
pause
goto menu

:needadmin
echo.
echo ERROR: This option requires Administrator privileges.
echo Select option 12 to relaunch as ADMIN.
echo.
pause
goto menu

:elevate
if "%ISADMIN%"=="1" goto menu
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:end
endlocal
exit /b
