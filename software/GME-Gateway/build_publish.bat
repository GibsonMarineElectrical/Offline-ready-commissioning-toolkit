@echo off
setlocal
REM Build self-contained single-file EXE for GME Gateway File Viewer
REM Requires .NET SDK installed

where dotnet >nul 2>nul
if errorlevel 1 (
  echo .NET SDK not found. Install from https://dotnet.microsoft.com/en-us/download/dotnet/8.0
  pause
  exit /b 1
)

dotnet publish -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:AssemblyName=GME-Gateway ^
  -o publish

if errorlevel 1 (
  echo Publish failed.
  pause
  exit /b 1
)

echo Publish succeeded. Output: publish\GME-Gateway.exe
pause
