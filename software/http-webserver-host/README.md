Data Gateway (File Browser)
===============================

Small read-only file browser served at `http://127.0.0.1:<port>`. Files are listed (not clickable); folders are navigable. Copy/paste and right-click are blocked in the UI. A watchdog restarts the server if it stops.

Run (interactive)
-----------------
- `dotnet run` (defaults: root = current directory, port = 1885).
- On first run you'll be prompted for folder and port; then it runs with a tray icon ("DG") showing it's active.

Publish self-contained single EXE
---------------------------------
- `dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebuggerSupport=false -p:EnableUnsafeBinaryFormatterSerialization=false -o publish`
- Output: `publish\file-web-browser.exe` (no .NET install needed). Log file `data-gateway.log` is written alongside the EXE.

Notes
-----
- Loopback-only binding for safety.
- Single-instance guard; tray menu has Open/Exit.
- Watchdog restarts the server automatically; log lives next to the EXE.
