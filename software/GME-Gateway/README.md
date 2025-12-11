GME Gateway File Viewer
=======================

Read-only file browser served at `http://127.0.0.1:<port>`. Files are listed (not clickable); folders are navigable. Clipboard and right-click are blocked. Tray icon shows state; single-instance guard prevents duplicates.

Run (interactive)
-----------------
- `dotnet run` (defaults: root = current directory, port = 1885).
- On first run you'll be prompted for folder and port.

Publish self-contained single EXE
---------------------------------
- Requires .NET SDK installed.
- `build_publish.bat` (or run the command inside it):
  ```
  dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:AssemblyName=GME-Gateway -o publish
  ```
- Output: `publish\GME-Gateway.exe`. Log `data-gateway.log` is written next to the EXE.

Notes
-----
- Loopback-only binding for safety.
- Watchdog restarts the server automatically.
- Branding: "GME Gateway File Viewer" (Gibson Marine Electrical LTD).

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
