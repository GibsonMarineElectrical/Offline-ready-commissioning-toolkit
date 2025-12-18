GME Gateway File Viewer
=======================

Read-only file browser served at `http://127.0.0.1:<port>`. Files are listed (not clickable); folders are navigable. Clipboard and right-click are blocked. Tray icon shows state; single-instance guard prevents duplicates.

Run
---
Run `GME-Gateway.exe` (double-click or from PowerShell). Defaults:
- Root folder = current directory
- Port = `1885`

On first run you’ll be prompted for the folder and port.

Notes
-----
- Loopback-only binding for safety.
- Watchdog restarts the server automatically.
- Branding: "GME Gateway File Viewer" (Gibson Marine Electrical LTD).
- Log file: `data-gateway.log` is written next to the EXE.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
