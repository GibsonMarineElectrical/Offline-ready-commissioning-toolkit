# GME Gateway File Viewer

Read-only file listing served via a local web page.

Behaviour:
- Files are listed. Links are disabled.
- Folder navigation is enabled.
- Clipboard and right-click are blocked.
- Single-instance guard prevents duplicates.

## Run
Start `GME-Gateway.exe`.

Defaults:
- Root folder: current directory
- Port: `1885`

First run prompts for the folder and port.

## Network and logging
- Binds to loopback only (`127.0.0.1`) for safety.
- Watchdog restarts the server automatically.
- Writes `data-gateway.log` next to the EXE.
