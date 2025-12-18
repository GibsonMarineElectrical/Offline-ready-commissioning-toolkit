# GME NetPulse (portable)

Local web dashboard showing Windows network adapter status (link speed, MAC) plus IPv4 addresses.

## Run
Start `GME-NetPulse.exe`.

Open `http://127.0.0.1:1989` locally.

PowerShell example:
```powershell
.\GME-NetPulse.exe --host 127.0.0.1 --port 1989 --no-prompt
```

## Options
- `--port <n>`: HTTP port for the web UI (default `1989`)
- `--host <ip>`: bind address (default `0.0.0.0`)
- `--no-prompt`: do not prompt for a port; use defaults or args

## Notes
Uses PowerShell (`Get-NetAdapter`, `Get-NetIPAddress`) to collect adapter info.

For LAN access, run with `--host 0.0.0.0` and browse to the host IP. Keep Windows Firewall rules tight.
