# GME ModGuard (portable)

Minimal Modbus TCP poller with a built-in local web dashboard.

## Run
Start `GME-ModGuard.exe`.

Open `http://127.0.0.1:8082`.

PowerShell example:
```powershell
.\GME-ModGuard.exe --port 8082 --no-prompt
```

## Options
- `--port <n>`: HTTP port for the web UI (default `8082`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: do not prompt for a port; use defaults or args

## Features
- Multiple targets (IP, port, unit id, start, count, interval)
- Continuous reads of holding registers (function 3)
- Live values, error counts, rolling event log
- Persists targets to `config.json` (created when you add targets)
