# GME LinkGuard (portable)

Local dashboard for Windows network adapters. Polls `Get-NetAdapter` and `Get-NetAdapterStatistics` to show link state, negotiated speed, error counters, discard deltas. Optional periodic ping.

## Run
Start `GME-LinkGuard.exe`.

Open `http://127.0.0.1:8083`.

PowerShell example:
```powershell
.\GME-LinkGuard.exe --port 8083 --no-prompt
```

## Options
- `--port <n>`: HTTP port for the web UI (default `8083`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: do not prompt for a port; use defaults or args

## Features
- Per-adapter status plus link speed
- TX/RX Mbps (based on byte deltas)
- Error and discard increment detection with event log
- Optional ping to a configurable target (basic latency sampling)
