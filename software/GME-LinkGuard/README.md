# GME LinkGuard (portable)

Local web dashboard for adapter health on Windows. Polls `Get-NetAdapter` and `Get-NetAdapterStatistics` to show link state, Mbps, and error/discard deltas; optional periodic ping.

## Run
```
python lan_port_stress.py
```
You’ll be prompted for a port (or pass `--port 8083 --no-prompt`). Open `http://127.0.0.1:<port>`.

## Features
- Per-adapter status, link speed, TX/RX Mbps (from byte deltas)
- Error/discard increment detection with event log
- Periodic ping to a configurable target (basic latency sampling)
- Pure stdlib; suitable for PyInstaller onefile

## Build onefile (optional)
```
pyinstaller --onefile --noconsole lan_port_stress.py
```
