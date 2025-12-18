# GME NavRec (portable)

Listens for NMEA 0183 over UDP/TCP, validates checksums, logs to a local file. Web UI runs on `http://127.0.0.1:8084`.

## Run
Start `GME-NavRec.exe`.

Open `http://127.0.0.1:8084`.

PowerShell example:
```powershell
.\GME-NavRec.exe --port 8084 --no-prompt
```

## Options
- `--port <n>`: HTTP port for the web UI (default `8084`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: do not prompt for a port; use defaults or args

## Features
- UDP and TCP listeners (defaults `10110` and `10111`), configurable via UI
- Counts total, good, bad sentences. Shows recent lines with OK/BAD flag
- Logs to `logs/nmea_<timestamp>.log` under the current working directory (usually next to the EXE)
